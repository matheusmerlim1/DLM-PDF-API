/**
 * routes/index.js
 * Rotas da API RESTful do servidor DLM-PDF.
 *
 * Erros do blockchainService com statusCode 503 (BLOCKCHAIN_OFFLINE)
 * são propagados para o error handler global do Express.
 *
 * Rotas DRM (v3 — sem JWT, autenticam via assinatura MetaMask):
 *   POST /encrypt          — cifra PDF e registra titular (nome + CPF)
 *   POST /decrypt          — decifra com cadeia de custódia + re-cifra para o dono atual
 *   POST /transfer/preview — retorna nome e CPF do destinatário antes da confirmação
 *   POST /transfer         — transfere posse no registro de licenças
 *   POST /users/register   — registra endereço → nome + CPF
 *   GET  /users/:address   — consulta nome e CPF por endereço
 */

import { Router }            from "express";
import { ethers }            from "ethers";
import { blockchainService } from "../services/blockchainService.js";
import {
  generateSessionKey,
  sha256Hex,
  encryptToDLM,
  encryptToDLMv2,
  encryptToDLMv3,
  decryptAny,
  decryptDLMv3WithChain,
  parseDLMHeader,
  storePDF,
  loadPDF,
} from "../services/encryptionService.js";
import {
  generateChallenge,
  verifySignature,
  issueToken,
  requireAuth,
} from "../middleware/authMiddleware.js";
import {
  createLicense,
  loadLicense,
  transferLicense,
  updateEncryptedWith,
  getCandidateAddresses,
  generateLicenseId,
} from "../services/licenseRegistryService.js";
import {
  registerUser,
  lookupUser,
} from "../services/userRegistryService.js";
import crypto from "crypto";

// Janela de validade da assinatura MetaMask: 5 minutos
const SIG_WINDOW_MS = 5 * 60 * 1000;

const router = Router();

// ─── Middleware: repassa erro com statusCode ao Express ───────────────────────
function wrap(fn) {
  return (req, res, next) => fn(req, res, next).catch(next);
}

// ═══════════════════════════════════════════════════════════
//  ROOT — info da API
// ═══════════════════════════════════════════════════════════

router.get("/", (req, res) => {
  res.json({
    name: "DLM-PDF API",
    version: "2.0.0",
    drm: {
      encrypt:         "POST /api/v1/encrypt          — cifra PDF (v3) e registra titular",
      decrypt:         "POST /api/v1/decrypt          — decifra com cadeia de custódia [assinatura]",
      transferPreview: "POST /api/v1/transfer/preview — consulta nome+CPF do destinatário",
      transfer:        "POST /api/v1/transfer         — transfere posse [assinatura do cedente]",
      registerUser:    "POST /api/v1/users/register   — cadastra endereço → nome + CPF",
      lookupUser:      "GET  /api/v1/users/:address   — consulta nome+CPF por endereço",
    },
    auth: {
      challenge:  "GET  /api/v1/auth/challenge?address=0x...",
      login:      "POST /api/v1/auth/login",
      wallet:     "GET  /api/v1/wallet/:address",
      myLicenses: "GET  /api/v1/licenses/mine  [Bearer]",
      openLicense:"POST /api/v1/licenses/:id/open  [Bearer]",
    },
    publisher: {
      bookInfo:   "GET  /api/v1/books/:id",
      encrypt:    "POST /api/v1/publisher/encrypt  [Bearer]",
    },
    health: "GET /api/v1/health",
    client: "http://localhost:3001",
  });
});

// ═══════════════════════════════════════════════════════════
//  UTILITÁRIO — verificação de assinatura MetaMask
// ═══════════════════════════════════════════════════════════

/**
 * Verifica que uma assinatura MetaMask é válida e recente.
 * message deve terminar em ":<timestamp>" (ex.: "DLM:decrypt:42:1716000000000").
 */
function verifyMetaMaskSignature(address, message, signature) {
  let recovered;
  try {
    recovered = ethers.verifyMessage(message, signature).toLowerCase();
  } catch {
    const err = new Error("Assinatura MetaMask inválida.");
    err.statusCode = 401;
    throw err;
  }

  if (recovered !== address.toLowerCase()) {
    const err = new Error("Assinatura não corresponde ao endereço informado.");
    err.statusCode = 401;
    throw err;
  }

  const tsMatch = message.match(/:(\d+)$/);
  if (!tsMatch || Date.now() - parseInt(tsMatch[1], 10) > SIG_WINDOW_MS) {
    const err = new Error("Assinatura expirada. Gere uma nova assinatura e tente novamente.");
    err.statusCode = 401;
    throw err;
  }
}

// ═══════════════════════════════════════════════════════════
//  DRM — USUÁRIOS
// ═══════════════════════════════════════════════════════════

/**
 * POST /users/register
 * Cadastra (ou atualiza) nome e CPF de um endereço Ethereum.
 * Body: { address, name, cpf }
 */
router.post("/users/register", (req, res) => {
  const { address, name, cpf } = req.body;

  if (!address || !name || !cpf)
    return res.status(400).json({ error: "address, name e cpf são obrigatórios." });
  if (!/^0x[0-9a-fA-F]{40}$/i.test(address))
    return res.status(400).json({ error: "address Ethereum inválido." });
  if (name.trim().length < 3)
    return res.status(400).json({ error: "name deve ter pelo menos 3 caracteres." });
  if (cpf.replace(/\D/g, "").length !== 11)
    return res.status(400).json({ error: "cpf deve ter 11 dígitos." });

  const user = registerUser(address, name.trim(), cpf.trim());
  res.json({ message: "Usuário registrado com sucesso.", user });
});

/**
 * GET /users/:address
 * Consulta nome e CPF pelo endereço Ethereum (público — sem auth).
 */
router.get("/users/:address", (req, res) => {
  const { address } = req.params;

  if (!/^0x[0-9a-fA-F]{40}$/i.test(address))
    return res.status(400).json({ error: "address Ethereum inválido." });

  const user = lookupUser(address);
  if (!user) return res.status(404).json({ error: "Usuário não cadastrado." });

  res.json({ address: user.address, name: user.name, cpf: user.cpf });
});

// ═══════════════════════════════════════════════════════════
//  DRM — ENCRIPTOGRAFAR
// ═══════════════════════════════════════════════════════════

/**
 * POST /encrypt
 * Encripta um PDF no formato .dlm v3 e registra a titularidade.
 *
 * Body (JSON):
 *   pdfBase64  : string  — PDF em base64
 *   publicKey  : string  — endereço Ethereum do titular (0x...)
 *   licenseId  : string? — ID da licença; gerado automaticamente se ausente
 *   userName   : string  — nome completo do titular
 *   userCPF    : string  — CPF do titular (11 dígitos)
 *
 * Retorna: { dlmBase64, licenseId, contentHash, owner: { address, name, cpf } }
 */
router.post("/encrypt", wrap(async (req, res) => {
  const { pdfBase64, publicKey, userName, userCPF } = req.body;
  let   { licenseId } = req.body;

  if (!pdfBase64 || !publicKey || !userName || !userCPF)
    return res.status(400).json({ error: "pdfBase64, publicKey, userName e userCPF são obrigatórios." });
  if (!/^0x[0-9a-fA-F]{40}$/i.test(publicKey))
    return res.status(400).json({ error: "publicKey (endereço Ethereum) inválido." });
  if (userName.trim().length < 3)
    return res.status(400).json({ error: "userName deve ter pelo menos 3 caracteres." });
  if (userCPF.replace(/\D/g, "").length !== 11)
    return res.status(400).json({ error: "userCPF deve ter 11 dígitos." });

  // Gera licenseId se não informado
  if (!licenseId) {
    licenseId = generateLicenseId();
  }

  const pdfBuffer = Buffer.from(pdfBase64, "base64");
  const hash      = sha256Hex(pdfBuffer);

  // Cifra no formato v3 (owner-bound + código verificador)
  const dlmBuffer = encryptToDLMv3(pdfBuffer, licenseId, publicKey);

  // Registra usuário e cria licença
  const owner = { address: publicKey, name: userName.trim(), cpf: userCPF.trim() };
  registerUser(publicKey, owner.name, owner.cpf);
  createLicense(licenseId, owner);

  res.json({
    dlmBase64:   dlmBuffer.toString("base64"),
    licenseId,
    contentHash: hash,
    size:        dlmBuffer.length,
    version:     3,
    owner: { address: publicKey.toLowerCase(), name: owner.name, cpf: owner.cpf },
  });
}));

// ═══════════════════════════════════════════════════════════
//  DRM — DESCRIPTOGRAFAR
// ═══════════════════════════════════════════════════════════

/**
 * POST /decrypt
 * Descriptografa um .dlm v3 com cadeia de custódia, exibe o PDF e
 * re-cifra o arquivo com as chaves do dono atual.
 *
 * Requer assinatura MetaMask para provar posse da carteira.
 *
 * Body (JSON):
 *   dlmBase64  : string — arquivo .dlm em base64
 *   publicKey  : string — endereço Ethereum do dono atual (0x...)
 *   signature  : string — assinatura MetaMask da mensagem
 *   message    : string — mensagem assinada (deve conter timestamp no final: ":millis")
 *
 * Retorna: { pdfBase64, dlmBase64 (atualizado), licenseId, owner }
 */
router.post("/decrypt", wrap(async (req, res) => {
  const { dlmBase64, publicKey, signature, message } = req.body;

  if (!dlmBase64 || !publicKey || !signature || !message)
    return res.status(400).json({ error: "dlmBase64, publicKey, signature e message são obrigatórios." });
  if (!/^0x[0-9a-fA-F]{40}$/i.test(publicKey))
    return res.status(400).json({ error: "publicKey (endereço Ethereum) inválido." });

  // 1. Verifica assinatura MetaMask — prova que o usuário controla a carteira
  verifyMetaMaskSignature(publicKey, message, signature);

  // 2. Lê o cabeçalho do .dlm para obter o licenseId
  const dlmBuffer = Buffer.from(dlmBase64, "base64");
  const header    = parseDLMHeader(dlmBuffer);

  if (header.version !== 3) {
    return res.status(400).json({
      error: `Formato .dlm v${header.version} não suportado por este endpoint. Use v3.`,
    });
  }

  const { licenseId } = header;

  // 3. Verifica se o publicKey é o dono atual no registro
  const licenseRecord = loadLicense(licenseId);
  if (!licenseRecord) {
    return res.status(404).json({ error: `Licença ${licenseId} não encontrada no registro.` });
  }
  if (licenseRecord.currentOwner.address.toLowerCase() !== publicKey.toLowerCase()) {
    return res.status(403).json({
      error: "Acesso negado: você não é o proprietário atual desta licença.",
      currentOwner: licenseRecord.currentOwner.address,
    });
  }

  // 4. Monta lista de candidatos: quem cifrou por último + histórico reverso
  const candidates = getCandidateAddresses(licenseRecord);

  // 5. Itera pelas chaves até encontrar a correta (valida pelo código verificador)
  const { pdf, decryptedWith } = decryptDLMv3WithChain(dlmBuffer, candidates);

  // 6. Re-cifra com as chaves do dono atual
  const newDlmBuffer = encryptToDLMv3(pdf, licenseId, publicKey);
  updateEncryptedWith(licenseId, publicKey);

  res.json({
    pdfBase64:     pdf.toString("base64"),
    dlmBase64:     newDlmBuffer.toString("base64"),
    licenseId,
    decryptedWith,
    owner:         licenseRecord.currentOwner,
    version:       3,
  });
}));

// ═══════════════════════════════════════════════════════════
//  DRM — TRANSFERÊNCIA DE POSSE
// ═══════════════════════════════════════════════════════════

/**
 * POST /transfer/preview
 * Consulta nome e CPF do destinatário antes da aprovação.
 * Não executa nenhuma transferência — apenas retorna dados para confirmação.
 *
 * Body (JSON): { toPublicKey, licenseId }
 * Retorna: { newOwner: { address, name, cpf }, currentOwner: { address } }
 */
router.post("/transfer/preview", wrap(async (req, res) => {
  const { toPublicKey, licenseId } = req.body;

  if (!toPublicKey || !licenseId)
    return res.status(400).json({ error: "toPublicKey e licenseId são obrigatórios." });
  if (!/^0x[0-9a-fA-F]{40}$/i.test(toPublicKey))
    return res.status(400).json({ error: "toPublicKey (endereço Ethereum) inválido." });

  // Verifica licença
  const licenseRecord = loadLicense(licenseId);
  if (!licenseRecord)
    return res.status(404).json({ error: `Licença ${licenseId} não encontrada.` });

  // Verifica destinatário cadastrado
  const newOwner = lookupUser(toPublicKey);
  if (!newOwner) {
    return res.status(404).json({
      error: "Destinatário não cadastrado no sistema. O novo dono deve se registrar antes de receber transferências.",
      toPublicKey: toPublicKey.toLowerCase(),
    });
  }

  res.json({
    newOwner:     { address: newOwner.address, name: newOwner.name, cpf: newOwner.cpf },
    currentOwner: { address: licenseRecord.currentOwner.address },
    licenseId,
  });
}));

/**
 * POST /transfer
 * Executa a transferência de posse de uma licença.
 *
 * Requer assinatura MetaMask do dono atual para autorizar a transferência.
 * Após aprovação exibida via /transfer/preview no frontend.
 *
 * Body (JSON):
 *   fromPublicKey : string — endereço do dono atual (cedente)
 *   toPublicKey   : string — endereço do novo dono (cessionário)
 *   licenseId     : string — ID da licença
 *   signature     : string — assinatura MetaMask do cedente
 *   message       : string — mensagem assinada (deve terminar em ":millis")
 *
 * Retorna: { licenseId, previousOwner, newOwner, transferredAt }
 */
router.post("/transfer", wrap(async (req, res) => {
  const { fromPublicKey, toPublicKey, licenseId, signature, message } = req.body;

  if (!fromPublicKey || !toPublicKey || !licenseId || !signature || !message)
    return res.status(400).json({
      error: "fromPublicKey, toPublicKey, licenseId, signature e message são obrigatórios.",
    });
  if (!/^0x[0-9a-fA-F]{40}$/i.test(fromPublicKey))
    return res.status(400).json({ error: "fromPublicKey inválido." });
  if (!/^0x[0-9a-fA-F]{40}$/i.test(toPublicKey))
    return res.status(400).json({ error: "toPublicKey inválido." });
  if (fromPublicKey.toLowerCase() === toPublicKey.toLowerCase())
    return res.status(400).json({ error: "Cedente e cessionário não podem ser o mesmo endereço." });

  // 1. Verifica assinatura MetaMask do cedente
  verifyMetaMaskSignature(fromPublicKey, message, signature);

  // 2. Verifica destinatário cadastrado
  const newOwnerUser = lookupUser(toPublicKey);
  if (!newOwnerUser) {
    return res.status(404).json({
      error: "Destinatário não cadastrado. Ele deve se registrar (POST /users/register) antes de receber transferências.",
    });
  }

  // 3. Executa transferência no registro
  const updatedRecord = transferLicense(licenseId, fromPublicKey, {
    address: toPublicKey,
    name:    newOwnerUser.name,
    cpf:     newOwnerUser.cpf,
  });

  res.json({
    licenseId,
    previousOwner:  { address: fromPublicKey.toLowerCase() },
    newOwner:       { address: newOwnerUser.address, name: newOwnerUser.name, cpf: newOwnerUser.cpf },
    transferredAt:  new Date().toISOString(),
    note: "O arquivo .dlm será re-cifrado com as chaves do novo dono na próxima chamada a POST /decrypt.",
  });
}));

// ═══════════════════════════════════════════════════════════
//  HEALTH — status do servidor e da blockchain
// ═══════════════════════════════════════════════════════════

router.get("/health", wrap(async (req, res) => {
  const status = blockchainService.getStatus();

  // Testa latência de rede se conectado
  let latencyMs = null;
  if (status.mode === "connected" && blockchainService.provider) {
    const t0 = Date.now();
    try {
      await blockchainService.provider.getBlockNumber();
      latencyMs = Date.now() - t0;
    } catch (_) {}
  }

  res.status(status.connected || status.demo ? 200 : 503).json({
    status:          status.mode === "connected" ? "ok" : status.mode,
    blockchain:      status,
    latencyMs,
    timestamp:       new Date().toISOString(),
    version:         "1.0.0",
    // Guia de solução quando offline
    ...(status.mode === "offline" && {
      troubleshoot: [
        "1. Suba o node local:  npx hardhat node",
        "2. Faça o deploy:      npx hardhat run scripts/deploy.js --network localhost",
        "3. Atualize .env:      CONTRACT_ADDRESS=<endereço gerado>",
        "4. Modo demo rápido:   CONTRACT_ADDRESS=demo no .env",
      ],
    }),
  });
}));

// ═══════════════════════════════════════════════════════════
//  AUTH
// ═══════════════════════════════════════════════════════════

/** GET /auth/challenge?address=0x... */
router.get("/auth/challenge", (req, res) => {
  const { address } = req.query;
  if (!address || !/^0x[0-9a-fA-F]{40}$/i.test(address)) {
    return res.status(400).json({ error: "Endereço Ethereum inválido." });
  }
  const challenge = generateChallenge(address);
  res.json(challenge);
});

/** POST /auth/login — { address, message, signature } */
router.post("/auth/login", (req, res) => {
  const { address, message, signature } = req.body;
  if (!address || !message || !signature) {
    return res.status(400).json({
      error: "address, message e signature são obrigatórios.",
    });
  }
  try {
    verifySignature(address, message, signature);
    const token = issueToken(address);
    res.json({ token, address: address.toLowerCase() });
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════
//  LICENÇAS
// ═══════════════════════════════════════════════════════════

/** GET /licenses/mine */
router.get("/licenses/mine", requireAuth, wrap(async (req, res) => {
  const ids     = await blockchainService.getLicensesByOwner(req.userAddress);
  const details = await Promise.all(ids.map(id => blockchainService.getLicenseInfo(id)));
  res.json({ licenses: ids.map((id, i) => ({ licenseId: id, ...details[i] })) });
}));

/** GET /licenses/:id */
router.get("/licenses/:id", requireAuth, wrap(async (req, res) => {
  const info = await blockchainService.getLicenseInfo(req.params.id);
  res.json({ licenseId: req.params.id, ...info });
}));

/** GET /licenses/:id/access — verificação rápida (sem gas) */
router.get("/licenses/:id/access", requireAuth, wrap(async (req, res) => {
  const granted = await blockchainService.checkAccessView(req.params.id, req.userAddress);
  res.json({ licenseId: req.params.id, address: req.userAddress, granted });
}));

/**
 * POST /licenses/:id/open — handshake (mantido para compatibilidade).
 * Prefira /licenses/:id/read que retorna o PDF diretamente.
 */
router.post("/licenses/:id/open", requireAuth, wrap(async (req, res) => {
  const licenseId = req.params.id;

  const { granted, txHash } = await blockchainService.validateAccessOnChain(
    licenseId,
    req.userAddress
  );

  if (!granted) {
    return res.status(403).json({
      error: "Acesso negado. Você não é o proprietário nem o tomador desta licença.",
      licenseId,
    });
  }

  const sessionNonce = crypto.randomBytes(16).toString("hex");
  const sessionKey   = generateSessionKey(licenseId, sessionNonce);

  res.json({
    granted: true,
    licenseId,
    txHash,
    sessionKey,
    sessionNonce,
    expiresAt: Date.now() + 60 * 60 * 1000,
    _note: "sessionKey deprecado — use POST /licenses/:id/read para descriptografia server-side",
  });
}));

/**
 * POST /licenses/:id/read — descriptografa .dlm no servidor e retorna PDF.
 *
 * Body (JSON): { dlmBase64?: string }
 *  - Se fornecido: descriptografa o arquivo enviado (v1 ou v2).
 *  - Se omitido:   gera a partir do PDF armazenado (requer upload prévio).
 *
 * Retorna: { pdfBase64: string, licenseId: string, ownerAddress: string|null }
 */
router.post("/licenses/:id/read", requireAuth, wrap(async (req, res) => {
  const licenseId = req.params.id;
  const userAddr  = req.userAddress;

  // 1. Verifica posse on-chain
  const { granted, txHash } = await blockchainService.validateAccessOnChain(licenseId, userAddr);
  if (!granted) {
    return res.status(403).json({
      error: "Acesso negado. Você não é o proprietário desta licença na blockchain.",
      licenseId,
    });
  }

  let pdf, ownerAddress = null;

  if (req.body.dlmBase64) {
    // Usuário enviou o arquivo .dlm
    const dlmBuffer = Buffer.from(req.body.dlmBase64, "base64");

    // Para v2: verifica que ownerAddress no arquivo == carteira autenticada
    const header = parseDLMHeader(dlmBuffer);
    if (header.version === 2 && header.ownerAddress.toLowerCase() !== userAddr.toLowerCase()) {
      return res.status(403).json({
        error: `Arquivo pertence a ${header.ownerAddress.slice(0, 10)}...${header.ownerAddress.slice(-6)}. Use a carteira correta.`,
      });
    }

    ({ pdf, ownerAddress } = decryptAny(dlmBuffer, userAddr));

  } else {
    // Tenta usar PDF armazenado no servidor
    const licInfo = await blockchainService.getLicenseInfo(licenseId).catch(() => null);
    const bookId  = licInfo?.bookId;
    const stored  = bookId ? loadPDF(bookId) : null;

    if (!stored) {
      return res.status(404).json({
        error: "PDF não armazenado no servidor. Envie o arquivo .dlm no corpo da requisição.",
      });
    }

    // Gera .dlm v2 owner-bound e já retorna o PDF
    pdf = stored;
    ownerAddress = userAddr;
  }

  res.json({
    pdfBase64:    pdf.toString("base64"),
    licenseId,
    ownerAddress,
    txHash,
  });
}));

/**
 * POST /licenses/:id/reencrypt — descriptografa o .dlm do dono atual
 * e re-encripta para o novo dono. Usado na transferência de licenças.
 *
 * Body (JSON): { dlmBase64: string, newOwnerAddress: string }
 * Retorna: { dlmBase64: string, licenseId: string, newOwnerAddress: string, version: 2 }
 */
router.post("/licenses/:id/reencrypt", requireAuth, wrap(async (req, res) => {
  const licenseId                     = req.params.id;
  const userAddr                      = req.userAddress;
  const { dlmBase64, newOwnerAddress } = req.body;

  if (!dlmBase64 || !newOwnerAddress) {
    return res.status(400).json({ error: "dlmBase64 e newOwnerAddress são obrigatórios." });
  }
  if (!/^0x[0-9a-fA-F]{40}$/i.test(newOwnerAddress)) {
    return res.status(400).json({ error: "newOwnerAddress inválido." });
  }

  // Verifica que o requisitante é o dono atual na blockchain
  const { granted } = await blockchainService.validateAccessOnChain(licenseId, userAddr);
  if (!granted) {
    return res.status(403).json({
      error: "Acesso negado. Você não é o proprietário atual desta licença.",
      licenseId,
    });
  }

  const dlmBuffer = Buffer.from(dlmBase64, "base64");

  // Para v2: garante que o arquivo pertence ao usuário autenticado
  const header = parseDLMHeader(dlmBuffer);
  if (header.version === 2 && header.ownerAddress.toLowerCase() !== userAddr.toLowerCase()) {
    return res.status(403).json({
      error: `Arquivo pertence a ${header.ownerAddress.slice(0, 10)}...${header.ownerAddress.slice(-6)}.`,
    });
  }

  // Descriptografa com chave do dono atual
  const { pdf } = decryptAny(dlmBuffer, userAddr);

  // Re-encripta com chave derivada do novo dono
  const newDlm = encryptToDLMv2(pdf, licenseId, newOwnerAddress.toLowerCase());

  res.json({
    dlmBase64:       newDlm.toString("base64"),
    licenseId,
    newOwnerAddress: newOwnerAddress.toLowerCase(),
    version:         2,
    size:            newDlm.length,
  });
}));

// ═══════════════════════════════════════════════════════════
//  CARTEIRA — consulta pública (sem auth)
// ═══════════════════════════════════════════════════════════

/**
 * GET /wallet/:address
 * Retorna tudo registrado na blockchain para um endereço Ethereum.
 * Endpoint público — não requer JWT. Útil para verificar posse externamente.
 */
router.get("/wallet/:address", wrap(async (req, res) => {
  const address = req.params.address;

  if (!/^0x[0-9a-fA-F]{40}$/i.test(address)) {
    return res.status(400).json({ error: "Endereço Ethereum inválido." });
  }

  const normalizedAddress = address.toLowerCase();
  const licenseIds = await blockchainService.getLicensesByOwner(normalizedAddress);

  // Para cada licença, busca os detalhes e o livro correspondente
  const licenses = await Promise.all(
    licenseIds.map(async (licenseId) => {
      const license = await blockchainService.getLicenseInfo(licenseId);
      let book = null;
      try {
        book = await blockchainService.getBookInfo(license.bookId);
      } catch (_) {}
      return {
        licenseId,
        ...license,
        book,
      };
    })
  );

  const status = blockchainService.getStatus();

  res.json({
    address:       normalizedAddress,
    blockchain:    status.mode,
    totalLicenses: licenses.length,
    licenses,
  });
}));

// ═══════════════════════════════════════════════════════════
//  LIVROS
// ═══════════════════════════════════════════════════════════

/** GET /books/:id */
router.get("/books/:id", wrap(async (req, res) => {
  const info = await blockchainService.getBookInfo(req.params.id);
  res.json({ bookId: req.params.id, ...info });
}));

// ═══════════════════════════════════════════════════════════
//  PUBLISHER
// ═══════════════════════════════════════════════════════════

/** POST /publisher/books */
router.post("/publisher/books", requireAuth, wrap(async (req, res) => {
  const { title, author, contentHash, royaltyBps } = req.body;
  if (!title || !author || !contentHash) {
    return res.status(400).json({ error: "title, author e contentHash são obrigatórios." });
  }
  const result = await blockchainService.registerBook(title, author, contentHash, royaltyBps || 500);
  res.status(201).json({ message: "Livro registrado.", ...result });
}));

/** POST /publisher/books/:bookId/mint */
router.post("/publisher/books/:bookId/mint", requireAuth, wrap(async (req, res) => {
  const { buyerAddress } = req.body;
  if (!buyerAddress) {
    return res.status(400).json({ error: "buyerAddress é obrigatório." });
  }
  const result = await blockchainService.mintLicense(req.params.bookId, buyerAddress);
  res.status(201).json({ message: "Licença emitida.", ...result });
}));

/**
 * POST /publisher/books/:bookId/upload — armazena PDF no servidor para geração
 * de .dlm on-demand. Body: { pdfBase64: string }
 */
router.post("/publisher/books/:bookId/upload", requireAuth, wrap(async (req, res) => {
  const { pdfBase64 } = req.body;
  if (!pdfBase64) return res.status(400).json({ error: "pdfBase64 é obrigatório." });

  const bookId    = req.params.bookId;
  const pdfBuffer = Buffer.from(pdfBase64, "base64");
  storePDF(bookId, pdfBuffer);
  const hash = sha256Hex(pdfBuffer);

  res.json({ message: "PDF armazenado com sucesso.", bookId, contentHash: hash });
}));

/**
 * POST /publisher/encrypt — encripta PDF base64 → .dlm v3.
 *
 * Sempre cria v3 (owner-bound + código verificador + cadeia de custódia).
 * ownerAddress: usa o do body se válido; senão usa o endereço autenticado via JWT.
 *
 * Bug corrigido (2026-05-15): versões anteriores criavam v1 quando ownerAddress
 * era omitido, gerando arquivos que exigiam blockchain para abrir.
 */
router.post("/publisher/encrypt", requireAuth, wrap(async (req, res) => {
  const { pdfBase64, licenseId, ownerAddress: bodyOwner } = req.body;
  if (!pdfBase64 || !licenseId) {
    return res.status(400).json({ error: "pdfBase64 e licenseId são obrigatórios." });
  }

  // Endereço do titular: body > JWT. Nunca cria v1.
  const ownerAddress = (bodyOwner && /^0x[0-9a-fA-F]{40}$/i.test(bodyOwner))
    ? bodyOwner.toLowerCase()
    : req.userAddress.toLowerCase();

  const pdfBuffer = Buffer.from(pdfBase64, "base64");
  const hash      = sha256Hex(pdfBuffer);

  const dlmBuffer = encryptToDLMv3(pdfBuffer, licenseId, ownerAddress);

  // Registra no licenseRegistry para permitir abertura via /decrypt sem blockchain
  const existingUser = lookupUser(ownerAddress);
  const ownerInfo = {
    address: ownerAddress,
    name:    existingUser?.name ?? "Publisher",
    cpf:     existingUser?.cpf  ?? "00000000000",
  };
  createLicense(licenseId, ownerInfo);

  res.json({
    dlmBase64:    dlmBuffer.toString("base64"),
    contentHash:  hash,
    licenseId,
    ownerAddress,
    version:      3,
    size:         dlmBuffer.length,
  });
}));

export default router;
