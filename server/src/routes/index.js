/**
 * routes/index.js
 * Rotas da API RESTful do servidor DLM-PDF.
 *
 * Erros do blockchainService com statusCode 503 (BLOCKCHAIN_OFFLINE)
 * são propagados para o error handler global do Express.
 */

import { Router }            from "express";
import { blockchainService } from "../services/blockchainService.js";
import {
  generateSessionKey,
  sha256Hex,
  encryptToDLM,
  encryptToDLMv2,
  decryptAny,
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
import crypto from "crypto";

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
    version: "1.0.0",
    endpoints: {
      health:     "GET  /api/v1/health",
      challenge:  "GET  /api/v1/auth/challenge?address=0x...",
      login:      "POST /api/v1/auth/login",
      wallet:     "GET  /api/v1/wallet/:address",
      myLicenses: "GET  /api/v1/licenses/mine  [Bearer]",
      openLicense:"POST /api/v1/licenses/:id/open  [Bearer]",
      bookInfo:   "GET  /api/v1/books/:id",
      encrypt:    "POST /api/v1/publisher/encrypt  [Bearer]",
    },
    client: "http://localhost:3001",
  });
});

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
 * POST /publisher/encrypt — encripta PDF base64 → .dlm base64.
 * Se ownerAddress fornecido: gera v2 (owner-bound).
 * Se omitido:               gera v1 (legado, sem vínculo de carteira).
 */
router.post("/publisher/encrypt", requireAuth, wrap(async (req, res) => {
  const { pdfBase64, licenseId, ownerAddress } = req.body;
  if (!pdfBase64 || !licenseId) {
    return res.status(400).json({ error: "pdfBase64 e licenseId são obrigatórios." });
  }

  const pdfBuffer = Buffer.from(pdfBase64, "base64");
  const hash      = sha256Hex(pdfBuffer);

  let dlmBuffer, version;
  if (ownerAddress) {
    dlmBuffer = encryptToDLMv2(pdfBuffer, licenseId, ownerAddress);
    version   = 2;
  } else {
    dlmBuffer = encryptToDLM(pdfBuffer, licenseId);
    version   = 1;
  }

  res.json({
    dlmBase64:    dlmBuffer.toString("base64"),
    contentHash:  hash,
    licenseId,
    ownerAddress: ownerAddress || null,
    version,
    size:         dlmBuffer.length,
  });
}));

export default router;
