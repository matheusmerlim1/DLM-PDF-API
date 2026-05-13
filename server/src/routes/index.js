/**
 * routes/index.js
 * Rotas da API RESTful do servidor DLM-PDF.
 *
 * Erros do blockchainService com statusCode 503 (BLOCKCHAIN_OFFLINE)
 * são propagados para o error handler global do Express.
 */

import { Router }            from "express";
import { blockchainService } from "../services/blockchainService.js";
import { generateSessionKey, sha256Hex } from "../services/encryptionService.js";
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
 * POST /licenses/:id/open — handshake principal
 * Valida posse on-chain e retorna chave de sessão efêmera.
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

/** POST /publisher/encrypt — encripta PDF base64 → .dlm base64 */
router.post("/publisher/encrypt", requireAuth, wrap(async (req, res) => {
  const { pdfBase64, licenseId } = req.body;
  if (!pdfBase64 || !licenseId) {
    return res.status(400).json({ error: "pdfBase64 e licenseId são obrigatórios." });
  }

  const { encryptToDLM } = await import("../services/encryptionService.js");
  const pdfBuffer = Buffer.from(pdfBase64, "base64");
  const dlmBuffer = encryptToDLM(pdfBuffer, licenseId);
  const hash      = sha256Hex(pdfBuffer);

  res.json({
    dlmBase64:   dlmBuffer.toString("base64"),
    contentHash: hash,
    licenseId,
    size:        dlmBuffer.length,
  });
}));

export default router;
