/**
 * authMiddleware.js
 * Middleware de autenticação por assinatura de carteira Ethereum.
 *
 * Fluxo:
 *  1. Cliente solicita um "desafio" (nonce) com GET /auth/challenge?address=0x...
 *  2. Cliente assina o nonce com sua chave privada (MetaMask / ethers.js)
 *  3. POST /auth/login com { address, signature } — servidor verifica e emite JWT
 *  4. Requisições subsequentes enviam Authorization: Bearer <jwt>
 */

import { ethers }  from "ethers";
import jwt         from "jsonwebtoken";
import crypto      from "crypto";

// Cache em memória de desafios pendentes { address => { nonce, expiresAt } }
const challengeCache = new Map();
const CHALLENGE_TTL  = 5 * 60 * 1000; // 5 minutos

// ─── Geração de desafio ───────────────────────────────────────────────────────

export function generateChallenge(address) {
  const normalized = address.toLowerCase();
  const nonce      = crypto.randomBytes(16).toString("hex");
  const expiresAt  = Date.now() + CHALLENGE_TTL;

  challengeCache.set(normalized, { nonce, expiresAt });

  // Mensagem legível pelo usuário na carteira
  const message =
    `Bem-vindo ao DLM-PDF!\n\n` +
    `Assine para provar que você controla esta carteira.\n\n` +
    `Nonce: ${nonce}\n` +
    `Expira em: ${new Date(expiresAt).toISOString()}`;

  return { message, nonce, expiresAt };
}

// ─── Verificação de assinatura ────────────────────────────────────────────────

export function verifySignature(address, message, signature) {
  const normalized = address.toLowerCase();
  const cached     = challengeCache.get(normalized);

  if (!cached) throw new Error("Nenhum desafio ativo para este endereço.");
  if (Date.now() > cached.expiresAt) {
    challengeCache.delete(normalized);
    throw new Error("Desafio expirado. Solicite um novo.");
  }
  if (!message.includes(cached.nonce)) {
    throw new Error("Mensagem não corresponde ao desafio emitido.");
  }

  // Recupera o endereço que gerou a assinatura
  const recovered = ethers.verifyMessage(message, signature).toLowerCase();
  if (recovered !== normalized) {
    throw new Error("Assinatura inválida: endereço não confere.");
  }

  challengeCache.delete(normalized); // uso único
  return true;
}

// ─── Emissão de JWT ───────────────────────────────────────────────────────────

export function issueToken(address) {
  const payload = {
    address: address.toLowerCase(),
    iss:     "dlm-pdf-oracle",
    aud:     "dlm-pdf-client",
  };
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || "1h",
  });
}

// ─── Middleware Express ───────────────────────────────────────────────────────

export function requireAuth(req, res, next) {
  const header = req.headers["authorization"] || "";
  const token  = header.startsWith("Bearer ") ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: "Token de autenticação ausente." });
  }

  try {
    const decoded   = jwt.verify(token, process.env.JWT_SECRET, {
      audience: "dlm-pdf-client",
      issuer:   "dlm-pdf-oracle",
    });
    req.userAddress = decoded.address; // disponível nas rotas
    next();
  } catch (err) {
    return res.status(401).json({ error: "Token inválido ou expirado.", detail: err.message });
  }
}

// Limpa desafios expirados periodicamente
setInterval(() => {
  const now = Date.now();
  for (const [addr, data] of challengeCache.entries()) {
    if (now > data.expiresAt) challengeCache.delete(addr);
  }
}, 60 * 1000);
