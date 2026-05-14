/**
 * encryptionService.js
 * Cifragem/decifragem dos arquivos .dlm e armazenamento de PDFs.
 *
 * Formato v1 (legado):
 * ┌───────────────────────────────────────────────────────┐
 * │ MAGIC     4B : "DLM\x01"                              │
 * │ licenseId 8B : uint64 big-endian                       │
 * │ IV       16B : AES-256-CBC IV                          │
 * │ HMAC     32B : HMAC-SHA256(licenseId+IV+ciphertext)    │
 * │ ciphertext NB                                          │
 * └───────────────────────────────────────────────────────┘
 *
 * Formato v2 (owner-bound — chave inclui ownerAddress):
 * ┌───────────────────────────────────────────────────────┐
 * │ MAGIC      4B : "DLM\x02"                             │
 * │ licenseId  8B : uint64 big-endian                      │
 * │ ownerAddr 42B : endereço Ethereum ASCII "0x..."        │
 * │ IV        16B : AES-256-CBC IV                         │
 * │ HMAC      32B : HMAC-SHA256(licId+owner+IV+cipher)     │
 * │ ciphertext NB                                          │
 * └───────────────────────────────────────────────────────┘
 *
 * No v2 a chave é HKDF(MASTER, "dlm-v2-enc:licenseId:owner).
 * Sem o ownerAddress correto é matematicamente impossível derivar
 * a mesma chave — demo mode e carteiras erradas não conseguem abrir.
 */

import crypto from "crypto";
import fs     from "fs";
import path   from "path";
import { fileURLToPath } from "url";

const __dirname  = path.dirname(fileURLToPath(import.meta.url));
const MAGIC_V1   = Buffer.from([0x44, 0x4C, 0x4D, 0x01]); // "DLM\x01"
const MAGIC_V2   = Buffer.from([0x44, 0x4C, 0x4D, 0x02]); // "DLM\x02"
const OWNER_LEN  = 42;
const ALGO       = "aes-256-cbc";

// Diretórios de armazenamento (criados automaticamente)
const STORAGE_ROOT = path.resolve(__dirname, "../../../storage");
const PDFS_DIR     = path.join(STORAGE_ROOT, "pdfs");
const KEYS_DIR     = path.join(STORAGE_ROOT, "keys");

function ensureDirs() {
  fs.mkdirSync(PDFS_DIR, { recursive: true });
  fs.mkdirSync(KEYS_DIR, { recursive: true });
}

function masterKey() {
  const hex = process.env.MASTER_ENCRYPTION_KEY;
  if (!hex || hex.length !== 64)
    throw new Error("MASTER_ENCRYPTION_KEY ausente ou inválida (exige 64 hex chars).");
  return Buffer.from(hex, "hex");
}

// ── Derivação de chaves ───────────────────────────────────

function deriveKeyV1(licenseId) {
  const info = Buffer.from(`dlm-v1:${licenseId}`);
  return crypto.hkdfSync("sha256", masterKey(), Buffer.alloc(32), info, 32);
}

function deriveEncKeyV2(licenseId, ownerAddress) {
  const info = Buffer.from(`dlm-v2-enc:${licenseId}:${ownerAddress.toLowerCase()}`);
  return crypto.hkdfSync("sha256", masterKey(), Buffer.alloc(32), info, 32);
}

function deriveMACKeyV2(licenseId, ownerAddress) {
  const info = Buffer.from(`dlm-v2-mac:${licenseId}:${ownerAddress.toLowerCase()}`);
  return crypto.hkdfSync("sha256", masterKey(), Buffer.alloc(32), info, 32);
}

// ── Formatação do cabeçalho ───────────────────────────────

/**
 * Lê o cabeçalho de qualquer versão .dlm sem descriptografar.
 * @param {Buffer} buf
 * @returns {{ version: number, licenseId: string, ownerAddress: string|null }}
 */
export function parseDLMHeader(buf) {
  const isV1 = buf.subarray(0, 4).equals(MAGIC_V1);
  const isV2 = buf.subarray(0, 4).equals(MAGIC_V2);
  if (!isV1 && !isV2) throw new Error("Formato .dlm inválido: magic incorreto.");

  const licenseId = buf.readBigUInt64BE(4).toString();
  if (isV1) return { version: 1, licenseId, ownerAddress: null };

  const ownerAddress = buf.subarray(12, 54).toString("ascii").replace(/\0/g, "").trim();
  return { version: 2, licenseId, ownerAddress };
}

// ── Criptografia v1 (mantido para compatibilidade) ────────

export function encryptToDLM(pdfBuffer, licenseId) {
  const key        = deriveKeyV1(licenseId);
  const iv         = crypto.randomBytes(16);
  const cipher     = crypto.createCipheriv(ALGO, key, iv);
  const ciphertext = Buffer.concat([cipher.update(pdfBuffer), cipher.final()]);

  const licIdBuf = Buffer.alloc(8);
  licIdBuf.writeBigUInt64BE(BigInt(licenseId));

  const hmacInput = Buffer.concat([licIdBuf, iv, ciphertext]);
  const hmac      = crypto.createHmac("sha256", key).update(hmacInput).digest();

  return Buffer.concat([MAGIC_V1, licIdBuf, iv, hmac, ciphertext]);
}

export function decryptDLM(dlmBuffer) {
  if (!dlmBuffer.subarray(0, 4).equals(MAGIC_V1))
    throw new Error("Formato .dlm v1 inválido.");

  const licIdBuf   = dlmBuffer.subarray(4, 12);
  const iv         = dlmBuffer.subarray(12, 28);
  const storedHmac = dlmBuffer.subarray(28, 60);
  const ciphertext = dlmBuffer.subarray(60);
  const licenseId  = licIdBuf.readBigUInt64BE().toString();
  const key        = deriveKeyV1(licenseId);

  const hmac = crypto.createHmac("sha256", key)
    .update(Buffer.concat([licIdBuf, iv, ciphertext])).digest();
  if (!crypto.timingSafeEqual(storedHmac, hmac))
    throw new Error("HMAC inválido: arquivo corrompido ou adulterado.");

  const decipher = crypto.createDecipheriv(ALGO, key, iv);
  return { pdf: Buffer.concat([decipher.update(ciphertext), decipher.final()]), licenseId };
}

// ── Criptografia v2 (owner-bound) ────────────────────────

/**
 * Encripta PDF no formato v2, vinculando ao ownerAddress.
 * @param {Buffer} pdfBuffer
 * @param {string|number} licenseId
 * @param {string} ownerAddress  - endereço Ethereum "0x..."
 * @returns {Buffer} arquivo .dlm v2
 */
export function encryptToDLMv2(pdfBuffer, licenseId, ownerAddress) {
  const owner = ownerAddress.toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(owner)) throw new Error("ownerAddress inválido.");

  const encKey     = deriveEncKeyV2(licenseId, owner);
  const macKey     = deriveMACKeyV2(licenseId, owner);
  const iv         = crypto.randomBytes(16);
  const cipher     = crypto.createCipheriv(ALGO, encKey, iv);
  const ciphertext = Buffer.concat([cipher.update(pdfBuffer), cipher.final()]);

  const licIdBuf  = Buffer.alloc(8);
  licIdBuf.writeBigUInt64BE(BigInt(licenseId));
  const ownerBuf  = Buffer.alloc(OWNER_LEN);
  Buffer.from(owner).copy(ownerBuf);

  const hmac = crypto.createHmac("sha256", macKey)
    .update(Buffer.concat([licIdBuf, ownerBuf, iv, ciphertext])).digest();

  return Buffer.concat([MAGIC_V2, licIdBuf, ownerBuf, iv, hmac, ciphertext]);
}

/**
 * Descriptografa um .dlm v2. O ownerAddress DEVE ser o dono embutido.
 * @param {Buffer} dlmBuffer
 * @param {string} connectedAddress - carteira que está tentando abrir
 * @returns {{ pdf: Buffer, licenseId: string, ownerAddress: string }}
 */
export function decryptDLMv2(dlmBuffer, connectedAddress) {
  if (!dlmBuffer.subarray(0, 4).equals(MAGIC_V2))
    throw new Error("Formato .dlm v2 inválido.");

  const licenseId    = dlmBuffer.readBigUInt64BE(4).toString();
  const ownerAddress = dlmBuffer.subarray(12, 54).toString("ascii").replace(/\0/g, "").trim();

  if (connectedAddress.toLowerCase() !== ownerAddress.toLowerCase()) {
    throw new Error(
      `Acesso negado: arquivo pertence a ${ownerAddress.slice(0, 10)}...${ownerAddress.slice(-6)}`
    );
  }

  const encKey     = deriveEncKeyV2(licenseId, ownerAddress);
  const macKey     = deriveMACKeyV2(licenseId, ownerAddress);
  const licIdBuf   = dlmBuffer.subarray(4, 12);
  const ownerBuf   = dlmBuffer.subarray(12, 54);
  const iv         = dlmBuffer.subarray(54, 70);
  const storedHmac = dlmBuffer.subarray(70, 102);
  const ciphertext = dlmBuffer.subarray(102);

  const hmac = crypto.createHmac("sha256", macKey)
    .update(Buffer.concat([licIdBuf, ownerBuf, iv, ciphertext])).digest();
  if (!crypto.timingSafeEqual(storedHmac, hmac))
    throw new Error("HMAC inválido: arquivo corrompido ou adulterado.");

  const decipher = crypto.createDecipheriv(ALGO, encKey, iv);
  return {
    pdf: Buffer.concat([decipher.update(ciphertext), decipher.final()]),
    licenseId,
    ownerAddress,
  };
}

/**
 * Descriptografa qualquer versão .dlm, verificando posse para v2.
 * @param {Buffer} dlmBuffer
 * @param {string} connectedAddress - carteira conectada
 */
export function decryptAny(dlmBuffer, connectedAddress) {
  const { version } = parseDLMHeader(dlmBuffer);
  if (version === 1) return decryptDLM(dlmBuffer);
  return decryptDLMv2(dlmBuffer, connectedAddress);
}

// ── Armazenamento de PDFs (servidor) ─────────────────────

/**
 * Armazena o PDF original cifrado com chave derivada de bookId.
 * @param {string|number} bookId
 * @param {Buffer} pdfBuffer
 */
export function storePDF(bookId, pdfBuffer) {
  ensureDirs();
  const key    = deriveKeyV1(`book-storage:${bookId}`);
  const iv     = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  const enc    = Buffer.concat([cipher.update(pdfBuffer), cipher.final()]);
  fs.writeFileSync(path.join(PDFS_DIR, `${bookId}.enc`), Buffer.concat([iv, enc]));
}

/**
 * Carrega e descriptografa um PDF armazenado pelo bookId.
 * Retorna null se não existir.
 * @param {string|number} bookId
 * @returns {Buffer|null}
 */
export function loadPDF(bookId) {
  const p = path.join(PDFS_DIR, `${bookId}.enc`);
  if (!fs.existsSync(p)) return null;
  const raw     = fs.readFileSync(p);
  const iv      = raw.subarray(0, 16);
  const enc     = raw.subarray(16);
  const key     = deriveKeyV1(`book-storage:${bookId}`);
  const decipher = crypto.createDecipheriv(ALGO, key, iv);
  return Buffer.concat([decipher.update(enc), decipher.final()]);
}

// ── Utilitários ───────────────────────────────────────────

export function sha256Hex(buffer) {
  return "0x" + crypto.createHash("sha256").update(buffer).digest("hex");
}

/** @deprecated A chave nunca deve sair do servidor. Use /licenses/:id/read */
export function generateSessionKey(licenseId, _nonce) {
  return Buffer.from(deriveKeyV1(licenseId)).toString("hex");
}
