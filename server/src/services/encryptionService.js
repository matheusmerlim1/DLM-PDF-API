/**
 * encryptionService.js
 * Gerencia a cifragem/decifragem dos arquivos .dlm (PDF criptografado).
 *
 * Formato do arquivo .dlm:
 * ┌──────────────────────────────────────────────────────┐
 * │ MAGIC     (4 bytes)  : "DLM\x01"                     │
 * │ licenseId (8 bytes)  : uint64 big-endian              │
 * │ IV        (16 bytes) : AES-256-CBC IV aleatório       │
 * │ HMAC      (32 bytes) : SHA-256 de (licenseId + IV + ciphertext) │
 * │ ciphertext (N bytes) : conteúdo AES-256-CBC           │
 * └──────────────────────────────────────────────────────┘
 *
 * A chave AES não é armazenada no arquivo. Ela é derivada da
 * MASTER_ENCRYPTION_KEY + licenseId via HKDF. Assim:
 * - Copiar o .dlm sem a licença não abre nada.
 * - O servidor gera uma chave de sessão por requisição autorizada.
 */

import crypto from "crypto";

const MAGIC       = Buffer.from("DLM\x01");
const MASTER_KEY  = () => Buffer.from(process.env.MASTER_ENCRYPTION_KEY || "0".repeat(64), "hex");
const ALGO        = "aes-256-cbc";
const HMAC_ALGO   = "sha256";

/**
 * Deriva uma chave AES-256 específica para um licenseId.
 * Usa HKDF-SHA256: chave mestra + "dlm-v1" + licenseId como info.
 */
function deriveKey(licenseId) {
  const info = Buffer.concat([
    Buffer.from("dlm-v1:"),
    Buffer.from(licenseId.toString()),
  ]);
  return crypto.hkdfSync("sha256", MASTER_KEY(), Buffer.alloc(32), info, 32);
}

/**
 * Encripta um Buffer PDF e retorna um Buffer no formato .dlm.
 * @param {Buffer} pdfBuffer  - Conteúdo do PDF original
 * @param {string|number} licenseId - ID da licença vinculada
 * @returns {Buffer} Arquivo .dlm encriptado
 */
export function encryptToDLM(pdfBuffer, licenseId) {
  const key = deriveKey(licenseId);
  const iv  = crypto.randomBytes(16);

  const cipher     = crypto.createCipheriv(ALGO, key, iv);
  const ciphertext = Buffer.concat([cipher.update(pdfBuffer), cipher.final()]);

  // licenseId em 8 bytes big-endian
  const licIdBuf = Buffer.alloc(8);
  licIdBuf.writeBigUInt64BE(BigInt(licenseId));

  // HMAC de integridade
  const hmacInput = Buffer.concat([licIdBuf, iv, ciphertext]);
  const hmac      = crypto.createHmac(HMAC_ALGO, key).update(hmacInput).digest();

  return Buffer.concat([MAGIC, licIdBuf, iv, hmac, ciphertext]);
}

/**
 * Decripta um Buffer .dlm, verificando HMAC e retornando o PDF.
 * @param {Buffer} dlmBuffer  - Arquivo .dlm encriptado
 * @returns {{ pdf: Buffer, licenseId: string }}
 */
export function decryptDLM(dlmBuffer) {
  // Valida magic
  if (!dlmBuffer.slice(0, 4).equals(MAGIC)) {
    throw new Error("Formato .dlm inválido: magic incorreto.");
  }

  const licIdBuf    = dlmBuffer.slice(4, 12);
  const iv          = dlmBuffer.slice(12, 28);
  const storedHmac  = dlmBuffer.slice(28, 60);
  const ciphertext  = dlmBuffer.slice(60);

  const licenseId = licIdBuf.readBigUInt64BE().toString();
  const key       = deriveKey(licenseId);

  // Verifica integridade
  const hmacInput  = Buffer.concat([licIdBuf, iv, ciphertext]);
  const hmac       = crypto.createHmac(HMAC_ALGO, key).update(hmacInput).digest();

  if (!crypto.timingSafeEqual(storedHmac, hmac)) {
    throw new Error("Verificação HMAC falhou: arquivo corrompido ou adulterado.");
  }

  const decipher = crypto.createDecipheriv(ALGO, key, iv);
  const pdf      = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

  return { pdf, licenseId };
}

/**
 * Calcula o hash SHA-256 de um Buffer (para verificação de integridade on-chain).
 * @param {Buffer} buffer
 * @returns {string} Hash hex com prefixo 0x
 */
export function sha256Hex(buffer) {
  return "0x" + crypto.createHash("sha256").update(buffer).digest("hex");
}

/**
 * Gera uma chave de sessão efêmera para leitura em memória.
 * O viewer usa essa chave para decriptação local sem persistir em disco.
 * @param {string} licenseId
 * @param {string} sessionNonce - nonce único por sessão
 * @returns {string} Chave hex de 32 bytes
 */
export function generateSessionKey(licenseId, sessionNonce) {
  return crypto
    .createHmac("sha256", deriveKey(licenseId))
    .update(sessionNonce)
    .digest("hex");
}
