/**
 * js/crypto.js
 * Responsabilidade: toda a lógica criptográfica do sistema DLM-PDF.
 *
 * Inclui:
 *  - Derivação de chave via HKDF-SHA-256
 *  - Cifragem AES-256-CBC (PDF → .dlm)
 *  - Decifragem AES-256-CBC (.dlm → PDF)
 *  - Cálculo de SHA-256 e HMAC-SHA-256
 *  - Montagem e parsing do formato binário .dlm
 *
 * Formato do arquivo .dlm:
 * ┌─────────────────────────────────────────────────────┐
 * │ MAGIC      4B  : "DLM\x01"                          │
 * │ licenseId  8B  : uint64 big-endian                   │
 * │ IV        16B  : vetor de inicialização AES          │
 * │ HMAC      32B  : HMAC-SHA-256 de integridade         │
 * │ ciphertext NB  : conteúdo AES-256-CBC                │
 * └─────────────────────────────────────────────────────┘
 */

'use strict';

// ── Constantes ────────────────────────────────────────────
const DLM_MAGIC = [0x44, 0x4C, 0x4D, 0x01]; // "DLM\x01"

/**
 * Chave mestra de demonstração (32 bytes / 256 bits).
 * Em produção, esta chave reside exclusivamente no servidor
 * de autenticação e nunca é exposta ao cliente.
 */
const MASTER_KEY_HEX =
  '4f8ef74f8ef74f8ef74f8ef74f8ef74f' +
  '8ef74f8ef74f8ef74f8ef74f8ef74f8e';

// ── Utilitários internos ──────────────────────────────────

/**
 * Converte string hex em Uint8Array.
 * @param {string} hex
 * @returns {Uint8Array}
 */
function hexToBytes(hex) {
  return new Uint8Array(hex.match(/.{2}/g).map(h => parseInt(h, 16)));
}

/**
 * Converte ArrayBuffer ou Uint8Array em string hex.
 * @param {ArrayBuffer|Uint8Array} buf
 * @param {number} [len] - limite de bytes
 * @returns {string}
 */
function bytesToHex(buf, len) {
  const arr = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return Array.from(len ? arr.slice(0, len) : arr)
    .map(b => b.toString(16).padStart(2, '0'))
    .join(' ');
}

/**
 * Gera N bytes aleatórios criptograficamente seguros.
 * @param {number} n
 * @returns {Uint8Array}
 */
function randomBytes(n) {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

// ── API pública do módulo ─────────────────────────────────

/**
 * Importa a chave mestra como CryptoKey HKDF.
 * @returns {Promise<CryptoKey>}
 */
async function importMasterKey() {
  const raw = hexToBytes(MASTER_KEY_HEX);
  return crypto.subtle.importKey(
    'raw', raw,
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );
}

/**
 * Deriva uma chave AES-256-CBC específica para um licenseId.
 * Usa HKDF-SHA-256: info = "dlm-v1:<licenseId>", salt fixo.
 *
 * @param {string|number} licenseId
 * @returns {Promise<CryptoKey>} Chave AES-256-CBC
 */
async function deriveKey(licenseId) {
  const master = await importMasterKey();
  const info   = new TextEncoder().encode(`dlm-v1:${licenseId}`);
  const salt   = new Uint8Array(32); // salt fixo em demo; em produção: aleatório e armazenado

  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    master,
    { name: 'AES-CBC', length: 256 },
    true,           // exportável apenas para exibição em modo demo
    ['encrypt', 'decrypt']
  );
}

/**
 * Exporta uma CryptoKey AES como string hex (somente demo).
 * @param {CryptoKey} cryptoKey
 * @returns {Promise<string>}
 */
async function exportKeyHex(cryptoKey) {
  const raw = await crypto.subtle.exportKey('raw', cryptoKey);
  return Array.from(new Uint8Array(raw))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Retorna os bytes brutos de uma CryptoKey AES.
 * @param {CryptoKey} cryptoKey
 * @returns {Promise<Uint8Array>}
 */
async function keyToBytes(cryptoKey) {
  return new Uint8Array(await crypto.subtle.exportKey('raw', cryptoKey));
}

/**
 * Calcula SHA-256 de um ArrayBuffer. Retorna string hex.
 * @param {ArrayBuffer} buf
 * @returns {Promise<string>}
 */
async function sha256(buf) {
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Calcula HMAC-SHA-256 com keyBytes sobre data.
 * @param {Uint8Array} keyBytes
 * @param {ArrayBuffer} data
 * @returns {Promise<Uint8Array>}
 */
async function hmacSHA256(keyBytes, data) {
  const k = await crypto.subtle.importKey(
    'raw', keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, data));
}

/**
 * Encripta um PDF (ArrayBuffer) e retorna um objeto .dlm.
 *
 * @param {ArrayBuffer} pdfBuffer - Conteúdo do PDF original
 * @param {string|number} licenseId - ID do exemplar único
 * @returns {Promise<{
 *   dlm: ArrayBuffer,        // arquivo .dlm final
 *   iv: Uint8Array,          // vetor de inicialização
 *   hmacBytes: Uint8Array,   // bytes do HMAC
 *   ciphertext: Uint8Array,  // conteúdo cifrado
 *   keyBytes: Uint8Array,    // bytes da chave (demo only)
 *   aesKey: CryptoKey        // chave AES (demo only)
 * }>}
 */
async function encryptPDF(pdfBuffer, licenseId) {
  // 1. Deriva a chave AES para este licenseId
  const aesKey   = await deriveKey(licenseId);
  const keyBytes = await keyToBytes(aesKey);

  // 2. IV aleatório de 16 bytes
  const iv = randomBytes(16);

  // 3. Cifra o PDF com AES-256-CBC
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, aesKey, pdfBuffer)
  );

  // 4. Serializa licenseId em 8 bytes big-endian
  const licIdBuf  = new Uint8Array(8);
  const licIdView = new DataView(licIdBuf.buffer);
  licIdView.setBigUint64(0, BigInt(licenseId), false);

  // 5. Calcula HMAC sobre (licenseId || IV || ciphertext)
  const hmacInput = new Uint8Array([...licIdBuf, ...iv, ...ciphertext]);
  const hmacBytes = await hmacSHA256(keyBytes, hmacInput.buffer);

  // 6. Monta o arquivo .dlm
  const magic  = new Uint8Array(DLM_MAGIC);
  const result = new Uint8Array(4 + 8 + 16 + 32 + ciphertext.length);
  let off = 0;
  result.set(magic,      off); off += 4;
  result.set(licIdBuf,   off); off += 8;
  result.set(iv,         off); off += 16;
  result.set(hmacBytes,  off); off += 32;
  result.set(ciphertext, off);

  return { dlm: result.buffer, iv, hmacBytes, ciphertext, keyBytes, aesKey };
}

/**
 * Decripta um arquivo .dlm (ArrayBuffer) e retorna o PDF original.
 * Verifica magic, HMAC de integridade e decifra AES-256-CBC.
 *
 * @param {ArrayBuffer} dlmBuffer
 * @returns {Promise<{ pdf: ArrayBuffer, licenseId: string, hmacOk: boolean }>}
 * @throws {Error} Se magic inválido ou HMAC não conferir
 */
async function decryptDLM(dlmBuffer) {
  const bytes = new Uint8Array(dlmBuffer);

  // Valida magic "DLM\x01"
  for (let i = 0; i < 4; i++) {
    if (bytes[i] !== DLM_MAGIC[i]) {
      throw new Error('Arquivo .dlm inválido: magic incorreto.');
    }
  }

  // Lê licenseId dos bytes 4–11 (uint64 big-endian)
  const view      = new DataView(dlmBuffer);
  const licenseId = view.getBigUint64(4, false).toString();

  const iv         = bytes.slice(12, 28);
  const storedHmac = bytes.slice(28, 60);
  const ciphertext = bytes.slice(60);

  // Deriva a mesma chave usada na cifragem
  const aesKey   = await deriveKey(licenseId);
  const keyBytes = await keyToBytes(aesKey);

  // Recalcula HMAC e compara (proteção contra adulteração)
  const licIdBuf  = bytes.slice(4, 12);
  const hmacInput = new Uint8Array([...licIdBuf, ...iv, ...ciphertext]);
  const computed  = await hmacSHA256(keyBytes, hmacInput.buffer);

  // Comparação bit a bit (evita timing attack)
  let diff = 0;
  for (let i = 0; i < 32; i++) diff |= computed[i] ^ storedHmac[i];
  if (diff !== 0) {
    throw new Error('Verificação HMAC falhou: arquivo corrompido ou adulterado.');
  }

  // Decifra o conteúdo
  const pdf = await crypto.subtle.decrypt(
    { name: 'AES-CBC', iv },
    aesKey,
    ciphertext.buffer
  );

  return { pdf, licenseId, hmacOk: true };
}

/**
 * Extrai o licenseId do cabeçalho de um arquivo .dlm
 * sem decriptografar o conteúdo.
 *
 * @param {ArrayBuffer} dlmBuffer
 * @returns {string} licenseId como string decimal
 * @throws {Error} Se magic inválido
 */
function readLicenseId(dlmBuffer) {
  const bytes = new Uint8Array(dlmBuffer);
  for (let i = 0; i < 4; i++) {
    if (bytes[i] !== DLM_MAGIC[i]) throw new Error('Magic inválido.');
  }
  const view = new DataView(dlmBuffer);
  return view.getBigUint64(4, false).toString();
}

// Exporta para uso nos outros módulos via window
window.DLMCrypto = {
  DLM_MAGIC,
  hexToBytes,
  bytesToHex,
  randomBytes,
  sha256,
  exportKeyHex,
  encryptPDF,
  decryptDLM,
  readLicenseId,
};
