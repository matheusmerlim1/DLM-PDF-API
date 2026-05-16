/**
 * js/crypto.js
 * Responsabilidade: toda a lógica criptográfica do sistema DLM-PDF.
 *
 * Formatos suportados:
 * ┌─────────────────────────────────────────────────────────────┐
 * │ v1  MAGIC(4) licenseId(8) IV(16) HMAC(32) ciphertext        │
 * │ v2  MAGIC(4) licenseId(8) ownerAddr(42) IV(16) HMAC(32) … │
 * │ v3  igual ao v2, com verifyCode + metadados no plaintext    │
 * └─────────────────────────────────────────────────────────────┘
 * v1: cabeçalho total = 60 bytes (decriptação local via demo key)
 * v2/v3: cabeçalho total = 102 bytes (decriptação via servidor)
 */

'use strict';

// ── Constantes ────────────────────────────────────────────
const DLM_MAGIC_V1 = [0x44, 0x4C, 0x4D, 0x01]; // "DLM\x01"
const DLM_MAGIC_V2 = [0x44, 0x4C, 0x4D, 0x02]; // "DLM\x02"
const DLM_MAGIC_V3 = [0x44, 0x4C, 0x4D, 0x03]; // "DLM\x03"
const DLM_MAGIC    = DLM_MAGIC_V1;              // alias legacy

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
/**
 * Decripta um arquivo .dlm v1 (demo) em memória.
 * Apenas para arquivos gerados localmente com a chave demo.
 * Arquivos v2/v3 devem ser decriptados via servidor (reader.js).
 *
 * @param {ArrayBuffer} dlmBuffer
 * @returns {Promise<{ pdf: ArrayBuffer, licenseId: string, hmacOk: boolean }>}
 */
async function decryptDLM(dlmBuffer) {
  const header = parseDLMHeader(dlmBuffer);
  if (header.version !== 1) {
    throw new Error(
      `Arquivo .dlm v${header.version} requer decriptação pelo servidor. Use MetaMask para abrir.`
    );
  }

  const bytes      = new Uint8Array(dlmBuffer);
  const { licenseId, ivOffset, hmacOffset, ciphertextOffset } = header;

  const iv         = bytes.slice(ivOffset,          ivOffset + 16);
  const storedHmac = bytes.slice(hmacOffset,        hmacOffset + 32);
  const ciphertext = bytes.slice(ciphertextOffset);

  const aesKey   = await deriveKey(licenseId);
  const keyBytes = await keyToBytes(aesKey);

  const licIdBuf  = bytes.slice(4, 12);
  const hmacInput = new Uint8Array([...licIdBuf, ...iv, ...ciphertext]);
  const computed  = await hmacSHA256(keyBytes, hmacInput.buffer);

  let diff = 0;
  for (let i = 0; i < 32; i++) diff |= computed[i] ^ storedHmac[i];
  if (diff !== 0) {
    throw new Error('Verificação HMAC falhou: arquivo corrompido ou adulterado.');
  }

  const pdf = await crypto.subtle.decrypt(
    { name: 'AES-CBC', iv },
    aesKey,
    ciphertext.buffer
  );

  return { pdf, licenseId, hmacOk: true };
}

/**
 * Detecta a versão de um arquivo .dlm pelos 4 bytes de magic.
 * @param {Uint8Array} bytes
 * @returns {1|2|3|0} versão ou 0 se inválido
 */
function detectDLMVersion(bytes) {
  if (bytes[0] !== 0x44 || bytes[1] !== 0x4C || bytes[2] !== 0x4D) return 0;
  if (bytes[3] === 0x01) return 1;
  if (bytes[3] === 0x02) return 2;
  if (bytes[3] === 0x03) return 3;
  return 0;
}

/**
 * Lê o cabeçalho de um .dlm (v1, v2 ou v3) sem decriptografar.
 * @param {ArrayBuffer} dlmBuffer
 * @returns {{ version, licenseId, ownerAddress, ivOffset, hmacOffset, ciphertextOffset }}
 * @throws {Error} Se o formato não for reconhecido
 */
function parseDLMHeader(dlmBuffer) {
  const bytes   = new Uint8Array(dlmBuffer);
  const version = detectDLMVersion(bytes);
  if (!version) throw new Error('Formato de arquivo .dlm não reconhecido.');

  const view      = new DataView(dlmBuffer);
  const licenseId = view.getBigUint64(4, false).toString();

  if (version === 1) {
    return { version: 1, licenseId, ownerAddress: null,
             ivOffset: 12, hmacOffset: 28, ciphertextOffset: 60 };
  }

  // v2 e v3: ownerAddr ASCII em bytes 12–53 (42 bytes)
  const ownerAddress = new TextDecoder().decode(bytes.slice(12, 54))
    .replace(/\0/g, '').trim();
  return { version, licenseId, ownerAddress,
           ivOffset: 54, hmacOffset: 70, ciphertextOffset: 102 };
}

/**
 * Extrai o licenseId do cabeçalho de um arquivo .dlm (v1, v2 ou v3)
 * sem decriptografar o conteúdo.
 * @param {ArrayBuffer} dlmBuffer
 * @returns {string} licenseId como string decimal
 * @throws {Error} Se o formato não for reconhecido
 */
function readLicenseId(dlmBuffer) {
  return parseDLMHeader(dlmBuffer).licenseId;
}

// Exporta para uso nos outros módulos via window
window.DLMCrypto = {
  DLM_MAGIC, DLM_MAGIC_V1, DLM_MAGIC_V2, DLM_MAGIC_V3,
  hexToBytes,
  bytesToHex,
  randomBytes,
  sha256,
  exportKeyHex,
  encryptPDF,
  decryptDLM,
  parseDLMHeader,
  readLicenseId,
};
