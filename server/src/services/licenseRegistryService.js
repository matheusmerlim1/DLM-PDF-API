/**
 * licenseRegistryService.js
 * Gerencia o registro de posse das licenças .dlm no sistema de arquivos.
 *
 * Cada licença tem um arquivo JSON em storage/licenses/{licenseId}.json com:
 *  - currentOwner: dono atual (address, name, cpf)
 *  - encryptedWithAddress: endereço cujas chaves foram usadas na última cifragem
 *  - ownershipHistory: cadeia completa de todos os donos anteriores
 *
 * O campo "encryptedWithAddress" é atualizado pelo servidor toda vez que o
 * arquivo é re-cifrado (na descriptografia pelo novo dono). Esse campo é a
 * primeira chave tentada na decriptação. Se falhar, o servidor itera o
 * histórico de donos até encontrar a chave correta (verificada pelo código
 * de verificação embutido no ciphertext).
 */

import crypto from "crypto";
import fs     from "fs";
import path   from "path";
import { fileURLToPath } from "url";

const __dirname     = path.dirname(fileURLToPath(import.meta.url));
const STORAGE_ROOT  = path.resolve(__dirname, "../../../storage");
const LICENSES_DIR  = path.join(STORAGE_ROOT, "licenses");

function ensureDirs() {
  fs.mkdirSync(LICENSES_DIR, { recursive: true });
}

function licensePath(licenseId) {
  return path.join(LICENSES_DIR, `${String(licenseId)}.json`);
}

// ── Geração de ID ─────────────────────────────────────────────

/**
 * Gera um licenseId numérico aleatório de 8 dígitos.
 * Em produção com blockchain, use o ID retornado pelo mintLicense().
 */
export function generateLicenseId() {
  return (crypto.randomBytes(4).readUInt32BE(0) % 90_000_000 + 10_000_000).toString();
}

// ── CRUD ──────────────────────────────────────────────────────

/**
 * Cria um novo registro de licença (chamado no encrypt).
 * @param {string} licenseId
 * @param {{ address: string, name: string, cpf: string }} owner
 * @param {{ title?: string, author?: string }|null} metadata
 */
export function createLicense(licenseId, owner, metadata = null) {
  ensureDirs();
  const normalized = owner.address.toLowerCase();
  const record = {
    licenseId: String(licenseId),
    currentOwner: { address: normalized, name: owner.name, cpf: owner.cpf },
    encryptedWithAddress: normalized,
    ownershipHistory: [
      {
        address:     normalized,
        name:        owner.name,
        cpf:         owner.cpf,
        acquiredAt:  new Date().toISOString(),
        releasedAt:  null,
      },
    ],
    createdAt: new Date().toISOString(),
    ...(metadata?.title  && { title:  metadata.title  }),
    ...(metadata?.author && { author: metadata.author }),
  };
  fs.writeFileSync(licensePath(licenseId), JSON.stringify(record, null, 2));
  return record;
}

/**
 * Lista todas as licenças cujo currentOwner é o endereço fornecido.
 * Usado pelo endpoint GET /busca.
 */
export function listLicensesByOwner(address) {
  ensureDirs();
  const normalized = address.toLowerCase();
  const files = fs.readdirSync(LICENSES_DIR).filter(f => f.endsWith(".json"));
  const books = [];
  for (const file of files) {
    try {
      const record = JSON.parse(fs.readFileSync(path.join(LICENSES_DIR, file), "utf8"));
      if (record.currentOwner?.address?.toLowerCase() === normalized) {
        books.push({
          licenseId: record.licenseId,
          title:     record.title  || null,
          author:    record.author || null,
        });
      }
    } catch { /* pula arquivos corrompidos */ }
  }
  return books;
}

/**
 * Carrega um registro de licença. Retorna null se não existir.
 */
export function loadLicense(licenseId) {
  const p = licensePath(licenseId);
  if (!fs.existsSync(p)) return null;
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

/**
 * Salva alterações em um registro existente.
 */
export function saveLicense(record) {
  ensureDirs();
  fs.writeFileSync(licensePath(record.licenseId), JSON.stringify(record, null, 2));
}

/**
 * Atualiza encryptedWithAddress após re-cifragem.
 * Chamado pelo endpoint /decrypt quando o arquivo é re-cifrado para o dono atual.
 */
export function updateEncryptedWith(licenseId, address) {
  const record = loadLicense(licenseId);
  if (!record) throw new Error(`Licença ${licenseId} não encontrada no registro.`);
  record.encryptedWithAddress = address.toLowerCase();
  saveLicense(record);
}

/**
 * Transfere a posse de uma licença para um novo dono.
 * Não re-cifra o arquivo .dlm — isso ocorre na próxima chamada ao /decrypt.
 *
 * @param {string} licenseId
 * @param {string} fromAddress - endereço do dono atual (verificado aqui)
 * @param {{ address: string, name: string, cpf: string }} toOwner
 */
export function transferLicense(licenseId, fromAddress, toOwner) {
  const record = loadLicense(licenseId);
  if (!record) throw new Error(`Licença ${licenseId} não encontrada.`);

  if (record.currentOwner.address.toLowerCase() !== fromAddress.toLowerCase()) {
    const err = new Error("Você não é o proprietário atual desta licença.");
    err.statusCode = 403;
    throw err;
  }

  // Marca o dono atual como liberado no histórico
  const last = record.ownershipHistory[record.ownershipHistory.length - 1];
  if (last && !last.releasedAt) {
    last.releasedAt = new Date().toISOString();
  }

  // Adiciona o novo dono ao histórico
  record.ownershipHistory.push({
    address:    toOwner.address.toLowerCase(),
    name:       toOwner.name,
    cpf:        toOwner.cpf,
    acquiredAt: new Date().toISOString(),
    releasedAt: null,
  });

  record.currentOwner = {
    address: toOwner.address.toLowerCase(),
    name:    toOwner.name,
    cpf:     toOwner.cpf,
  };

  // encryptedWithAddress permanece o mesmo até o novo dono abrir o arquivo
  // (que re-cifra com as chaves dele)

  saveLicense(record);
  return record;
}

/**
 * Retorna todos os endereços que já cifraram o arquivo, em ordem de
 * prioridade: [encryptedWithAddress, ...história reversa].
 * Usado pelo /decrypt para tentar cada chave.
 */
export function getCandidateAddresses(record) {
  const seen = new Set();
  const result = [];

  // Primeiro candidato: quem cifrou por último
  const enc = record.encryptedWithAddress.toLowerCase();
  seen.add(enc);
  result.push(enc);

  // Demais: histórico em ordem reversa (mais recente primeiro)
  for (let i = record.ownershipHistory.length - 1; i >= 0; i--) {
    const addr = record.ownershipHistory[i].address.toLowerCase();
    if (!seen.has(addr)) {
      seen.add(addr);
      result.push(addr);
    }
  }

  return result;
}
