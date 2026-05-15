/**
 * userRegistryService.js
 * Registro de usuários (endereço Ethereum → nome + CPF).
 *
 * Usado pelos endpoints /encrypt (para gravar o titular inicial) e
 * /transfer/preview (para exibir nome e CPF do destinatário antes
 * da aprovação da transferência).
 *
 * Armazenamento: storage/users.json  (objeto chaveado pelo address em lowercase)
 */

import fs   from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname    = path.dirname(fileURLToPath(import.meta.url));
const STORAGE_ROOT = path.resolve(__dirname, "../../../storage");
const USERS_FILE   = path.join(STORAGE_ROOT, "users.json");

function ensureFile() {
  fs.mkdirSync(STORAGE_ROOT, { recursive: true });
  if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, "{}");
}

function loadDB() {
  ensureFile();
  return JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
}

function saveDB(db) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(db, null, 2));
}

// ── API pública ───────────────────────────────────────────────

/**
 * Registra ou atualiza um usuário.
 * @param {string} address - endereço Ethereum
 * @param {string} name    - nome completo
 * @param {string} cpf     - CPF (formato livre, validado pelo front)
 */
export function registerUser(address, name, cpf) {
  const db  = loadDB();
  const key = address.toLowerCase();
  db[key] = {
    address:      key,
    name,
    cpf,
    updatedAt:    new Date().toISOString(),
  };
  saveDB(db);
  return db[key];
}

/**
 * Busca usuário pelo endereço Ethereum. Retorna null se não encontrado.
 */
export function lookupUser(address) {
  const db = loadDB();
  return db[address.toLowerCase()] || null;
}
