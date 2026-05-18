/**
 * db.js — Camada de persistência
 *
 * Quando DATABASE_URL está definida: usa PostgreSQL (Railway).
 * Caso contrário: usa sistema de arquivos local (development / fallback).
 *
 * Para ativar no Railway:
 *   1. Adicione o plugin "PostgreSQL" no painel Railway — ele define DATABASE_URL automaticamente.
 *   2. Faça redeploy. Os dados persistem entre reinícios.
 */

import fs   from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname    = path.dirname(fileURLToPath(import.meta.url));
const STORAGE_ROOT = process.env.STORAGE_PATH
  || path.resolve(__dirname, "../../../storage");
const LICENSES_DIR = path.join(STORAGE_ROOT, "licenses");
const USERS_FILE   = path.join(STORAGE_ROOT, "users.json");

let pool = null;

// ── Inicialização ─────────────────────────────────────────────────────────────

/**
 * Inicializa a conexão com o banco de dados.
 * Deve ser chamado uma vez no startup, antes de qualquer rota ser servida.
 */
export async function initDB() {
  if (!process.env.DATABASE_URL) {
    return; // usa filesystem
  }

  const { default: pg } = await import("pg");
  const isLocal = process.env.DATABASE_URL.includes("localhost") ||
                  process.env.DATABASE_URL.includes("127.0.0.1") ||
                  process.env.DATABASE_URL.includes(".railway.internal");

  pool = new pg.Pool({
    connectionString: process.env.DATABASE_URL,
    ...(!isLocal && { ssl: { rejectUnauthorized: false } }),
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
  });

  // Cria tabelas se não existirem
  await pool.query(`
    CREATE TABLE IF NOT EXISTS dlm_users (
      address     TEXT PRIMARY KEY,
      name        TEXT NOT NULL,
      cpf         TEXT NOT NULL,
      updated_at  TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS dlm_licenses (
      license_id            TEXT PRIMARY KEY,
      current_owner_address TEXT NOT NULL,
      data                  TEXT NOT NULL,
      updated_at            TEXT NOT NULL
    );
  `);
}

export function dbMode() {
  return pool ? "postgres" : "filesystem";
}

// ── Usuários ──────────────────────────────────────────────────────────────────

export async function dbGetUser(address) {
  const key = address.toLowerCase();
  if (pool) {
    const { rows } = await pool.query(
      "SELECT name, cpf, updated_at FROM dlm_users WHERE address = $1",
      [key]
    );
    if (!rows.length) return null;
    return { address: key, name: rows[0].name, cpf: rows[0].cpf, updatedAt: rows[0].updated_at };
  }
  const db = _loadUsersFile();
  return db[key] || null;
}

export async function dbSetUser(address, user) {
  const key = address.toLowerCase();
  if (pool) {
    await pool.query(
      `INSERT INTO dlm_users (address, name, cpf, updated_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (address) DO UPDATE SET name = $2, cpf = $3, updated_at = $4`,
      [key, user.name, user.cpf, user.updatedAt]
    );
    return;
  }
  const db = _loadUsersFile();
  db[key] = user;
  _saveUsersFile(db);
}

// ── Licenças ──────────────────────────────────────────────────────────────────

export async function dbGetLicense(licenseId) {
  const id = String(licenseId);
  if (pool) {
    const { rows } = await pool.query(
      "SELECT data FROM dlm_licenses WHERE license_id = $1",
      [id]
    );
    return rows.length ? JSON.parse(rows[0].data) : null;
  }
  const p = _licensePath(id);
  if (!fs.existsSync(p)) return null;
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

export async function dbSetLicense(licenseId, record) {
  const id        = String(licenseId);
  const ownerAddr = record.currentOwner.address.toLowerCase();
  if (pool) {
    await pool.query(
      `INSERT INTO dlm_licenses (license_id, current_owner_address, data, updated_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (license_id) DO UPDATE
         SET current_owner_address = $2, data = $3, updated_at = $4`,
      [id, ownerAddr, JSON.stringify(record), new Date().toISOString()]
    );
    return;
  }
  _ensureDirs();
  fs.writeFileSync(_licensePath(id), JSON.stringify(record, null, 2));
}

export async function dbListLicensesByOwner(address) {
  const normalized = address.toLowerCase();
  if (pool) {
    const { rows } = await pool.query(
      "SELECT data FROM dlm_licenses WHERE current_owner_address = $1",
      [normalized]
    );
    return rows.map(r => {
      const rec = JSON.parse(r.data);
      return { licenseId: rec.licenseId, title: rec.title || null, author: rec.author || null };
    });
  }
  _ensureDirs();
  const files = fs.readdirSync(LICENSES_DIR).filter(f => f.endsWith(".json"));
  const books = [];
  for (const file of files) {
    try {
      const rec = JSON.parse(fs.readFileSync(path.join(LICENSES_DIR, file), "utf8"));
      if (rec.currentOwner?.address?.toLowerCase() === normalized) {
        books.push({ licenseId: rec.licenseId, title: rec.title || null, author: rec.author || null });
      }
    } catch { }
  }
  return books;
}

// ── Helpers de arquivo (fallback) ─────────────────────────────────────────────

function _ensureDirs() {
  fs.mkdirSync(LICENSES_DIR, { recursive: true });
}

function _licensePath(licenseId) {
  return path.join(LICENSES_DIR, `${licenseId}.json`);
}

function _loadUsersFile() {
  fs.mkdirSync(STORAGE_ROOT, { recursive: true });
  if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, "{}");
  return JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
}

function _saveUsersFile(db) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(db, null, 2));
}
