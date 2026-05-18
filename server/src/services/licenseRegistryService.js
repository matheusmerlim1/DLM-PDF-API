/**
 * licenseRegistryService.js
 * Gerencia o registro de posse das licenças .dlm.
 *
 * Persistência: PostgreSQL quando DATABASE_URL está definida (Railway),
 * sistema de arquivos local como fallback (dev / sem banco).
 */

import crypto from "crypto";
import {
  dbGetLicense,
  dbSetLicense,
  dbListLicensesByOwner,
} from "./db.js";

// ── Geração de ID ─────────────────────────────────────────────────────────────

export function generateLicenseId() {
  return (crypto.randomBytes(4).readUInt32BE(0) % 90_000_000 + 10_000_000).toString();
}

// ── CRUD ──────────────────────────────────────────────────────────────────────

export async function createLicense(licenseId, owner, metadata = null) {
  const normalized = owner.address.toLowerCase();
  const record = {
    licenseId:            String(licenseId),
    currentOwner:         { address: normalized, name: owner.name, cpf: owner.cpf },
    encryptedWithAddress: normalized,
    ownershipHistory: [{
      address:    normalized,
      name:       owner.name,
      cpf:        owner.cpf,
      acquiredAt: new Date().toISOString(),
      releasedAt: null,
    }],
    createdAt: new Date().toISOString(),
    ...(metadata?.title  && { title:  metadata.title  }),
    ...(metadata?.author && { author: metadata.author }),
  };
  await dbSetLicense(licenseId, record);
  return record;
}

export async function listLicensesByOwner(address) {
  return dbListLicensesByOwner(address);
}

export async function loadLicense(licenseId) {
  return dbGetLicense(licenseId);
}

export async function saveLicense(record) {
  await dbSetLicense(record.licenseId, record);
}

export async function updateEncryptedWith(licenseId, address) {
  const record = await dbGetLicense(licenseId);
  if (!record) throw new Error(`Licença ${licenseId} não encontrada no registro.`);
  record.encryptedWithAddress = address.toLowerCase();
  await dbSetLicense(licenseId, record);
}

export async function transferLicense(licenseId, fromAddress, toOwner, metadata = null) {
  const record = await dbGetLicense(licenseId);
  if (!record) throw new Error(`Licença ${licenseId} não encontrada.`);

  if (record.currentOwner.address.toLowerCase() !== fromAddress.toLowerCase()) {
    const err = new Error("Você não é o proprietário atual desta licença.");
    err.statusCode = 403;
    throw err;
  }

  const last = record.ownershipHistory[record.ownershipHistory.length - 1];
  if (last && !last.releasedAt) last.releasedAt = new Date().toISOString();

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

  if (metadata?.title  && !record.title)  record.title  = metadata.title;
  if (metadata?.author && !record.author) record.author = metadata.author;

  await dbSetLicense(licenseId, record);
  return record;
}

/**
 * Retorna candidatos para descriptografia (função pura — sem I/O).
 * Mantida síncrona pois é chamada após loadLicense já ter sido awaited.
 */
export function getCandidateAddresses(record) {
  const seen   = new Set();
  const result = [];
  const enc    = record.encryptedWithAddress.toLowerCase();
  seen.add(enc);
  result.push(enc);
  for (let i = record.ownershipHistory.length - 1; i >= 0; i--) {
    const addr = record.ownershipHistory[i].address.toLowerCase();
    if (!seen.has(addr)) { seen.add(addr); result.push(addr); }
  }
  return result;
}
