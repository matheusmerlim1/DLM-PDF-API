/**
 * userRegistryService.js
 * Registro de usuários (endereço Ethereum → nome + CPF).
 *
 * Persistência: PostgreSQL quando DATABASE_URL está definida (Railway),
 * arquivo storage/users.json como fallback (dev / sem banco).
 */

import { dbGetUser, dbSetUser } from "./db.js";

export async function registerUser(address, name, cpf) {
  const user = {
    address:   address.toLowerCase(),
    name,
    cpf,
    updatedAt: new Date().toISOString(),
  };
  await dbSetUser(address, user);
  return user;
}

export async function lookupUser(address) {
  return dbGetUser(address);
}
