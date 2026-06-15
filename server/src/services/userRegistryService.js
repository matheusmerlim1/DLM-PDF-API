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

/**
 * Mascara um CPF para retorno em respostas da API.
 * Revela apenas os 2 últimos dígitos; o resto vira '*'.
 *
 * LGPD: nenhuma lógica criptográfica depende do CPF (é só cadastro), então
 * ele nunca deve sair completo em endpoints — vários são públicos (GET
 * /users/:address) ou expõem o dado de um terceiro (POST /transfer/preview).
 * A máscara preserva os 2 dígitos finais para conferência humana sem vazar
 * o documento inteiro.
 *
 * Ex.: "123.456.789-01" → "***.***.***-01"
 *
 * @param {string|null|undefined} cpf
 * @returns {string|null}
 */
export function maskCPF(cpf) {
  if (cpf == null) return null;
  const digits = String(cpf).replace(/\D/g, "");
  if (digits.length !== 11) return "***.***.***-**";
  return `***.***.***-${digits.slice(-2)}`;
}
