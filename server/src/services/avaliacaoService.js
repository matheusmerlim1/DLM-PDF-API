/**
 * avaliacaoService.js
 * Armazena e consulta respostas do formulário de avaliação com autores.
 *
 * Persistência: PostgreSQL quando DATABASE_URL está definida (Railway),
 * arquivo storage/avaliacoes.json como fallback (dev / sem banco).
 */

import crypto from "crypto";
import { dbListAvaliacoes, dbInsertAvaliacao, dbDeleteAvaliacao } from "./db.js";

export async function salvarAvaliacao(data) {
  const record = {
    id:          crypto.randomUUID(),
    createdAt:   new Date().toISOString(),
    ...data,
  };
  await dbInsertAvaliacao(record);
  return record;
}

export async function listarAvaliacoes() {
  return dbListAvaliacoes();
}

export async function excluirAvaliacao(id) {
  const deleted = await dbDeleteAvaliacao(id);
  if (!deleted) {
    const err = new Error(`Avaliação ${id} não encontrada.`);
    err.statusCode = 404;
    throw err;
  }
}
