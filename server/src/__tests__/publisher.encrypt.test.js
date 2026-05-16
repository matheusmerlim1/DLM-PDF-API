/**
 * publisher.encrypt.test.js
 *
 * Regressão: POST /publisher/encrypt criava .dlm v1 quando ownerAddress
 * era omitido (Livraria DLM antiga enviava só licenseId, sem ownerAddress).
 * Arquivos v1 exigem blockchain para abrir → "Acesso negado. Você não é o
 * proprietário desta licença na blockchain."
 *
 * Bug corrigido em 2026-05-15: rota agora SEMPRE cria v3, usando o
 * endereço do JWT quando ownerAddress não é fornecido.
 *
 * Estes testes cobrem o comportamento correto da função de encriptação
 * (a rota em si requer mock de auth middleware que está fora do escopo aqui).
 */

process.env.MASTER_ENCRYPTION_KEY = "4f8ef74f8ef74f8ef74f8ef74f8ef74f4f8ef74f8ef74f8ef74f8ef74f8ef74f";

import {
  encryptToDLMv3,
  encryptToDLM,
  parseDLMHeader,
} from "../services/encryptionService.js";

const FAKE_ADDRESS = "0x" + "c".repeat(40);
const SAMPLE_PDF   = Buffer.from("fake-pdf-content-for-publisher-regression");
const LICENSE_ID   = "99887766";

// ── Testes de regressão ───────────────────────────────────────────────────────

describe("Regressão: publisher.encrypt deve sempre criar v3 (não v1)", () => {

  test("encryptToDLMv3 produz magic byte 0x03 (v3), não 0x01 (v1)", () => {
    const dlm = encryptToDLMv3(SAMPLE_PDF, LICENSE_ID, FAKE_ADDRESS);
    expect(dlm[3]).toBe(0x03);  // v3
    expect(dlm[3]).not.toBe(0x01);  // não v1
    expect(dlm[3]).not.toBe(0x02);  // não v2
  });

  test("encryptToDLM (legado) ainda cria v1 — confirmar que NÃO deve ser chamado", () => {
    const dlmV1 = encryptToDLM(SAMPLE_PDF, LICENSE_ID);
    expect(dlmV1[3]).toBe(0x01);
    // Isso prova que o bug era chamar encryptToDLM; a correção foi chamar encryptToDLMv3
  });

  test("parseDLMHeader do output v3 retorna versão 3 e ownerAddress correto", () => {
    const dlm    = encryptToDLMv3(SAMPLE_PDF, LICENSE_ID, FAKE_ADDRESS);
    const header = parseDLMHeader(dlm);
    expect(header.version).toBe(3);
    expect(header.ownerAddress.toLowerCase()).toBe(FAKE_ADDRESS.toLowerCase());
    expect(header.licenseId).toBe(LICENSE_ID);
  });

  test("v3 sem ownerAddress do body usa endereço do JWT — simulado como endereço fixo", () => {
    // Simula o comportamento da rota quando bodyOwner é inválido/ausente:
    // a rota usa req.userAddress (do JWT). Aqui testamos que o endereço
    // é corretamente gravado no cabeçalho.
    const jwtAddress = "0x" + "d".repeat(40);
    const dlm = encryptToDLMv3(SAMPLE_PDF, LICENSE_ID, jwtAddress);
    const header = parseDLMHeader(dlm);
    expect(header.ownerAddress.toLowerCase()).toBe(jwtAddress.toLowerCase());
  });

  test("dois arquivos criados com o mesmo PDF mas ownerAddresses diferentes são distintos", () => {
    const dlmA = encryptToDLMv3(SAMPLE_PDF, LICENSE_ID, "0x" + "a".repeat(40));
    const dlmB = encryptToDLMv3(SAMPLE_PDF, LICENSE_ID, "0x" + "b".repeat(40));

    const headerA = parseDLMHeader(dlmA);
    const headerB = parseDLMHeader(dlmB);

    // Proprietários diferentes
    expect(headerA.ownerAddress).not.toBe(headerB.ownerAddress);

    // Ambos são v3
    expect(headerA.version).toBe(3);
    expect(headerB.version).toBe(3);

    // Ciphertext diferente (chaves HKDF derivadas do ownerAddress)
    expect(dlmA.equals(dlmB)).toBe(false);
  });
});

describe("Regressão: fallback perigoso removido de APIPublisher.encryptPDF", () => {

  test("formato v1 falso (btoa) NÃO é um .dlm válido — confirmar que o fallback era inválido", () => {
    // O fallback antigo criava: btoa('DLM\x01' + licenseId + '_encrypted_content_demo')
    // Isso NÃO é um .dlm estruturalmente válido (licenseId não é uint64 big-endian)
    const fakeDlm = Buffer.from(
      btoa ? btoa("DLM\x01" + "4" + "_encrypted_content_demo") : "invalid",
      "base64"
    );

    // O header parseado teria versão 1 mas licenseId corrompido
    if (fakeDlm[3] === 0x01) {
      const header = parseDLMHeader(fakeDlm);
      // licenseId lido como uint64 big-endian da sequência ASCII "4_encry..." ≠ "4"
      expect(header.licenseId).not.toBe("4");
    }
  });

  // NOTA: o comportamento correto é que drmFetch lance erro em vez de retornar fallback.
  // O teste de integração real requer mock de fetch — coberto nos testes do DML-PDF Platform.
});
