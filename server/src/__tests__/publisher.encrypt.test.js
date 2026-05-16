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
 * Regressão 2 (2026-05-16): "Arquivo .dlm inválido: formato não reconhecido."
 * Causado por crypto.js sem suporte a v3 sendo servido do cache do browser.
 * Estes testes confirmam que o serviço de criptografia produz arquivos v3
 * válidos e que parseDLMHeader os reconhece corretamente (versão = 3).
 *
 * Estes testes cobrem o comportamento correto da função de encriptação
 * (a rota em si requer mock de auth middleware que está fora do escopo aqui).
 */

process.env.MASTER_ENCRYPTION_KEY = "4f8ef74f8ef74f8ef74f8ef74f8ef74f4f8ef74f8ef74f8ef74f8ef74f8ef74f";

import {
  encryptToDLMv3,
  encryptToDLM,
  parseDLMHeader,
  tryDecryptV3WithAddress,
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

    expect(headerA.ownerAddress).not.toBe(headerB.ownerAddress);
    expect(headerA.version).toBe(3);
    expect(headerB.version).toBe(3);
    expect(dlmA.equals(dlmB)).toBe(false);
  });
});

// ── Regressão: "formato não reconhecido" ─────────────────────────────────────
// Bug: DML-PDF Platform browser carregava crypto.js antigo (v=2 no cache) que só
// conhecia v1/v2. Arquivos v3 gerados pelo servidor causavam "formato não reconhecido".
// Correção: cache-busting com ?v=3 em todas as páginas.
// Estes testes confirmam que encryptToDLMv3 produz arquivos cujo header é
// reconhecido como versão 3 (magic byte 0x03), não como formato desconhecido.

describe("Regressão: arquivo v3 deve ser reconhecido como versão válida, não 'formato não reconhecido'", () => {

  test("magic bytes de um arquivo v3 são exatamente DLM\\x03 (0x44 0x4C 0x4D 0x03)", () => {
    const dlm = encryptToDLMv3(SAMPLE_PDF, LICENSE_ID, FAKE_ADDRESS);
    expect(dlm[0]).toBe(0x44); // 'D'
    expect(dlm[1]).toBe(0x4C); // 'L'
    expect(dlm[2]).toBe(0x4D); // 'M'
    expect(dlm[3]).toBe(0x03); // versão 3
  });

  test("parseDLMHeader retorna version=3 para arquivo v3 (não lança 'formato não reconhecido')", () => {
    const dlm = encryptToDLMv3(SAMPLE_PDF, LICENSE_ID, FAKE_ADDRESS);
    expect(() => parseDLMHeader(dlm)).not.toThrow();
    const header = parseDLMHeader(dlm);
    expect(header.version).toBe(3);
  });

  test("parseDLMHeader lança erro claro para buffer com magic desconhecido", () => {
    const badMagic = Buffer.from([0x44, 0x4C, 0x4D, 0x04, ...Array(20).fill(0)]);
    expect(() => parseDLMHeader(badMagic)).toThrow(/formato/i);
  });

  test("parseDLMHeader lança erro claro para buffer totalmente inválido (ex.: base64 corrompido)", () => {
    const garbage = Buffer.from("not-a-dlm-file");
    expect(() => parseDLMHeader(garbage)).toThrow();
  });

  test("tryDecryptV3WithAddress retorna null (não lança) para arquivo v1 (versão incompatível)", () => {
    const dlmV1 = encryptToDLM(SAMPLE_PDF, LICENSE_ID);
    // Não deve lançar — retorna null para sinalizar incompatibilidade silenciosamente
    const result = tryDecryptV3WithAddress(dlmV1, FAKE_ADDRESS);
    expect(result).toBeNull();
  });
});

// ── Metadados embutidos (title + author) ─────────────────────────────────────
// Feature implementada em 2026-05-16: title e author são opcionalmente
// embutidos no plaintext v3 usando o marcador "DLMm" para retrocompatibilidade.

describe("Metadados: título e autor embutidos no .dlm v3", () => {

  test("arquivo com metadata embute título e autor — tryDecryptV3WithAddress os retorna", () => {
    const meta = { title: "O Senhor dos Anéis", author: "J.R.R. Tolkien" };
    const dlm  = encryptToDLMv3(SAMPLE_PDF, LICENSE_ID, FAKE_ADDRESS, meta);
    const result = tryDecryptV3WithAddress(dlm, FAKE_ADDRESS);

    expect(result).not.toBeNull();
    expect(result.pdf.equals(SAMPLE_PDF)).toBe(true);
    expect(result.metadata).toEqual({ title: "O Senhor dos Anéis", author: "J.R.R. Tolkien" });
  });

  test("arquivo sem metadata tem metadata=null após decrypt", () => {
    const dlm    = encryptToDLMv3(SAMPLE_PDF, LICENSE_ID, FAKE_ADDRESS);
    const result = tryDecryptV3WithAddress(dlm, FAKE_ADDRESS);

    expect(result).not.toBeNull();
    expect(result.metadata).toBeNull();
  });

  test("arquivo com só title (sem author) é aceito", () => {
    const dlm    = encryptToDLMv3(SAMPLE_PDF, LICENSE_ID, FAKE_ADDRESS, { title: "Duna" });
    const result = tryDecryptV3WithAddress(dlm, FAKE_ADDRESS);

    expect(result).not.toBeNull();
    expect(result.metadata?.title).toBe("Duna");
    expect(result.metadata?.author).toBeUndefined();
  });

  test("arquivo com metadata vazio ({}) trata como sem metadata", () => {
    const dlm    = encryptToDLMv3(SAMPLE_PDF, LICENSE_ID, FAKE_ADDRESS, {});
    const result = tryDecryptV3WithAddress(dlm, FAKE_ADDRESS);

    expect(result).not.toBeNull();
    // {} não tem title nem author → metadata não é embutido → result.metadata é null
    expect(result.metadata).toBeNull();
  });

  test("metadata preservado após re-encriptação com novo dono", () => {
    const meta    = { title: "1984", author: "George Orwell" };
    const dlmOwA  = encryptToDLMv3(SAMPLE_PDF, LICENSE_ID, FAKE_ADDRESS, meta);
    const resOwA  = tryDecryptV3WithAddress(dlmOwA, FAKE_ADDRESS);

    expect(resOwA).not.toBeNull();

    // Re-encripta para novo dono preservando metadata
    const newOwner = "0x" + "e".repeat(40);
    const dlmOwB   = encryptToDLMv3(resOwA.pdf, LICENSE_ID, newOwner, resOwA.metadata);
    const resOwB   = tryDecryptV3WithAddress(dlmOwB, newOwner);

    expect(resOwB).not.toBeNull();
    expect(resOwB.metadata).toEqual(meta);
    expect(resOwB.pdf.equals(SAMPLE_PDF)).toBe(true);
  });

  test("arquivo v3 antigo (sem marcador DLMm) ainda decifra corretamente (retrocompatibilidade)", () => {
    // Simula plaintext antigo: verifyCode(4B) || pdf — sem marcador DLMm
    // Confirmado pelo fato de encryptToDLMv3 sem metadata não incluir o marcador
    const dlmLegacy = encryptToDLMv3(SAMPLE_PDF, LICENSE_ID, FAKE_ADDRESS, null);
    const result    = tryDecryptV3WithAddress(dlmLegacy, FAKE_ADDRESS);

    expect(result).not.toBeNull();
    expect(result.pdf.equals(SAMPLE_PDF)).toBe(true);
    expect(result.metadata).toBeNull();
  });
});

// ── Fallback perigoso removido ────────────────────────────────────────────────

describe("Regressão: fallback perigoso removido de APIPublisher.encryptPDF", () => {

  test("formato v1 falso (btoa) NÃO é um .dlm válido — confirmar que o fallback era inválido", () => {
    const fakeDlm = Buffer.from(
      btoa ? btoa("DLM\x01" + "4" + "_encrypted_content_demo") : "invalid",
      "base64"
    );

    if (fakeDlm[3] === 0x01) {
      const header = parseDLMHeader(fakeDlm);
      expect(header.licenseId).not.toBe("4");
    }
  });
});
