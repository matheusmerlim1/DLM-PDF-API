/**
 * drm.v3.test.js
 *
 * Testes de regressão para o formato .dlm v3 e cadeia de custódia.
 *
 * Bug corrigido: arquivos criados via publisher.html (v1, sem licenseRegistry)
 * não podiam ser lidos no DML-PDF Reader porque a rota /licenses/:id/read
 * exigia validação blockchain inexistente para esses licenseIds.
 *
 * A correção: publisher agora usa APIDLM.encrypt (v3) que registra o titular
 * no licenseRegistry; o reader usa a rota /decrypt que verifica o licenseRegistry.
 *
 * Este arquivo testa as funções de criptografia v3 e o licenseRegistry isoladamente.
 */

// Define MASTER_ENCRYPTION_KEY antes de qualquer import que a use
process.env.MASTER_ENCRYPTION_KEY = "4f8ef74f8ef74f8ef74f8ef74f8ef74f4f8ef74f8ef74f8ef74f8ef74f8ef74f";

import {
  encryptToDLMv3,
  tryDecryptV3WithAddress,
  decryptDLMv3WithChain,
  parseDLMHeader,
} from "../services/encryptionService.js";

// ── Constantes de teste ──────────────────────────────────────────────────────

const FAKE_ADDRESS_A = "0x" + "a".repeat(40);
const FAKE_ADDRESS_B = "0x" + "b".repeat(40);
const SAMPLE_PDF     = Buffer.from("fake-pdf-content-for-testing-drm-v3");
const LICENSE_ID     = "12345678";

// ── Testes ───────────────────────────────────────────────────────────────────

describe("DRM v3 — encryptToDLMv3", () => {
  let dlmBuffer;

  beforeAll(() => {
    dlmBuffer = encryptToDLMv3(SAMPLE_PDF, LICENSE_ID, FAKE_ADDRESS_A);
  });

  test("retorna Buffer não-vazio", () => {
    expect(Buffer.isBuffer(dlmBuffer)).toBe(true);
    expect(dlmBuffer.length).toBeGreaterThan(0);
  });

  test("magic bytes = DLM\\x03", () => {
    expect(dlmBuffer[0]).toBe(0x44); // D
    expect(dlmBuffer[1]).toBe(0x4C); // L
    expect(dlmBuffer[2]).toBe(0x4D); // M
    expect(dlmBuffer[3]).toBe(0x03); // v3
  });

  test("parseDLMHeader detecta versão 3", () => {
    const header = parseDLMHeader(dlmBuffer);
    expect(header.version).toBe(3);
    expect(header.licenseId).toBe(LICENSE_ID);
  });

  test("ownerAddress no cabeçalho bate com o endereço informado", () => {
    const header = parseDLMHeader(dlmBuffer);
    expect(header.ownerAddress.toLowerCase()).toBe(FAKE_ADDRESS_A.toLowerCase());
  });
});

describe("DRM v3 — tryDecryptV3WithAddress", () => {
  let dlmBuffer;

  beforeAll(() => {
    dlmBuffer = encryptToDLMv3(SAMPLE_PDF, LICENSE_ID, FAKE_ADDRESS_A);
  });

  test("decifra com o endereço correto e retorna o PDF original", () => {
    const result = tryDecryptV3WithAddress(dlmBuffer, FAKE_ADDRESS_A);
    expect(result).not.toBeNull();
    expect(result.pdf.equals(SAMPLE_PDF)).toBe(true);
  });

  test("retorna null para endereço errado (simula acesso negado sem blockchain)", () => {
    const result = tryDecryptV3WithAddress(dlmBuffer, FAKE_ADDRESS_B);
    expect(result).toBeNull();
  });
});

describe("DRM v3 — decryptDLMv3WithChain (cadeia de custódia)", () => {
  test("encontra a chave correta em uma lista de candidatos", () => {
    const dlm = encryptToDLMv3(SAMPLE_PDF, LICENSE_ID, FAKE_ADDRESS_A);
    // Candid lista: B (errado primeiro), A (correto)
    const { pdf, decryptedWith } = decryptDLMv3WithChain(dlm, [FAKE_ADDRESS_B, FAKE_ADDRESS_A]);
    expect(pdf.equals(SAMPLE_PDF)).toBe(true);
    expect(decryptedWith.toLowerCase()).toBe(FAKE_ADDRESS_A.toLowerCase());
  });

  test("lança erro quando nenhum candidato tem a chave correta", () => {
    const dlm = encryptToDLMv3(SAMPLE_PDF, LICENSE_ID, FAKE_ADDRESS_A);
    expect(() => decryptDLMv3WithChain(dlm, [FAKE_ADDRESS_B])).toThrow();
  });

  test("re-encriptação muda o proprietário no cabeçalho mas mantém o PDF", () => {
    // Simula transferência: cifra com A, decifra com cadeia, re-cifra para B
    const original = encryptToDLMv3(SAMPLE_PDF, LICENSE_ID, FAKE_ADDRESS_A);
    const { pdf }  = decryptDLMv3WithChain(original, [FAKE_ADDRESS_A]);
    const reCifrado = encryptToDLMv3(pdf, LICENSE_ID, FAKE_ADDRESS_B);

    const header = parseDLMHeader(reCifrado);
    expect(header.ownerAddress.toLowerCase()).toBe(FAKE_ADDRESS_B.toLowerCase());

    // B consegue decifrar o arquivo re-encriptado
    const result = tryDecryptV3WithAddress(reCifrado, FAKE_ADDRESS_B);
    expect(result).not.toBeNull();
    expect(result.pdf.equals(SAMPLE_PDF)).toBe(true);

    // A NÃO consegue decifrar o arquivo re-encriptado
    const resultA = tryDecryptV3WithAddress(reCifrado, FAKE_ADDRESS_A);
    expect(resultA).toBeNull();
  });
});
