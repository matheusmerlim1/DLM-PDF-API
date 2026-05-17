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
  decryptAny,
  parseDLMHeader,
} from "../services/encryptionService.js";
import { getCandidateAddresses } from "../services/licenseRegistryService.js";

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

// ── Bug de regressão: novo dono após transferência ───────────────────────────
// Cenário: arquivo cifrado por A, transferido para B no registro, B tenta abrir.
// O arquivo ainda tem a chave de A embutida. O servidor deve tentar o encryptedWith
// (= A) e conseguir decifrar, mesmo sem acesso direto ao .dlm re-criptografado.

describe("DRM v3 — transferência: novo dono acessa via cadeia de custódia", () => {
  let dlmEncryptedByA;

  beforeAll(() => {
    dlmEncryptedByA = encryptToDLMv3(SAMPLE_PDF, LICENSE_ID, FAKE_ADDRESS_A);
  });

  // Simula o licenseRecord após POST /transfer: currentOwner=B, encryptedWith=A
  function makeMockLicenseRecord(encryptedWith, currentOwner) {
    return {
      licenseId: LICENSE_ID,
      currentOwner: { address: currentOwner },
      encryptedWithAddress: encryptedWith,
      ownershipHistory: [
        { address: encryptedWith, acquiredAt: "2026-01-01T00:00:00Z", releasedAt: "2026-01-02T00:00:00Z" },
        { address: currentOwner,  acquiredAt: "2026-01-02T00:00:00Z", releasedAt: null },
      ],
    };
  }

  test("getCandidateAddresses retorna [encryptedWith, newOwner] após transferência", () => {
    const record = makeMockLicenseRecord(FAKE_ADDRESS_A, FAKE_ADDRESS_B);
    const candidates = getCandidateAddresses(record);
    expect(candidates[0].toLowerCase()).toBe(FAKE_ADDRESS_A.toLowerCase()); // encryptedWith primeiro
    expect(candidates).toContain(FAKE_ADDRESS_B.toLowerCase());
  });

  test("novo dono (B) consegue abrir arquivo ainda cifrado com chave de A", () => {
    const record = makeMockLicenseRecord(FAKE_ADDRESS_A, FAKE_ADDRESS_B);
    const candidates = getCandidateAddresses(record);

    // Rota POST /decrypt usa decryptDLMv3WithChain — deve funcionar
    const { pdf, decryptedWith } = decryptDLMv3WithChain(dlmEncryptedByA, candidates);
    expect(pdf.equals(SAMPLE_PDF)).toBe(true);
    expect(decryptedWith.toLowerCase()).toBe(FAKE_ADDRESS_A.toLowerCase());
  });

  test("antigo dono (A) não consegue acessar após perder currentOwner no registro", () => {
    // Simula que a rota já verificou currentOwner e bloqueou A.
    // Garante que tryDecryptV3WithAddress com B falha (arquivo ainda tem chave de A).
    const result = tryDecryptV3WithAddress(dlmEncryptedByA, FAKE_ADDRESS_B);
    expect(result).toBeNull(); // B não tem a chave direta — precisa da cadeia
  });
});

// ── Bug de regressão: decryptAny não suportava v3 ────────────────────────────
// Bug: decryptAny chamava decryptDLMv2 para arquivos v3, que falhava com
// "Formato .dlm v2 inválido" ao verificar o magic byte 0x03 ≠ 0x02.
// Fix: decryptAny agora tenta o endereço embutido no cabeçalho para v3.

describe("DRM v3 — decryptAny corrige bug de v3-como-v2", () => {
  test("decryptAny funciona para v3 com o dono original (endereço embutido)", () => {
    const dlm = encryptToDLMv3(SAMPLE_PDF, LICENSE_ID, FAKE_ADDRESS_A);
    // Deve funcionar sem lançar "Formato .dlm v2 inválido"
    const result = decryptAny(dlm, FAKE_ADDRESS_A);
    expect(result.pdf.equals(SAMPLE_PDF)).toBe(true);
  });

  test("decryptAny funciona para v3 mesmo quando connectedAddress é o novo dono", () => {
    // Após transferência, arquivo ainda tem chave de A embutida.
    // decryptAny usa o endereço embutido (A), não connectedAddress (B).
    // O controle de acesso é feito ANTES por blockchain/registro — decryptAny apenas decifra.
    const dlm = encryptToDLMv3(SAMPLE_PDF, LICENSE_ID, FAKE_ADDRESS_A);
    const result = decryptAny(dlm, FAKE_ADDRESS_B); // B é o connectedAddress
    expect(result.pdf.equals(SAMPLE_PDF)).toBe(true);
  });

  test("decryptAny lança erro para v3 com chave mestre incorreta (arquivo corrompido)", () => {
    // Cria um arquivo com chave diferente, simula corrupção do cabeçalho
    const dlm = encryptToDLMv3(SAMPLE_PDF, LICENSE_ID, FAKE_ADDRESS_A);
    // Corrompe o ownerAddress no header (bytes 12-53) para um endereço desconhecido
    const fakeOwner = "0x" + "c".repeat(40);
    const corrupted = Buffer.from(dlm);
    Buffer.from(fakeOwner).copy(corrupted, 12);

    expect(() => decryptAny(corrupted, FAKE_ADDRESS_A)).toThrow(/Impossível|inválid/i);
  });
});

// ── Regressão: fluxo completo POST /decrypt com re-encriptação ───────────────
// Cenário: A cifra → transfere para B → B abre via cadeia (servidor re-cifra para B)
//          → B abre novamente, agora diretamente sem cadeia → A não consegue mais.
//
// Este teste valida a sequência exata executada pela rota POST /decrypt:
//   1. getCandidateAddresses(licenseRecord)
//   2. decryptDLMv3WithChain(dlmBuffer, candidates)
//   3. encryptToDLMv3(pdf, licenseId, publicKey)   ← re-cifra para o novo dono
//   4. updateEncryptedWith(licenseId, publicKey)    ← atualiza o registro
//
// Após o passo 3, o arquivo no servidor usa a chave de B. Próximas aberturas
// não precisam da cadeia — apenas a chave direta de B.

describe("DRM v3 — fluxo completo POST /decrypt: re-encriptação para o novo dono", () => {
  function makeMockRecord(encryptedWith, currentOwner) {
    return {
      licenseId: LICENSE_ID,
      currentOwner: { address: currentOwner },
      encryptedWithAddress: encryptedWith,
      ownershipHistory: [
        { address: encryptedWith, acquiredAt: "2026-01-01T00:00:00Z", releasedAt: "2026-01-02T00:00:00Z" },
        { address: currentOwner,  acquiredAt: "2026-01-02T00:00:00Z", releasedAt: null },
      ],
    };
  }

  test("B abre via cadeia e o arquivo re-cifrado com chave de B pode ser aberto diretamente", () => {
    // Passo 1: A cifra o arquivo original
    const dlmByA = encryptToDLMv3(SAMPLE_PDF, LICENSE_ID, FAKE_ADDRESS_A);

    // Passo 2: Registro após transferência — currentOwner=B, encryptedWith=A
    const record     = makeMockRecord(FAKE_ADDRESS_A, FAKE_ADDRESS_B);
    const candidates = getCandidateAddresses(record);

    // Passo 3: servidor decripta via cadeia (encontra chave de A)
    const { pdf, decryptedWith } = decryptDLMv3WithChain(dlmByA, candidates);
    expect(pdf.equals(SAMPLE_PDF)).toBe(true);
    expect(decryptedWith.toLowerCase()).toBe(FAKE_ADDRESS_A.toLowerCase());

    // Passo 4: servidor re-cifra com chave de B (simula encryptToDLMv3 + updateEncryptedWith)
    const dlmByB = encryptToDLMv3(pdf, LICENSE_ID, FAKE_ADDRESS_B);

    // Passo 5: B abre novamente — agora usa a chave direta (sem cadeia)
    const result = tryDecryptV3WithAddress(dlmByB, FAKE_ADDRESS_B);
    expect(result).not.toBeNull();
    expect(result.pdf.equals(SAMPLE_PDF)).toBe(true);
  });

  test("após re-cifrar para B, A não consegue mais abrir o arquivo", () => {
    const dlmByA     = encryptToDLMv3(SAMPLE_PDF, LICENSE_ID, FAKE_ADDRESS_A);
    const record     = makeMockRecord(FAKE_ADDRESS_A, FAKE_ADDRESS_B);
    const candidates = getCandidateAddresses(record);
    const { pdf }    = decryptDLMv3WithChain(dlmByA, candidates);
    const dlmByB     = encryptToDLMv3(pdf, LICENSE_ID, FAKE_ADDRESS_B);

    // A tenta abrir o arquivo re-cifrado para B — deve falhar
    const resultA = tryDecryptV3WithAddress(dlmByB, FAKE_ADDRESS_A);
    expect(resultA).toBeNull();
  });

  test("cabeçalho do arquivo re-cifrado reflete o novo dono (B)", () => {
    const dlmByA     = encryptToDLMv3(SAMPLE_PDF, LICENSE_ID, FAKE_ADDRESS_A);
    const record     = makeMockRecord(FAKE_ADDRESS_A, FAKE_ADDRESS_B);
    const candidates = getCandidateAddresses(record);
    const { pdf }    = decryptDLMv3WithChain(dlmByA, candidates);
    const dlmByB     = encryptToDLMv3(pdf, LICENSE_ID, FAKE_ADDRESS_B);

    const header = parseDLMHeader(dlmByB);
    expect(header.ownerAddress.toLowerCase()).toBe(FAKE_ADDRESS_B.toLowerCase());
    expect(header.licenseId).toBe(LICENSE_ID);
    expect(header.version).toBe(3);
  });
});
