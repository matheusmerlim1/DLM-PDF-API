/**
 * users.cpf.mask.test.js
 *
 * Regressão de segurança (LGPD): o CPF era retornado completo em respostas da
 * API, inclusive em endpoints públicos sem autenticação (GET /users/:address) e
 * em consultas de dado de terceiros (POST /transfer/preview, POST /transfer).
 *
 * Correção: maskCPF() revela apenas os 2 dígitos finais; as rotas passam todo
 * CPF por ela antes de devolver. O armazenamento (registerUser) continua
 * guardando o CPF completo — só o que sai na resposta é mascarado.
 *
 * Estes testes cobrem a função de mascaramento isoladamente.
 */

import { maskCPF } from "../services/userRegistryService.js";

describe("Segurança/LGPD — maskCPF não vaza o CPF completo", () => {

  test("mascara um CPF de 11 dígitos preservando só os 2 finais", () => {
    expect(maskCPF("12345678901")).toBe("***.***.***-01");
  });

  test("aceita CPF já formatado (pontos e traço) e mascara igual", () => {
    expect(maskCPF("123.456.789-01")).toBe("***.***.***-01");
  });

  test("o resultado não contém nenhum dos 9 primeiros dígitos do CPF", () => {
    const masked = maskCPF("98765432100");
    // Nenhum dígito além dos 2 finais ("00") pode aparecer no retorno
    expect(masked).toBe("***.***.***-00");
    expect(masked).not.toMatch(/9|8|7|6|5|4|3|2|1/);
  });

  test("retorna null quando o CPF é null ou undefined", () => {
    expect(maskCPF(null)).toBeNull();
    expect(maskCPF(undefined)).toBeNull();
  });

  test("entrada com quantidade de dígitos inesperada é totalmente mascarada", () => {
    expect(maskCPF("123")).toBe("***.***.***-**");
    expect(maskCPF("")).toBe("***.***.***-**");
  });

  test("nunca devolve a string original (garante que mascarou)", () => {
    const original = "11122233344";
    expect(maskCPF(original)).not.toBe(original);
    expect(maskCPF(original)).not.toContain("111");
  });
});
