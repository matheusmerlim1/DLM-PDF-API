/**
 * emailService.js
 * Envia e-mail com as respostas do formulário de avaliação.
 *
 * Requer no .env:
 *   EMAIL_USER=seu-email@gmail.com
 *   EMAIL_PASS=xxxx xxxx xxxx xxxx   ← senha de app do Gmail (não a senha normal)
 *   EMAIL_TO=matheusmerlim@gmail.com  ← destinatário (opcional, tem default)
 *
 * Para gerar a senha de app: myaccount.google.com → Segurança → Senhas de app
 */

import nodemailer from "nodemailer";

const DEST = process.env.EMAIL_TO || "matheusmerlim@gmail.com";

function criarTransporte() {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) return null;
  return nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });
}

export async function enviarAvaliacao(record) {
  const transport = criarTransporte();
  if (!transport) {
    console.warn("⚠️  EMAIL_USER/EMAIL_PASS não configurados — e-mail não enviado.");
    return;
  }

  const campos = Object.entries(record)
    .filter(([k]) => !k.startsWith("_") && k !== "id" && k !== "createdAt")
    .map(([k, v]) => {
      const valor = Array.isArray(v) ? v.join(", ") : v;
      return `<tr>
        <td style="padding:6px 12px;border-bottom:1px solid #e2e8f0;color:#64748b;white-space:nowrap">${k}</td>
        <td style="padding:6px 12px;border-bottom:1px solid #e2e8f0">${valor ?? "—"}</td>
      </tr>`;
    })
    .join("");

  const html = `
    <div style="font-family:system-ui,sans-serif;max-width:680px;margin:0 auto">
      <div style="background:#0f172a;color:#22d3ee;padding:16px 24px;border-radius:8px 8px 0 0">
        <strong>DLM-PDF — Nova avaliação recebida</strong>
      </div>
      <div style="background:#f8fafc;padding:16px 24px;border-radius:0 0 8px 8px;border:1px solid #e2e8f0">
        <p style="margin:0 0 12px;color:#475569;font-size:.9rem">
          Enviado em: <strong>${record._timestamp || new Date().toLocaleString("pt-BR")}</strong>
          &nbsp;·&nbsp; ID: <code style="font-size:.78rem">${record.id}</code>
        </p>
        <table style="width:100%;border-collapse:collapse;font-size:.88rem">
          <tbody>${campos}</tbody>
        </table>
        <details style="margin-top:16px">
          <summary style="cursor:pointer;color:#94a3b8;font-size:.78rem">JSON bruto</summary>
          <pre style="background:#1e293b;color:#e2e8f0;padding:12px;border-radius:6px;font-size:.75rem;overflow-x:auto;margin-top:8px">${JSON.stringify(record, null, 2)}</pre>
        </details>
      </div>
    </div>`;

  await transport.sendMail({
    from:    `"DLM-PDF Pesquisa" <${process.env.EMAIL_USER}>`,
    to:      DEST,
    subject: `[DLM-PDF] Nova avaliação — ${record._timestamp || record.createdAt?.slice(0, 10)}`,
    html,
  });
}
