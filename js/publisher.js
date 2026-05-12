/**
 * js/publisher.js
 * Responsabilidade: lógica da aba "Editora — Criptografar PDF".
 *
 * Fluxo:
 *  1. Usuário seleciona ou arrasta um arquivo PDF
 *  2. Preenche License ID, título e opcionalmente o endereço do proprietário
 *  3. Clica em "Gerar arquivo .dlm"
 *  4. O sistema executa o processo de cifragem com feedback visual passo a passo
 *  5. O arquivo .dlm é oferecido para download
 *  6. O painel direito exibe detalhes técnicos e hex dump do arquivo gerado
 *
 * Depende de: DLMCrypto (crypto.js), UI (ui.js)
 */

'use strict';

// ── Estado do módulo ──────────────────────────────────────
let pubPdfBuffer   = null;   // ArrayBuffer do PDF carregado
let pubDLMBuffer   = null;   // ArrayBuffer do .dlm gerado
let pubContentHash = '';     // SHA-256 do PDF original (hex)

// ── Inicialização ─────────────────────────────────────────

/**
 * Inicializa todos os event listeners do painel da editora.
 * Chamado pelo main.js após o DOM estar pronto.
 */
function initPublisher() {
  // Drag-and-drop do PDF
  UI.setupDrop('pub-drop', 'pub-file', '.pdf', handlePDFLoad);

  // Botão de criptografar
  document.getElementById('btn-encrypt')
    .addEventListener('click', handleEncrypt);

  // Botão de download do .dlm
  document.getElementById('btn-download')
    .addEventListener('click', handleDownload);

  // Botão de copiar hash
  document.getElementById('btn-copy-hash')
    .addEventListener('click', () => {
      UI.copyToClipboard(pubContentHash, 'Hash SHA-256 copiado!');
    });
}

// ── Handlers ──────────────────────────────────────────────

/**
 * Processado quando o usuário seleciona um PDF.
 * @param {File} file
 */
async function handlePDFLoad(file) {
  pubPdfBuffer = await file.arrayBuffer();

  // Atualiza chip de arquivo
  document.getElementById('pub-fname').textContent = file.name;
  document.getElementById('pub-chip').style.display = 'flex';

  // Habilita botão de criptografar
  document.getElementById('btn-encrypt').disabled = false;

  // Marca step 1 como concluído
  UI.setStep('pstep-1', 'done');

  // Pré-calcula o hash SHA-256 do PDF para exibição posterior
  pubContentHash = await DLMCrypto.sha256(pubPdfBuffer);

  UI.toast(`PDF carregado: ${file.name}`, 'ok');
}

/**
 * Executa o processo completo de cifragem com feedback visual.
 */
async function handleEncrypt() {
  if (!pubPdfBuffer) return;

  const licenseId = parseInt(document.getElementById('pub-licid').value) || 1;
  const btn       = document.getElementById('btn-encrypt');

  btn.disabled  = true;
  btn.innerHTML = '<span class="spin"></span> Cifrando...';

  // Reseta estado anterior
  UI.resetProgress('pub-prog');
  document.getElementById('pub-result').style.display = 'none';

  try {
    // — Step 2: Derivar chave HKDF ——————————————————————
    UI.setStep('pstep-2', 'active');
    UI.setProgress('pub-prog', 20);
    await UI.delay(400);

    const result = await DLMCrypto.encryptPDF(pubPdfBuffer, licenseId);
    UI.setStep('pstep-2', 'done');

    // — Step 3: Cifragem AES-256-CBC ————————————————————
    UI.setStep('pstep-3', 'active');
    UI.setProgress('pub-prog', 55);
    await UI.delay(300);
    UI.setStep('pstep-3', 'done');

    // — Step 4: Montar cabeçalho .dlm ———————————————————
    UI.setStep('pstep-4', 'active');
    UI.setProgress('pub-prog', 80);
    await UI.delay(250);
    UI.setStep('pstep-4', 'done');

    // — Step 5: Arquivo pronto ——————————————————————————
    UI.setStep('pstep-5', 'active');
    UI.setProgress('pub-prog', 100);
    await UI.delay(200);
    UI.setStep('pstep-5', 'done');

    pubDLMBuffer = result.dlm;

    // Exibe resultado e painel técnico
    await showEncryptResult(result, licenseId);
    UI.toast('Arquivo .dlm gerado com sucesso!', 'ok');

  } catch (err) {
    UI.toast('Erro na cifragem: ' + err.message, 'err');
    ['pstep-2','pstep-3','pstep-4','pstep-5'].forEach(s => UI.setStep(s, 'fail'));
  }

  btn.innerHTML = '🔒 Gerar arquivo .dlm';
  btn.disabled  = false;
}

/**
 * Exibe os resultados técnicos após a cifragem bem-sucedida.
 * @param {object} result - Retorno de DLMCrypto.encryptPDF
 * @param {number} licenseId
 */
async function showEncryptResult(result, licenseId) {
  const { dlm, iv, hmacBytes, aesKey } = result;

  const keyHex  = await DLMCrypto.exportKeyHex(aesKey);
  const dlmHash = await DLMCrypto.sha256(dlm);
  const title   = document.getElementById('pub-title').value || '(sem título)';

  // ── Painel de hash ──
  document.getElementById('pub-result').style.display = 'block';
  document.getElementById('pub-hash-display').innerHTML =
    `<span style="color:var(--muted)">SHA-256 do .dlm gerado:</span><br>${dlmHash}<br><br>` +
    `<span style="color:var(--muted)">SHA-256 do PDF original:</span><br>${pubContentHash}`;

  // ── Painel técnico (direita) ──
  document.getElementById('pub-empty').style.display   = 'none';
  document.getElementById('pub-preview').style.display = 'flex';

  document.getElementById('pub-tech-view').innerHTML = `
    <div style="margin-bottom:.6rem;color:var(--text)">
      📦 <strong>${title}</strong> — License #${licenseId}
    </div>
    <div style="color:var(--muted)">
      Tamanho PDF original:
      <span style="color:var(--cyan)">${(pubPdfBuffer.byteLength / 1024).toFixed(1)} KB</span>
    </div>
    <div style="color:var(--muted)">
      Tamanho .dlm gerado:
      <span style="color:var(--cyan)">${(dlm.byteLength / 1024).toFixed(1)} KB</span>
    </div>
    <div style="color:var(--muted);margin-top:.4rem">
      IV AES-CBC:
      <span style="color:var(--accent)">${DLMCrypto.bytesToHex(iv.buffer)}</span>
    </div>
    <div style="color:var(--muted)">
      HMAC-SHA256:
      <span style="color:var(--green)">${DLMCrypto.bytesToHex(hmacBytes.buffer)}</span>
    </div>
    <div style="color:var(--muted);margin-top:.4rem">
      🔑 Chave derivada HKDF <em>(demo only — nunca exposta em produção)</em>:
      <span style="color:var(--gold);font-size:.6rem">${keyHex}</span>
    </div>
  `;

  // ── Hex dump dos primeiros 128 bytes ──
  const hexStr = DLMCrypto.bytesToHex(dlm, 128);
  document.getElementById('pub-hex').textContent =
    hexStr.match(/.{1,47}/g).join('\n');
}

/**
 * Inicia o download do arquivo .dlm gerado.
 */
function handleDownload() {
  if (!pubDLMBuffer) return;

  const title = (document.getElementById('pub-title').value || 'ebook')
    .replace(/\s+/g, '-');
  const licId = document.getElementById('pub-licid').value || '1';
  const fname = `${title}-license${licId}.dlm`;

  const blob = new Blob([pubDLMBuffer], { type: 'application/octet-stream' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = fname;
  a.click();
  URL.revokeObjectURL(url);

  UI.toast(`Download iniciado: ${fname}`, 'ok');
}

// Exporta para main.js
window.Publisher = { initPublisher };
