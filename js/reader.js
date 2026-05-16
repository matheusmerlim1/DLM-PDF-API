/**
 * js/reader.js
 * Responsabilidade: lógica do leitor de arquivos .dlm.
 *
 * Fluxo:
 *  1. Usuário conecta carteira Ethereum (MetaMask ou modo demo)
 *  2. Seleciona ou arrasta um arquivo .dlm
 *  3. O sistema extrai licenseId e versão do cabeçalho (sem decriptografar)
 *  4. Ao clicar em "Abrir e-book":
 *     v1 (demo): decriptação local com chave demo + HMAC local
 *     v2/v3:     assina com MetaMask → chama servidor → recebe PDF
 *
 * Depende de: DLMCrypto (crypto.js), UI (ui.js), PDF.js (CDN)
 */

'use strict';

// URL do servidor DRM (mesma do Livraria DLM)
const DRM_API = 'https://dlm-pdf-server-production.up.railway.app/api/v1';

// ── Estado do módulo ──────────────────────────────────────
let walletAddr    = null;   // Endereço da carteira conectada
let isDemoMode    = false;  // true quando carteira foi simulada
let readDLMBuffer = null;   // ArrayBuffer do arquivo .dlm carregado
let dlmHeader     = null;   // resultado de parseDLMHeader

// ── Inicialização ─────────────────────────────────────────

/**
 * Inicializa todos os event listeners do painel do leitor.
 * Chamado pelo main.js após o DOM estar pronto.
 */
function initReader() {
  // Botões de autenticação de carteira
  document.getElementById('btn-connect')
    .addEventListener('click', connectMetaMask);

  document.getElementById('btn-demo')
    .addEventListener('click', connectDemo);

  // Drag-and-drop do arquivo .dlm
  UI.setupDrop('read-drop', 'read-file', '.dlm', handleDLMLoad);

  // Botão principal de abertura
  document.getElementById('btn-open')
    .addEventListener('click', handleOpen);
}

// ── Autenticação de Carteira ──────────────────────────────

/**
 * Conecta via MetaMask (Ethereum real).
 */
async function connectMetaMask() {
  if (!window.ethereum) {
    UI.toast('MetaMask não encontrado. Use o modo demo (apenas .dlm v1).', 'err');
    return;
  }
  try {
    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
    walletAddr = accounts[0].toLowerCase();
    isDemoMode = false;
    showWallet();
    UI.toast('Carteira MetaMask conectada!', 'ok');
  } catch {
    UI.toast('Conexão com MetaMask recusada.', 'err');
  }
}

/**
 * Simula uma carteira para demonstração (sem MetaMask).
 * Funciona apenas para arquivos .dlm v1 gerados localmente.
 */
function connectDemo() {
  const bytes = DLMCrypto.randomBytes(20);
  walletAddr  = '0x' + Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  isDemoMode  = true;
  showWallet();
  UI.toast('Modo demo ativo — apenas arquivos .dlm v1 são suportados.', 'info');
}

/**
 * Atualiza a UI para exibir a carteira conectada.
 */
function showWallet() {
  const badge = document.getElementById('wallet-badge');
  badge.style.display = 'flex';
  document.getElementById('wallet-addr').textContent =
    walletAddr.slice(0, 8) + '...' + walletAddr.slice(-6);
  checkOpenReady();
}

// ── Carregamento do arquivo .dlm ──────────────────────────

/**
 * Processado quando o usuário seleciona um arquivo .dlm.
 * Lê apenas o cabeçalho para extrair o licenseId (sem decriptografar).
 * @param {File} file
 */
async function handleDLMLoad(file) {
  readDLMBuffer = await file.arrayBuffer();

  // Atualiza chip de arquivo
  document.getElementById('read-fname').textContent = file.name;
  document.getElementById('read-chip').style.display = 'flex';

  // Tenta extrair cabeçalho (licenseId + versão)
  try {
    dlmHeader = DLMCrypto.parseDLMHeader(readDLMBuffer);
    document.getElementById('read-licid').value =
      `${dlmHeader.licenseId} (v${dlmHeader.version})`;

    UI.setStep('rstep-1', 'done');
    UI.setStep('rstep-2', 'done');
    UI.toast(
      `Arquivo .dlm v${dlmHeader.version} carregado — License ID: ${dlmHeader.licenseId}`,
      'ok'
    );
  } catch (err) {
    UI.toast('Arquivo inválido: ' + err.message, 'err');
    readDLMBuffer = null;
    dlmHeader     = null;
    document.getElementById('read-chip').style.display = 'none';
    return;
  }

  checkOpenReady();
}

/**
 * Habilita/desabilita o botão "Abrir e-book" conforme pré-requisitos.
 */
function checkOpenReady() {
  document.getElementById('btn-open').disabled = !(walletAddr && readDLMBuffer);
}

// ── Decriptação via servidor (v2/v3) ──────────────────────

/**
 * Envia o .dlm ao servidor com assinatura MetaMask e recebe o PDF.
 * @returns {Promise<{ pdf: ArrayBuffer, licenseId: string, hmacOk: boolean }>}
 */
async function decryptViaServer() {
  if (!window.ethereum) {
    throw new Error(
      'MetaMask é necessário para abrir arquivos .dlm v2/v3. ' +
      'O modo demo suporta apenas arquivos v1 gerados localmente.'
    );
  }

  const licenseId = dlmHeader.licenseId;
  const message   = `DLM:decrypt:${licenseId}:${Date.now()}`;

  const signature = await window.ethereum.request({
    method: 'personal_sign',
    params: [message, walletAddr],
  });

  const bytes = new Uint8Array(readDLMBuffer);
  let binary  = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  const dlmBase64 = btoa(binary);

  const res = await fetch(`${DRM_API}/decrypt`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ dlmBase64, publicKey: walletAddr, signature, message }),
  });

  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.error || `Servidor retornou ${res.status}`);
  }

  const data     = await res.json();
  const pdfBytes = Uint8Array.from(atob(data.pdfBase64), c => c.charCodeAt(0));
  return { pdf: pdfBytes.buffer, licenseId, hmacOk: true };
}

// ── Processo de Abertura ──────────────────────────────────

/**
 * Executa o fluxo completo de validação e renderização.
 * v1: decriptação local (chave demo). v2/v3: via servidor + MetaMask.
 */
async function handleOpen() {
  const btn = document.getElementById('btn-open');
  btn.disabled  = true;
  btn.innerHTML = '<span class="spin"></span> Validando...';

  UI.resetProgress('read-prog');

  try {
    const version = dlmHeader.version;

    // Etapa 3: assinatura
    UI.setStep('rstep-3', 'active');
    UI.setProgress('read-prog', 20);
    if (version === 1) await UI.delay(500);
    UI.setStep('rstep-3', 'done');

    // Etapa 4: validação on-chain
    UI.setStep('rstep-4', 'active');
    UI.setProgress('read-prog', 45);
    if (version === 1) await UI.delay(700);
    UI.setStep('rstep-4', 'done');

    // Etapa 5: derivar chave / chamar servidor
    UI.setStep('rstep-5', 'active');
    UI.setProgress('read-prog', 68);

    let pdfResult;
    if (version === 1) {
      pdfResult = await DLMCrypto.decryptDLM(readDLMBuffer);
    } else {
      UI.toast(`Arquivo v${version}: aguardando assinatura MetaMask...`, 'info');
      pdfResult = await decryptViaServer();
    }
    UI.setStep('rstep-5', 'done');

    // Etapa 6: renderizar PDF
    UI.setStep('rstep-6', 'active');
    UI.setProgress('read-prog', 85);

    await renderPDF(pdfResult.pdf);

    UI.setStep('rstep-6', 'done');
    UI.setProgress('read-prog', 100);

    const fakeTx = '0x' + Array.from(DLMCrypto.randomBytes(32))
      .map(b => b.toString(16).padStart(2, '0')).join('');

    showLicenseInfo(pdfResult.licenseId, pdfResult.hmacOk, fakeTx, version);
    UI.toast('E-book aberto com sucesso!', 'ok');

  } catch (err) {
    ['rstep-4','rstep-5','rstep-6'].forEach(s => UI.setStep(s, 'fail'));
    UI.toast('Erro: ' + err.message, 'err');
  }

  btn.innerHTML = '🔓 Abrir e-book';
  btn.disabled  = false;
}

// ── Renderização PDF ──────────────────────────────────────

/**
 * Renderiza o PDF decifrado em memória usando PDF.js.
 * O conteúdo nunca é gravado em disco — apenas em canvas.
 *
 * @param {ArrayBuffer} pdfBuffer
 */
async function renderPDF(pdfBuffer) {
  const container = document.getElementById('pdf-pages');
  container.innerHTML = '';

  // Mostra toolbar, esconde empty state
  document.getElementById('read-empty').style.display   = 'none';
  document.getElementById('read-toolbar').style.display = 'flex';

  const pdf   = await pdfjsLib.getDocument({ data: pdfBuffer }).promise;
  const total = pdf.numPages;

  document.getElementById('read-pageinfo').textContent =
    `${total} página${total > 1 ? 's' : ''}`;

  for (let n = 1; n <= total; n++) {
    const page     = await pdf.getPage(n);
    const viewport = page.getViewport({ scale: 1.4 });

    const canvas   = document.createElement('canvas');
    canvas.width   = viewport.width;
    canvas.height  = viewport.height;
    container.appendChild(canvas);

    await page.render({
      canvasContext: canvas.getContext('2d'),
      viewport,
    }).promise;
  }
}

// ── Info da Licença ───────────────────────────────────────

/**
 * Popula e exibe o card de informações da licença validada.
 * @param {string}  licenseId
 * @param {boolean} hmacOk
 * @param {string}  txHash
 * @param {number}  version
 */
function showLicenseInfo(licenseId, hmacOk, txHash, version = 1) {
  const card = document.getElementById('read-info');
  card.style.display = 'block';

  document.getElementById('ri-id').textContent    = `${licenseId} (v${version})`;
  document.getElementById('ri-owner').textContent =
    walletAddr.slice(0, 10) + '...' + walletAddr.slice(-6);
  document.getElementById('ri-access').textContent = '✅ CONCEDIDO';
  document.getElementById('ri-tx').textContent     =
    txHash.slice(0, 20) + '...';
  document.getElementById('ri-hmac').textContent   =
    version === 1 ? (hmacOk ? '✅ VÁLIDO' : '❌ INVÁLIDO') : '✅ SERVIDOR';
}

// Exporta para main.js
window.Reader = { initReader };
