/**
 * js/reader.js
 * Responsabilidade: lógica da aba "Leitor — Abrir .dlm".
 *
 * Fluxo:
 *  1. Usuário conecta carteira Ethereum (MetaMask ou modo demo)
 *  2. Seleciona ou arrasta um arquivo .dlm
 *  3. O sistema extrai o licenseId do cabeçalho sem decriptografar
 *  4. Ao clicar em "Abrir e-book":
 *     a. Simula assinatura criptográfica com a carteira
 *     b. Simula validação de posse na Blockchain
 *     c. Deriva a chave de sessão via HKDF
 *     d. Verifica HMAC e decifra o arquivo em memória
 *     e. Renderiza o PDF via PDF.js (nunca grava em disco)
 *
 * Depende de: DLMCrypto (crypto.js), UI (ui.js), PDF.js (CDN)
 */

'use strict';

// ── Estado do módulo ──────────────────────────────────────
let walletAddr    = null;   // Endereço da carteira conectada
let readDLMBuffer = null;   // ArrayBuffer do arquivo .dlm carregado

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
    UI.toast('MetaMask não encontrado. Use o modo demo.', 'err');
    return;
  }
  try {
    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
    walletAddr = accounts[0].toLowerCase();
    showWallet();
    UI.toast('Carteira MetaMask conectada!', 'ok');
  } catch {
    UI.toast('Conexão com MetaMask recusada.', 'err');
  }
}

/**
 * Simula uma carteira para demonstração (sem MetaMask).
 */
function connectDemo() {
  const bytes = DLMCrypto.randomBytes(20);
  walletAddr  = '0x' + Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  showWallet();
  UI.toast('Modo demo: carteira simulada com sucesso.', 'info');
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

  // Tenta extrair licenseId do cabeçalho
  try {
    const lid = DLMCrypto.readLicenseId(readDLMBuffer);
    document.getElementById('read-licid').value = lid;

    UI.setStep('rstep-1', 'done');
    UI.setStep('rstep-2', 'done');
    UI.toast(`Arquivo .dlm carregado — License ID: ${lid}`, 'ok');
  } catch (err) {
    UI.toast('Arquivo inválido: ' + err.message, 'err');
    readDLMBuffer = null;
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

// ── Processo de Abertura ──────────────────────────────────

/**
 * Executa o fluxo completo de validação e renderização.
 */
async function handleOpen() {
  const btn = document.getElementById('btn-open');
  btn.disabled  = true;
  btn.innerHTML = '<span class="spin"></span> Validando...';

  UI.resetProgress('read-prog');

  try {
    // — Step 3: Assinatura da carteira (simulada em demo) ——
    UI.setStep('rstep-3', 'active');
    UI.setProgress('read-prog', 20);
    await UI.delay(500);
    UI.setStep('rstep-3', 'done');

    // — Step 4: Validação on-chain (simulada em demo) ———————
    UI.setStep('rstep-4', 'active');
    UI.setProgress('read-prog', 45);
    await UI.delay(700);

    // Gera um TX hash fictício para demonstração
    const fakeTxBytes = DLMCrypto.randomBytes(32);
    const fakeTx = '0x' + Array.from(fakeTxBytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    UI.setStep('rstep-4', 'done');

    // — Step 5: Derivar chave + verificar HMAC ——————————————
    UI.setStep('rstep-5', 'active');
    UI.setProgress('read-prog', 68);
    await UI.delay(300);

    // Decifra e verifica HMAC (operação real)
    const { pdf, licenseId, hmacOk } = await DLMCrypto.decryptDLM(readDLMBuffer);
    UI.setStep('rstep-5', 'done');

    // — Step 6: Renderizar PDF ——————————————————————————————
    UI.setStep('rstep-6', 'active');
    UI.setProgress('read-prog', 85);

    await renderPDF(pdf);

    UI.setStep('rstep-6', 'done');
    UI.setProgress('read-prog', 100);

    // Exibe painel de informações da licença
    showLicenseInfo(licenseId, hmacOk, fakeTx);
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
 */
function showLicenseInfo(licenseId, hmacOk, txHash) {
  const card = document.getElementById('read-info');
  card.style.display = 'block';

  document.getElementById('ri-id').textContent    = licenseId;
  document.getElementById('ri-owner').textContent =
    walletAddr.slice(0, 10) + '...' + walletAddr.slice(-6);
  document.getElementById('ri-access').textContent = '✅ CONCEDIDO';
  document.getElementById('ri-tx').textContent     =
    txHash.slice(0, 20) + '...';
  document.getElementById('ri-hmac').textContent   =
    hmacOk ? '✅ VÁLIDO' : '❌ INVÁLIDO';
}

// Exporta para main.js
window.Reader = { initReader };
