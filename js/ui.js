/**
 * js/ui.js
 * Responsabilidade: utilitários de interface reutilizáveis.
 *
 * Inclui:
 *  - Sistema de toasts (notificações)
 *  - Controle de steps (etapas visuais)
 *  - Barra de progresso
 *  - Configuração de drag-and-drop zones
 *  - Controle de abas (tabs)
 *  - Utilitário de delay (para animações visuais)
 */

'use strict';

// ══════════════════════════════════════════════════════════
//  TOAST — notificações temporárias
// ══════════════════════════════════════════════════════════

/**
 * Exibe uma notificação temporária no canto inferior direito.
 * @param {string} msg   - Texto da notificação
 * @param {'ok'|'err'|'info'} type - Tipo visual
 * @param {number} [dur=4000]     - Duração em ms
 */
function toast(msg, type = 'info', dur = 4000) {
  const container = document.getElementById('toasts');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => el.remove(), dur);
}

// ══════════════════════════════════════════════════════════
//  STEPS — etapas visuais de processo
// ══════════════════════════════════════════════════════════

const STEP_ICONS = {
  active: '⏳',
  done:   '✅',
  fail:   '❌',
};

/**
 * Atualiza o estado visual de um step.
 * @param {string} id    - ID do elemento step no DOM
 * @param {'active'|'done'|'fail'|''} state - Estado desejado
 */
function setStep(id, state) {
  const el = document.getElementById(id);
  if (!el) return;
  el.className = `step ${state}`;
  if (state in STEP_ICONS) {
    el.querySelector('.step-ico').textContent = STEP_ICONS[state];
  }
}

/**
 * Reseta todos os steps de uma lista para o estado padrão.
 * @param {string[]} ids - Array de IDs dos steps
 */
function resetSteps(ids) {
  ids.forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.className = 'step';
    // Restaura ícone original do HTML (guardado em data-icon)
    const ico = el.querySelector('.step-ico');
    if (ico && ico.dataset.icon) ico.textContent = ico.dataset.icon;
  });
}

// ══════════════════════════════════════════════════════════
//  PROGRESS BAR
// ══════════════════════════════════════════════════════════

/**
 * Define a porcentagem de preenchimento de uma barra de progresso.
 * @param {string} id  - ID do elemento .progress-fill
 * @param {number} pct - Porcentagem (0–100)
 */
function setProgress(id, pct) {
  const el = document.getElementById(id);
  if (el) el.style.width = `${pct}%`;
}

/**
 * Reseta uma barra de progresso para 0%.
 * @param {string} id
 */
function resetProgress(id) {
  setProgress(id, 0);
}

// ══════════════════════════════════════════════════════════
//  DROPZONE — drag-and-drop de arquivos
// ══════════════════════════════════════════════════════════

/**
 * Configura uma área de drag-and-drop para arquivos.
 *
 * @param {string}   zoneId  - ID do elemento dropzone no DOM
 * @param {string}   inputId - ID do input[type=file] dentro da zone
 * @param {string}   ext     - Extensão aceita (ex: '.pdf', '.dlm')
 * @param {Function} onFile  - Callback chamado com o File selecionado
 */
function setupDrop(zoneId, inputId, ext, onFile) {
  const zone  = document.getElementById(zoneId);
  const input = document.getElementById(inputId);

  if (!zone || !input) return;

  // Clique na zone abre o seletor
  zone.addEventListener('click', () => input.click());

  // Mudança no input (seleção manual)
  input.addEventListener('change', e => {
    const file = e.target.files[0];
    if (file) onFile(file);
    // Limpa valor para permitir selecionar o mesmo arquivo novamente
    input.value = '';
  });

  // Drag over: destaca a zone
  zone.addEventListener('dragover', e => {
    e.preventDefault();
    zone.classList.add('over');
  });

  // Drag leave: remove destaque
  zone.addEventListener('dragleave', () => zone.classList.remove('over'));

  // Drop: processa o arquivo
  zone.addEventListener('drop', e => {
    e.preventDefault();
    zone.classList.remove('over');
    const file = e.dataTransfer.files[0];
    if (!file) return;

    if (ext !== '.*' && !file.name.toLowerCase().endsWith(ext)) {
      toast(`Selecione um arquivo ${ext}`, 'err');
      return;
    }
    onFile(file);
  });
}

// ══════════════════════════════════════════════════════════
//  TABS — alternância de painéis
// ══════════════════════════════════════════════════════════

/**
 * Inicializa o sistema de abas.
 * Cada .tab deve ter data-tab="<panelId>" e haver um
 * elemento com id="panel-<panelId>" correspondente.
 */
function initTabs() {
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById(`panel-${tab.dataset.tab}`)?.classList.add('active');
    });
  });
}

// ══════════════════════════════════════════════════════════
//  DIAGRAM — diagrama do formato .dlm
// ══════════════════════════════════════════════════════════

/**
 * Renderiza o diagrama visual do formato binário .dlm
 * no elemento com id="format-diagram".
 */
function buildFormatDiagram() {
  const target = document.getElementById('format-diagram');
  if (!target) return;

  const parts = [
    { label: 'MAGIC',      bytes: '4B',  color: '#4f8ef7', desc: '"DLM\\x01" — identificador do formato' },
    { label: 'LICENSE ID', bytes: '8B',  color: '#22d3ee', desc: 'uint64 big-endian — exemplar único' },
    { label: 'IV',         bytes: '16B', color: '#a78bfa', desc: 'Vetor de inicialização AES (aleatório)' },
    { label: 'HMAC',       bytes: '32B', color: '#10b981', desc: 'SHA-256 — integridade e autenticidade' },
    { label: 'CIPHERTEXT', bytes: 'N B', color: '#f59e0b', desc: 'Conteúdo do PDF cifrado AES-256-CBC' },
  ];

  target.innerHTML = parts.map(p => `
    <div style="display:flex;align-items:stretch;margin-bottom:4px">
      <div style="
        background:${p.color}22;border:1px solid ${p.color}55;border-radius:5px 0 0 5px;
        padding:.4rem .7rem;min-width:110px;color:${p.color};font-weight:700;font-size:.65rem;
        display:flex;align-items:center;gap:.4rem;font-family:var(--mono)">
        <span>${p.label}</span>
        <span style="color:${p.color}99;font-size:.58rem">${p.bytes}</span>
      </div>
      <div style="
        flex:1;background:rgba(255,255,255,.03);border:1px solid ${p.color}22;
        border-left:none;border-radius:0 5px 5px 0;padding:.4rem .75rem;
        font-size:.63rem;color:#64748b;display:flex;align-items:center;font-family:var(--sans)">
        ${p.desc}
      </div>
    </div>
  `).join('');
}

// ══════════════════════════════════════════════════════════
//  MISC
// ══════════════════════════════════════════════════════════

/**
 * Retorna uma Promise que resolve após `ms` milissegundos.
 * Usado para criar pausas visuais animadas entre etapas.
 * @param {number} ms
 * @returns {Promise<void>}
 */
function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Copia texto para a área de transferência e exibe toast.
 * @param {string} text
 * @param {string} [label='Copiado!']
 */
async function copyToClipboard(text, label = 'Copiado!') {
  try {
    await navigator.clipboard.writeText(text);
    toast(label, 'info');
  } catch {
    toast('Não foi possível copiar.', 'err');
  }
}

// Exporta para uso global
window.UI = {
  toast,
  setStep,
  resetSteps,
  setProgress,
  resetProgress,
  setupDrop,
  initTabs,
  buildFormatDiagram,
  delay,
  copyToClipboard,
};
