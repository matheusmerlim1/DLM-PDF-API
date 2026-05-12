/**
 * js/main.js
 * Responsabilidade: ponto de entrada da aplicação DLM-PDF Platform.
 *
 * Inicializa todos os módulos após o DOM estar carregado:
 *  - UI (tabs, diagrama de formato)
 *  - Publisher (aba da editora)
 *  - Reader (aba do leitor)
 *  - PDF.js worker
 *
 * Ordem de carregamento dos scripts no HTML:
 *  1. pdf.min.js (CDN)
 *  2. crypto.js   → window.DLMCrypto
 *  3. ui.js       → window.UI
 *  4. publisher.js → window.Publisher
 *  5. reader.js   → window.Reader
 *  6. main.js     (este arquivo — último)
 */

'use strict';

// Configura o worker do PDF.js
pdfjsLib.GlobalWorkerOptions.workerSrc =
  'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';

document.addEventListener('DOMContentLoaded', () => {
  // 1. Inicializa sistema de abas
  UI.initTabs();

  // 2. Renderiza diagrama do formato .dlm no painel da editora
  UI.buildFormatDiagram();

  // 3. Inicializa o painel da editora
  Publisher.initPublisher();

  // 4. Inicializa o painel do leitor
  Reader.initReader();

  console.log('[DLM-PDF] Plataforma inicializada.');
});
