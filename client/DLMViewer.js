/**
 * DLMViewer.js — SDK do cliente para leitura de arquivos .dlm
 *
 * Responsabilidade:
 *  1. Autenticar o usuário via assinatura de carteira (MetaMask / ethers.js)
 *  2. Fazer handshake com o servidor para obter chave de sessão
 *  3. Decriptografar o arquivo .dlm em memória (nunca em disco)
 *  4. Renderizar o PDF decriptado via PDF.js
 *
 * Dependências:
 *  - ethers.js v6 (carteira / assinatura)
 *  - PDF.js (renderização)
 *  - Web Crypto API (AES-CBC nativo do browser)
 */

export class DLMViewer {
  /**
   * @param {object} opts
   * @param {string}  opts.apiBaseUrl       - URL do servidor de autenticação
   * @param {string}  opts.pdfJsWorkerUrl   - URL do pdf.js worker
   * @param {HTMLElement} opts.container    - Elemento onde o PDF será renderizado
   */
  constructor({ apiBaseUrl, pdfJsWorkerUrl, container }) {
    this.apiBaseUrl      = apiBaseUrl.replace(/\/$/, "");
    this.pdfJsWorkerUrl  = pdfJsWorkerUrl;
    this.container       = container;

    this._jwt            = null;
    this._walletAddress  = null;
    this._provider       = null;
    this._signer         = null;
  }

  // ─── Autenticação ──────────────────────────────────────────────────────────

  /**
   * Conecta a carteira MetaMask e autentica no servidor via assinatura.
   * @returns {string} Endereço da carteira conectada
   */
  async connect() {
    if (typeof window.ethereum === "undefined") {
      throw new Error("MetaMask não encontrado. Instale a extensão para continuar.");
    }

    // Solicita acesso à carteira
    const { ethers } = await import("https://cdn.jsdelivr.net/npm/ethers@6.11.1/dist/ethers.min.js");
    this._provider = new ethers.BrowserProvider(window.ethereum);
    await this._provider.send("eth_requestAccounts", []);
    this._signer       = await this._provider.getSigner();
    this._walletAddress = (await this._signer.getAddress()).toLowerCase();

    // Solicita desafio ao servidor
    const challengeRes = await fetch(
      `${this.apiBaseUrl}/auth/challenge?address=${this._walletAddress}`
    );
    if (!challengeRes.ok) throw new Error("Falha ao solicitar desafio de autenticação.");
    const { message } = await challengeRes.json();

    // Assina o desafio com a carteira
    const signature = await this._signer.signMessage(message);

    // Login no servidor
    const loginRes = await fetch(`${this.apiBaseUrl}/auth/login`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ address: this._walletAddress, message, signature }),
    });
    if (!loginRes.ok) {
      const err = await loginRes.json();
      throw new Error(err.error || "Falha na autenticação.");
    }

    const { token } = await loginRes.json();
    this._jwt = token;

    return this._walletAddress;
  }

  // ─── Abertura do Arquivo .dlm ─────────────────────────────────────────────

  /**
   * Abre um arquivo .dlm, valida a posse on-chain e renderiza o PDF.
   * @param {File|ArrayBuffer} dlmFile  - Arquivo .dlm do disco do usuário
   */
  async openDLM(dlmFile) {
    if (!this._jwt) throw new Error("Usuário não autenticado. Chame connect() primeiro.");

    // Lê o arquivo
    const dlmBuffer = dlmFile instanceof File
      ? await dlmFile.arrayBuffer()
      : dlmFile;

    // Extrai o licenseId do header do arquivo (bytes 4–12)
    const licenseId = this._readLicenseId(dlmBuffer);

    // Handshake com o servidor: valida posse on-chain
    const handshakeRes = await fetch(
      `${this.apiBaseUrl}/licenses/${licenseId}/open`,
      {
        method:  "POST",
        headers: {
          "Content-Type":  "application/json",
          "Authorization": `Bearer ${this._jwt}`,
        },
        body: JSON.stringify({}),
      }
    );

    if (handshakeRes.status === 403) {
      const err = await handshakeRes.json();
      throw new Error(err.error || "Acesso negado pela blockchain.");
    }
    if (!handshakeRes.ok) {
      throw new Error("Falha na validação de acesso.");
    }

    const { sessionKey, sessionNonce } = await handshakeRes.json();

    // Decripta o arquivo em memória usando Web Crypto API
    const pdfBuffer = await this._decryptDLM(dlmBuffer, sessionKey, sessionNonce);

    // Renderiza o PDF
    await this._renderPDF(pdfBuffer);
  }

  // ─── Decriptação em Memória ────────────────────────────────────────────────

  /**
   * Decripta um arquivo .dlm usando a chave de sessão recebida do servidor.
   * Toda a operação ocorre em memória — o PDF nunca é salvo em disco.
   *
   * Formato do arquivo:
   * [MAGIC 4B][licenseId 8B][IV 16B][HMAC 32B][ciphertext NB]
   */
  async _decryptDLM(dlmBuffer, sessionKey, sessionNonce) {
    const bytes = new Uint8Array(dlmBuffer);

    // Valida magic "DLM\x01"
    const magic = String.fromCharCode(...bytes.slice(0, 4));
    if (magic !== "DLM\x01") throw new Error("Arquivo .dlm inválido.");

    const iv         = bytes.slice(12, 28);
    const ciphertext = bytes.slice(60);

    // Importa a chave AES-256-CBC via Web Crypto
    const keyBytes = this._hexToBytes(sessionKey);
    const cryptoKey = await crypto.subtle.importKey(
      "raw", keyBytes,
      { name: "AES-CBC" },
      false,
      ["decrypt"]
    );

    // Decripta
    const pdfBuffer = await crypto.subtle.decrypt(
      { name: "AES-CBC", iv },
      cryptoKey,
      ciphertext
    );

    return pdfBuffer;
  }

  // ─── Renderização PDF.js ──────────────────────────────────────────────────

  async _renderPDF(pdfBuffer) {
    // Carrega PDF.js dinamicamente
    const pdfjsLib = window["pdfjs-dist/build/pdf"];
    if (!pdfjsLib) throw new Error("PDF.js não carregado. Inclua o script na página.");

    pdfjsLib.GlobalWorkerOptions.workerSrc = this.pdfJsWorkerUrl;

    const pdf     = await pdfjsLib.getDocument({ data: pdfBuffer }).promise;
    const numPages = pdf.numPages;

    this.container.innerHTML = "";

    for (let pageNum = 1; pageNum <= numPages; pageNum++) {
      const page    = await pdf.getPage(pageNum);
      const viewport = page.getViewport({ scale: 1.5 });

      const canvas  = document.createElement("canvas");
      canvas.width  = viewport.width;
      canvas.height = viewport.height;
      canvas.style.display = "block";
      canvas.style.margin  = "0 auto 16px";
      this.container.appendChild(canvas);

      await page.render({
        canvasContext: canvas.getContext("2d"),
        viewport,
      }).promise;
    }
  }

  // ─── Utilitários ──────────────────────────────────────────────────────────

  _readLicenseId(dlmBuffer) {
    const view = new DataView(dlmBuffer instanceof ArrayBuffer ? dlmBuffer : dlmBuffer.buffer);
    // bytes 4–12: uint64 big-endian
    const high = view.getUint32(4, false);
    const low  = view.getUint32(8, false);
    return (BigInt(high) * 0x100000000n + BigInt(low)).toString();
  }

  _hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  }
}
