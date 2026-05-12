/**
 * blockchainService.js
 * Camada de abstração para interação com o Smart Contract DLMPDFLicense.
 *
 * Modos de operação:
 *  - connected : blockchain disponível, todas as funções ativas
 *  - demo      : CONTRACT_ADDRESS=demo, respostas simuladas para desenvolvimento
 *  - offline   : blockchain indisponível, rotas retornam 503 com diagnóstico
 */

import { ethers } from "ethers";
import { createLogger, transports, format } from "winston";

const logger = createLogger({
  level: process.env.NODE_ENV === "production" ? "warn" : "info",
  format: format.combine(
    format.colorize(),
    format.timestamp({ format: "HH:mm:ss" }),
    format.printf(({ timestamp, level, message }) =>
      `${timestamp} ${level}: ${message}`
    )
  ),
  transports: [new transports.Console()],
});

// ─── ABI mínima do contrato ───────────────────────────────────────────────────
const CONTRACT_ABI = [
  "function checkAccess(uint256 licenseId, address requester) external view returns (bool)",
  "function getLicenseInfo(uint256 licenseId) external view returns (uint256 bookId, address owner, address borrower, uint256 borrowUntil, bool isLoanActive)",
  "function getLicensesByOwner(address owner) external view returns (uint256[])",
  "function books(uint256) external view returns (string title, string author, bytes32 contentHash, address publisher, uint256 totalCopies, uint256 royaltyBps, bool active)",
  "function validateAccess(uint256 licenseId, address requester) external returns (bool)",
  "function mintLicense(uint256 bookId, address buyer) external returns (uint256)",
  "function transferLicense(uint256 licenseId, address to) external payable",
  "function lendLicense(uint256 licenseId, address borrower, uint256 duration) external",
  "function returnLicense(uint256 licenseId) external",
  "function registerBook(string title, string author, bytes32 contentHash, uint256 royaltyBps) external returns (uint256)",
  "event AccessValidated(uint256 indexed licenseId, address indexed requester, bool granted)",
  "event LicenseTransferred(uint256 indexed licenseId, address indexed from, address indexed to, uint256 price)",
  "event LicenseMinted(uint256 indexed licenseId, uint256 indexed bookId, address indexed owner)",
];

// ─── Dados simulados para modo DEMO ──────────────────────────────────────────
const DEMO_LICENSES = {
  "1": {
    bookId: "1",
    owner: "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
    borrower: "0x0000000000000000000000000000000000000000",
    borrowUntil: "0",
    isLoanActive: false,
  },
};

const DEMO_BOOKS = {
  "1": {
    title: "Livro Demo — DLM-PDF",
    author: "Autor Demo",
    contentHash: "0x" + "0".repeat(64),
    publisher: "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
    totalCopies: "1",
    royaltyBps: "500",
    active: true,
  },
};

// ─── Classe BlockchainService ─────────────────────────────────────────────────
class BlockchainService {
  constructor() {
    this.provider  = null;
    this.signer    = null;
    this.contract  = null;
    this.mode      = "offline"; // "connected" | "demo" | "offline"
    this.chainId   = null;
    this.initError = null;
  }

  // ── Init: nunca lança exceção, usa modo degraded ──────────────────────────

  async init() {
    const rpcUrl          = process.env.BLOCKCHAIN_RPC_URL;
    const contractAddress = process.env.CONTRACT_ADDRESS;
    const privateKey      = process.env.ORACLE_PRIVATE_KEY;

    // Modo DEMO
    if (contractAddress === "demo" || process.env.DEMO_MODE === "true") {
      this.mode = "demo";
      logger.warn("⚡ Modo DEMO — respostas simuladas (sem blockchain real).");
      logger.warn("   Para usar blockchain real: configure CONTRACT_ADDRESS no .env");
      return;
    }

    // Verifica variáveis ausentes
    const missing = [];
    if (!rpcUrl)          missing.push("BLOCKCHAIN_RPC_URL");
    if (!contractAddress) missing.push("CONTRACT_ADDRESS");
    if (!privateKey)      missing.push("ORACLE_PRIVATE_KEY");

    if (missing.length > 0) {
      this._setOffline(`Variáveis de ambiente ausentes: ${missing.join(", ")}`);
      logger.warn("   Dica: copie server/.env.example → server/.env e preencha.");
      logger.warn("   Dica: para testar sem blockchain, defina CONTRACT_ADDRESS=demo");
      return;
    }

    // Valida formato da chave privada
    const key = privateKey.startsWith("0x") ? privateKey : `0x${privateKey}`;
    if (!/^0x[0-9a-fA-F]{64}$/.test(key)) {
      this._setOffline("ORACLE_PRIVATE_KEY inválida: deve ter 64 caracteres hexadecimais.");
      return;
    }

    // Valida endereço do contrato
    if (contractAddress === "0x" + "0".repeat(40)) {
      this._setOffline(
        "CONTRACT_ADDRESS é o endereço zero. " +
        "Faça o deploy primeiro: npx hardhat run scripts/deploy.js --network localhost"
      );
      return;
    }

    if (!/^0x[0-9a-fA-F]{40}$/.test(contractAddress)) {
      this._setOffline(`CONTRACT_ADDRESS inválido: "${contractAddress}"`);
      return;
    }

    // Tenta conectar com timeout de 5 segundos
    try {
      this.provider = new ethers.JsonRpcProvider(rpcUrl);
      this.signer   = new ethers.Wallet(key, this.provider);
      this.contract = new ethers.Contract(contractAddress, CONTRACT_ABI, this.signer);

      const network = await Promise.race([
        this.provider.getNetwork(),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error(`Timeout: node RPC não respondeu. URL: ${rpcUrl}`)), 5000)
        ),
      ]);

      this.chainId = network.chainId.toString();
      this.mode    = "connected";

      logger.info(`✅ Blockchain conectada | chainId=${this.chainId}`);
      logger.info(`   RPC:      ${rpcUrl}`);
      logger.info(`   Contrato: ${contractAddress}`);
      logger.info(`   Oráculo:  ${this.signer.address}`);

    } catch (err) {
      this._setOffline(err.message);
      logger.warn("   Soluções:");
      logger.warn("     1. Suba o Hardhat node:  npx hardhat node");
      logger.warn("     2. Faça o deploy:        npx hardhat run scripts/deploy.js --network localhost");
      logger.warn("     3. Configure .env com o endereço gerado pelo deploy");
      logger.warn("     4. Use modo demo:        CONTRACT_ADDRESS=demo");
    }
  }

  _setOffline(reason) {
    this.mode      = "offline";
    this.initError = reason;
    this.provider  = null;
    this.signer    = null;
    this.contract  = null;
    logger.warn(`⚠️  Blockchain offline: ${reason}`);
  }

  // ── Guard ─────────────────────────────────────────────────────────────────

  _requireConnection(operation = "operação") {
    if (this.mode === "connected" || this.mode === "demo") return;

    const err = new Error(
      `Blockchain indisponível para: ${operation}. ` +
      (this.initError ? `Causa: ${this.initError}` : "") +
      " | Dica: defina CONTRACT_ADDRESS=demo no .env para modo de demonstração."
    );
    err.statusCode = 503;
    err.code = "BLOCKCHAIN_OFFLINE";
    throw err;
  }

  // ── Status ────────────────────────────────────────────────────────────────

  getStatus() {
    return {
      mode:            this.mode,
      connected:       this.mode === "connected",
      demo:            this.mode === "demo",
      chainId:         this.chainId,
      contractAddress: process.env.CONTRACT_ADDRESS || null,
      rpcUrl:          process.env.BLOCKCHAIN_RPC_URL || null,
      oracleAddress:   this.signer?.address || null,
      error:           this.initError || null,
    };
  }

  // ── Oráculo de Acesso ─────────────────────────────────────────────────────

  async checkAccessView(licenseId, requesterAddress) {
    this._requireConnection("checkAccess");

    if (this.mode === "demo") {
      const lic = DEMO_LICENSES[String(licenseId)];
      const granted = lic
        ? lic.owner.toLowerCase() === requesterAddress.toLowerCase()
        : false;
      logger.info(`[DEMO] checkAccess lid=${licenseId} granted=${granted}`);
      return granted;
    }

    const granted = await this.contract.checkAccess(BigInt(licenseId), requesterAddress);
    logger.info(`checkAccess lid=${licenseId} addr=${requesterAddress} granted=${granted}`);
    return granted;
  }

  async validateAccessOnChain(licenseId, requesterAddress) {
    this._requireConnection("validateAccess");

    if (this.mode === "demo") {
      const lic     = DEMO_LICENSES[String(licenseId)];
      const granted = lic
        ? lic.owner.toLowerCase() === requesterAddress.toLowerCase()
        : false;
      const fakeTx  = "0x" + Array.from({ length: 64 }, () =>
        Math.floor(Math.random() * 16).toString(16)).join("");
      logger.info(`[DEMO] validateAccess lid=${licenseId} granted=${granted}`);
      return { granted, txHash: fakeTx };
    }

    const tx      = await this.contract.validateAccess(BigInt(licenseId), requesterAddress);
    const receipt = await tx.wait();

    let granted = false;
    for (const log of receipt.logs) {
      try {
        const parsed = this.contract.interface.parseLog(log);
        if (parsed?.name === "AccessValidated") {
          granted = parsed.args.granted;
          break;
        }
      } catch (_) {}
    }

    logger.info(`validateOnChain lid=${licenseId} granted=${granted} tx=${receipt.hash}`);
    return { granted, txHash: receipt.hash };
  }

  // ── Consultas ─────────────────────────────────────────────────────────────

  async getLicenseInfo(licenseId) {
    this._requireConnection("getLicenseInfo");

    if (this.mode === "demo") {
      const lic = DEMO_LICENSES[String(licenseId)];
      if (!lic) throw Object.assign(new Error(`Licença ${licenseId} não encontrada.`), { statusCode: 404 });
      return lic;
    }

    const info = await this.contract.getLicenseInfo(BigInt(licenseId));
    return {
      bookId:       info.bookId.toString(),
      owner:        info.owner,
      borrower:     info.borrower,
      borrowUntil:  info.borrowUntil.toString(),
      isLoanActive: info.isLoanActive,
    };
  }

  async getBookInfo(bookId) {
    this._requireConnection("getBookInfo");

    if (this.mode === "demo") {
      const book = DEMO_BOOKS[String(bookId)];
      if (!book) throw Object.assign(new Error(`Livro ${bookId} não encontrado.`), { statusCode: 404 });
      return book;
    }

    const book = await this.contract.books(BigInt(bookId));
    return {
      title:       book.title,
      author:      book.author,
      contentHash: book.contentHash,
      publisher:   book.publisher,
      totalCopies: book.totalCopies.toString(),
      royaltyBps:  book.royaltyBps.toString(),
      active:      book.active,
    };
  }

  async getLicensesByOwner(ownerAddress) {
    this._requireConnection("getLicensesByOwner");

    if (this.mode === "demo") {
      return Object.entries(DEMO_LICENSES)
        .filter(([, l]) => l.owner.toLowerCase() === ownerAddress.toLowerCase())
        .map(([id]) => id);
    }

    const ids = await this.contract.getLicensesByOwner(ownerAddress);
    return ids.map(id => id.toString());
  }

  // ── Transações ────────────────────────────────────────────────────────────

  async mintLicense(bookId, buyerAddress) {
    this._requireConnection("mintLicense");

    if (this.mode === "demo") {
      const newId = String(Object.keys(DEMO_LICENSES).length + 1);
      DEMO_LICENSES[newId] = {
        bookId: String(bookId),
        owner: buyerAddress.toLowerCase(),
        borrower: "0x0000000000000000000000000000000000000000",
        borrowUntil: "0",
        isLoanActive: false,
      };
      return { licenseId: newId, txHash: "0x" + "b".repeat(64) };
    }

    const tx      = await this.contract.mintLicense(BigInt(bookId), buyerAddress);
    const receipt = await tx.wait();

    for (const log of receipt.logs) {
      try {
        const parsed = this.contract.interface.parseLog(log);
        if (parsed?.name === "LicenseMinted") {
          return { licenseId: parsed.args.licenseId.toString(), txHash: receipt.hash };
        }
      } catch (_) {}
    }
    throw new Error("Evento LicenseMinted não encontrado no recibo da transação.");
  }

  async registerBook(title, author, contentHash, royaltyBps) {
    this._requireConnection("registerBook");

    if (this.mode === "demo") {
      const newId = String(Object.keys(DEMO_BOOKS).length + 1);
      DEMO_BOOKS[newId] = {
        title, author, contentHash,
        publisher: "demo",
        totalCopies: "0",
        royaltyBps: String(royaltyBps),
        active: true,
      };
      return { bookId: newId, txHash: "0x" + "c".repeat(64) };
    }

    const hashBytes = ethers.hexlify(
      typeof contentHash === "string" && contentHash.startsWith("0x")
        ? contentHash
        : ethers.toUtf8Bytes(contentHash).slice(0, 32)
    );
    const tx      = await this.contract.registerBook(title, author, hashBytes, BigInt(royaltyBps));
    const receipt = await tx.wait();
    return { txHash: receipt.hash };
  }
}

export const blockchainService = new BlockchainService();
