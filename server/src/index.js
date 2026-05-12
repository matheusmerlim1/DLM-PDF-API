/**
 * index.js — Ponto de entrada do servidor DLM-PDF
 *
 * O servidor SEMPRE sobe, independentemente do status da blockchain.
 * O modo de operação (connected / demo / offline) é informado nos logs
 * e retornado pelo endpoint GET /api/v1/health.
 */

import "dotenv/config";
import express   from "express";
import helmet    from "helmet";
import cors      from "cors";
import rateLimit from "express-rate-limit";
import { createLogger, transports, format } from "winston";

import routes                from "./routes/index.js";
import { blockchainService } from "./services/blockchainService.js";

// ─── Logger ───────────────────────────────────────────────────────────────────
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

// ─── App Express ──────────────────────────────────────────────────────────────
const app = express();

app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGIN || "*", credentials: true }));
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { error: "Muitas requisições. Tente em 15 minutos." },
}));
app.use(express.json({ limit: "50mb" }));

// ─── Rotas ────────────────────────────────────────────────────────────────────
app.use("/api/v1", routes);

// ─── 404 ──────────────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: `Rota não encontrada: ${req.method} ${req.path}` });
});

// ─── Error handler global ─────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  const status = err.statusCode || 500;
  logger.error(`[${status}] ${err.message}`);
  res.status(status).json({
    error:  err.message,
    code:   err.code || "INTERNAL_ERROR",
  });
});

// ─── Inicialização ────────────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT || "3000", 10);

async function start() {
  logger.info("🚀 Iniciando servidor DLM-PDF...");

  // Tenta conectar à blockchain — nunca lança exceção, usa modo degraded
  await blockchainService.init();

  const status = blockchainService.getStatus();

  app.listen(PORT, () => {
    logger.info(`────────────────────────────────────────`);
    logger.info(`✅ Servidor rodando: http://localhost:${PORT}/api/v1`);
    logger.info(`   Blockchain: ${status.mode.toUpperCase()}`);

    if (status.mode === "connected") {
      logger.info(`   Chain ID:  ${status.chainId}`);
      logger.info(`   Contrato:  ${status.contractAddress}`);
      logger.info(`   Oráculo:   ${status.oracleAddress}`);
    } else if (status.mode === "demo") {
      logger.warn(`   ⚡ MODO DEMO — dados simulados em memória`);
    } else {
      logger.warn(`   ⚠️  OFFLINE — endpoints de blockchain retornam 503`);
      logger.warn(`   Causa: ${status.error}`);
      logger.warn(`   Acesse GET /api/v1/health para diagnóstico completo`);
    }

    logger.info(`────────────────────────────────────────`);
  });
}

start().catch(err => {
  // Só chega aqui se o próprio app.listen falhar (porta em uso, etc.)
  logger.error(`❌ Falha crítica ao iniciar: ${err.message}`);
  process.exit(1);
});

export default app;
