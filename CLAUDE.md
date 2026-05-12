# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Blockchain / Smart Contract (root)
```bash
npm install                  # Install Hardhat + toolbox
npm run chain:node           # Start local Hardhat node (Terminal 1)
npm run chain:deploy         # Deploy DLMPDFLicense.sol → prints contract address
npm run chain:test           # Run Hardhat/Mocha tests in test/
npx hardhat compile          # Compile Solidity only
```

### Server (Node.js)
```bash
npm run node:install         # Install server deps (runs npm install --prefix server)
npm run node:dev             # Start server with nodemon (hot-reload, port 3000)
npm run node:start           # Start server in production mode
cd server && npm test        # Run Jest tests (uses --experimental-vm-modules)
```

### Client
```bash
npx serve client/            # Serve browser viewer at http://localhost:3001
```

### Environment setup
```bash
cp server/.env.example server/.env
# Minimum for local dev without blockchain: CONTRACT_ADDRESS=demo
```

## Architecture

The system has three layers that communicate in sequence:

```
Browser (DLMViewer.js + MetaMask)
    ↕ HTTPS + JWT
Node.js/Express server  (server/src/)
    ↕ ethers.js / JSON-RPC
Solidity Smart Contract  (contracts/DLMPDFLicense.sol)
```

### Smart Contract (`contracts/DLMPDFLicense.sol`)
Solidity 0.8.20. Core concept: each book copy is a unique on-chain asset (`License` struct). Key rules:
- Only the book's publisher (`msg.sender` at `registerBook`) can `mintLicense`.
- `transferLicense` is payable; royalty (basis points) is auto-sent to the publisher.
- Lending locks the owner out — during an active loan only the borrower has access.
- `validateAccess` (state-changing, emits event) vs `checkAccess` (view, no gas) implement the same logic; the server calls the former for the actual open handshake.

### Server (`server/src/`)
ES module (`"type": "module"`). Three-mode operation controlled by `.env`:

| Mode | Trigger | Behavior |
|------|---------|----------|
| `connected` | Valid `BLOCKCHAIN_RPC_URL` + `CONTRACT_ADDRESS` + `ORACLE_PRIVATE_KEY` | Full on-chain calls via ethers.js |
| `demo` | `CONTRACT_ADDRESS=demo` | In-memory mock data, no blockchain needed |
| `offline` | Missing/bad env vars or RPC unreachable | Blockchain endpoints return `503 BLOCKCHAIN_OFFLINE` |

The server **always starts** regardless of blockchain status; mode is reported at `/api/v1/health`.

**Auth flow** (`middleware/authMiddleware.js`):
1. `GET /auth/challenge?address=0x…` — server generates a nonce, stores it in a `Map` with 5-minute TTL.
2. User signs the human-readable message with MetaMask.
3. `POST /auth/login` — server calls `ethers.verifyMessage` to recover signer address, issues JWT (`iss: dlm-pdf-oracle`, `aud: dlm-pdf-client`).
4. All protected routes use `requireAuth` middleware, which sets `req.userAddress`.

**Main handshake** (`POST /licenses/:id/open`):
1. `blockchainService.validateAccessOnChain(licenseId, address)` — calls `validateAccess()` on-chain, waits for receipt, parses `AccessValidated` event.
2. If granted: derives a per-request session key via `generateSessionKey(licenseId, nonce)` (HMAC-SHA256 of HKDF-derived key + random nonce).
3. Returns `{ granted, txHash, sessionKey, sessionNonce, expiresAt }`.

### Encryption Service (`server/src/services/encryptionService.js`)
`.dlm` file format (binary):
```
[MAGIC 4B: "DLM\x01"][licenseId 8B uint64 BE][IV 16B][HMAC-SHA256 32B][ciphertext NB]
```
- Key is **never stored in the file**. It is derived per `licenseId` using HKDF-SHA256 from `MASTER_ENCRYPTION_KEY`.
- `encryptToDLM(pdfBuffer, licenseId)` → `.dlm` Buffer.
- `decryptDLM(dlmBuffer)` → `{ pdf, licenseId }`, verifies HMAC with `timingSafeEqual` before decrypting.
- `generateSessionKey(licenseId, nonce)` is used for the ephemeral key returned to the client — it is a second HMAC layer on top of the HKDF key, scoped to one session nonce.

### Client (`client/`)
Static HTML + `DLMViewer.js`. Runs in the browser, uses MetaMask for wallet signing and PDF.js for rendering. Decrypts the `.dlm` file **in memory** using the session key returned by the server — the PDF is never written to disk.

## Key constraints
- `royaltyBps` max is 3000 (30%) — enforced in the contract.
- Loan duration max is 30 days — enforced in the contract.
- The oracle's private key (`ORACLE_PRIVATE_KEY`) is the account that signs transactions; it must hold enough ETH for gas on the target network.
- `validateAccess` costs ~50k gas per call. For mainnet, use an L2 (Polygon, Arbitrum).
- The server's `challengeCache` is in-memory only — restarts invalidate pending challenges. This is intentional (challenges expire in 5 min anyway).
