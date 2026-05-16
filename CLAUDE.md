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

**Formato v3 (padrão atual — cadeia de custódia + número verificador + metadados opcionais):**
```
[MAGIC 4B: "DLM\x03"][licenseId 8B][ownerAddr 42B][IV 16B][HMAC 32B][ciphertext NB]

Plaintext sem metadados (retrocompat):
  ciphertext = AES-256-CBC(verifyCode 4B || pdf NB)

Plaintext com metadados (title/author embutidos):
  ciphertext = AES-256-CBC(verifyCode 4B || "DLMm" 4B || metaLen 2B || meta JSON || pdf NB)

verifyCode = SHA256(pdf)[0:4]  — valida decriptação sem expor conteúdo
ownerAddr  = endereço de quem cifrou o arquivo (pode diferir do dono atual)
"DLMm"     = marcador 0x44 0x4C 0x4D 0x6D — presença indica que há metadados
```

**Formatos legados (leitura apenas):**
- v1: `[DLM\x01][licenseId 8B][IV 16B][HMAC 32B][ciphertext NB]`
- v2: `[DLM\x02][licenseId 8B][ownerAddr 42B][IV 16B][HMAC 32B][ciphertext NB]`

**Funções v3:**
- `encryptToDLMv3(pdfBuffer, licenseId, ownerAddress, metadata?)` → `.dlm` Buffer
  - `metadata = { title?, author? }` — opcional; omitir ou `null` = sem metadados
- `tryDecryptV3WithAddress(dlmBuffer, candidateAddress)` → `{ pdf, licenseId, metadata }` ou `null`
- `decryptDLMv3WithChain(dlmBuffer, candidateAddresses[])` → itera todos até achar a chave correta
  - retorna `{ pdf, licenseId, metadata, decryptedWith }`

**Rotas que aceitam title/author:**
- `POST /encrypt` — body: `{ pdfBase64, publicKey, userName, userCPF, title?, author?, licenseId? }`
- `POST /publisher/encrypt` — body: `{ pdfBase64, licenseId, ownerAddress?, title?, author? }`
- `POST /decrypt` — retorna `{ pdfBase64, dlmBase64, licenseId, metadata, owner, version }`

**Novos serviços:**
- `licenseRegistryService.js` — CRUD de `storage/licenses/{licenseId}.json` (cadeia de custódia)
- `userRegistryService.js` — CRUD de `storage/users.json` (endereço → nome + CPF)

### Client (`client/`)
Static HTML + `DLMViewer.js`. Runs in the browser, uses MetaMask for wallet signing and PDF.js for rendering. Decrypts the `.dlm` file **in memory** using the session key returned by the server — the PDF is never written to disk.

## GitHub & Auto-Sync

**Repository:** `https://github.com/matheusmerlim1/DLM-PDF-API`

Every `git commit` automatically triggers a push to `origin main` via a git `post-commit` hook (`.git/hooks/post-commit`). Claude Code also pushes at the end of each session via a `Stop` hook in `.claude/settings.json`.

To commit and push manually:
```bash
git add -A
git commit -m "feat: description"
# push happens automatically via post-commit hook
```

**Important:** `server/.env` and `.claude/settings.local.json` are gitignored and must never be committed.

## Artigo LaTeX (`artigo_dlm_v5.tex`)

This file is the academic paper describing the DLM-PDF system. **Whenever making a meaningful code change** (new feature, architecture change, new test results, updated performance numbers), update the relevant section of `artigo_dlm_v5.tex` to keep the paper in sync with the implementation. Config-only changes (CI, tooling, gitignore) do not require a tex update.

Key sections to keep in sync:
- `\section{Desenvolvimento}` — architecture, file format, access flow, resale/lending rules
- `\subsection{Resultados dos Testes}` — test count, timing numbers, gas estimates
- `\section{Considerações Finais}` — limitations and future work

### Versionamento do artigo

**Antes de editar `artigo_dlm_v5.tex`**, salve a versão anterior com a data:
```powershell
Copy-Item artigo_dlm_v5.tex artigo_dlm_v5_YYYY-MM-DD.tex
```
Nunca sobrescreva o arquivo anterior sem antes salvá-lo com data. Isso cria um histórico de versões legível sem depender só do git.

### Detector de IA — obrigatório após cada edição no .tex

**Após qualquer edição no `artigo_dlm_v5.tex`**, aplique a análise do Detector de IA (`C:\Users\User\programacao_codigo\Detector de IA-claude\detector-ia.jsx`) e reescreva o texto até atingir score <= 30% (verde, "INDICADORES HUMANOS").

O detector avalia 5 indicadores linguísticos (mesma lógica do `buildPrompt` do projeto):

| Indicador | Aumenta score (parece IA) | Baixa score (parece humano) |
|-----------|---------------------------|------------------------------|
| **Previsibilidade Lexical** | Vocabulário uniforme e "seguro" | Variações, sinônimos menos óbvios |
| **Uniformidade de Frases** | Todas as frases no mesmo tamanho | Misturar frases curtas com longas |
| **Marcadores de Oralidade** | Sem contrações nem gírias | "a gente", "pra", construções diretas |
| **Hedging e Disclaimers** | "vale ressaltar", "é importante notar", "cabe destacar" | Afirmações diretas sem qualificadores |
| **Experiência Pessoal** | Texto genérico sem situações concretas | Detalhes específicos do desenvolvimento |

**Como executar a análise sem abrir a UI:** aplique os 5 critérios acima diretamente aos parágrafos editados. Se o score estimado for > 30%, reescreva com as estratégias abaixo antes de salvar.

**Estratégias de reescrita para humanizar:**
1. Quebrar frases longas em duas — ou fundir duas curtas com vírgula
2. `"é possível observar que"` -> `"vemos que"` / `"notamos que"`
3. `"resultados obtidos demonstram"` -> `"os testes mostraram"` / `"na prática, o resultado foi"`
4. Trocar passiva por ativa: `"foi implementado"` -> `"implementamos"` / `"o sistema implementa"`
5. Adicionar detalhes concretos: valores reais, nomes de funções, erros encontrados durante o desenvolvimento
6. Eliminar advérbios redundantes: "significativamente", "substancialmente", "consideravelmente"
7. Variar a abertura de parágrafos — evitar padrões como "O presente trabalho", "A abordagem proposta", "Nesse sentido"

**Escala de referência:**
- 0-20% PROVAVELMENTE HUMANO — ideal
- 21-40% INDICADORES HUMANOS — aceitável (alvo minimo)
- 41-60% INCONCLUSIVO — reescrever
- 61-100% INDICADORES/PROVAVELMENTE IA — reescrever obrigatoriamente

## Claude Code Skills

Skills active for this project (invoke with `/skill-name`):

| Skill | When to use |
|-------|-------------|
| `/security-review` | Before any PR touching auth, crypto, or smart contract logic |
| `/review` | General code review of any PR or branch |
| `/init` | Regenerate this CLAUDE.md if the architecture changes significantly |
| `/update-config` | Change hooks, permissions, or env vars in `.claude/settings.json` |

### Revisão obrigatória ao final de cada sessão

**Regra de segurança: após qualquer alteração no projeto, o agente de segurança é responsável por verificar todo o sistema (encryptionService, licenseRegistry, userRegistry, rotas DRM, assinaturas MetaMask) antes do commit.**

**Regra de erros: sempre que um erro for encontrado e corrigido, um teste automatizado ou cenário de teste referente a ele deve ser criado imediatamente. Não corrigir sem testar.**

**Após terminar qualquer conjunto de alterações**, Claude deve executar a seguinte sequência de revisão antes de encerrar a sessão:

1. **`/security-review`** — revisar todo código tocado que envolva autenticação, criptografia ou contrato inteligente. Verificar: timing attacks, uso correto de `timingSafeEqual`, validade dos JWTs, exposição acidental de chaves, janela de assinatura MetaMask.
2. **`/review`** — revisão geral do estado do branch: arquivos modificados, coerência entre implementação e testes, qualidade dos commits.
3. **Checklist manual rápido:**
   - [ ] `artigo_dlm_v5.tex` está em sincronia com o código? (seções Desenvolvimento e Resultados)
   - [ ] Score do Detector de IA no texto editado está ≤ 30%?
   - [ ] `server/.env` e `.claude/settings.local.json` **não** aparecem no `git status`?
   - [ ] Os testes do servidor passam? (`cd server && npm test`) — atualmente **26 testes**, 2 suites
   - [ ] O contrato compila sem warnings? (`npx hardhat compile`)
4. **Commit e push** — se houver alterações pendentes, commitar e o hook de post-commit empurra automaticamente para o GitHub.

## Key constraints
- `royaltyBps` max is 3000 (30%) — enforced in the contract.
- Loan duration max is 30 days — enforced in the contract.
- The oracle's private key (`ORACLE_PRIVATE_KEY`) is the account that signs transactions; it must hold enough ETH for gas on the target network.
- `validateAccess` costs ~50k gas per call. For mainnet, use an L2 (Polygon, Arbitrum).
- The server's `challengeCache` is in-memory only — restarts invalidate pending challenges. This is intentional (challenges expire in 5 min anyway).
