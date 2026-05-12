# DLM-PDF — Gestão de Posse Digital de E-books via Blockchain

> Modelo de custódia de autorização para e-books: cada exemplar é um ativo digital único registrado na blockchain Ethereum, com suporte a revenda P2P e empréstimo digital.

---

## Arquitetura

```
┌──────────────────────────────────────────────────────────────────┐
│                        CLIENTE (Browser)                         │
│  DLMViewer.js  →  assina com MetaMask  →  abre arquivo .dlm      │
└───────────────────────────┬──────────────────────────────────────┘
                            │ HTTPS + JWT
┌───────────────────────────▼──────────────────────────────────────┐
│              SERVIDOR DE AUTENTICAÇÃO (Node.js/Express)          │
│  POST /api/v1/licenses/:id/open  →  valida via Smart Contract    │
│  GET  /api/v1/auth/challenge     →  emite nonce para assinatura  │
└───────────────────────────┬──────────────────────────────────────┘
                            │ ethers.js / JSON-RPC
┌───────────────────────────▼──────────────────────────────────────┐
│            SMART CONTRACT (Solidity 0.8.20 / Ethereum)           │
│  DLMPDFLicense.sol:                                              │
│    validateAccess()  →  registra evento on-chain                 │
│    checkAccess()     →  leitura view (sem gas)                   │
│    transferLicense() →  revenda P2P com royalty                  │
│    lendLicense()     →  empréstimo temporário                    │
└──────────────────────────────────────────────────────────────────┘
```

### Fluxo de leitura de um e-book

```
1. Usuário abre arquivo .dlm  →  browser extrai licenseId do header
2. Usuário clica "Abrir"      →  DLMViewer assina nonce com MetaMask
3. Servidor autentica JWT     →  chama validateAccess() on-chain
4. Blockchain retorna true    →  servidor gera sessionKey efêmera
5. Browser decripta .dlm      →  PDF em memória (AES-256-CBC)
6. PDF.js renderiza           →  usuário lê o e-book
```

### Formato do arquivo `.dlm`

```
[MAGIC 4B: "DLM\x01"][licenseId 8B][IV 16B][HMAC-SHA256 32B][ciphertext NB]
```

A chave AES **não é armazenada no arquivo**. Ela é derivada via HKDF do segredo mestre + licenseId. Copiar o arquivo sem a licença não abre nada.

---

## Estrutura do Projeto

```
dlm-pdf/
├── contracts/
│   └── DLMPDFLicense.sol       # Smart Contract principal
├── scripts/
│   └── deploy.js               # Script de deploy (Hardhat)
├── test/
│   └── DLMPDFLicense.test.js   # Testes do contrato
├── server/
│   ├── package.json
│   ├── .env.example
│   └── src/
│       ├── index.js             # Entry point Express
│       ├── routes/index.js      # Rotas da API
│       ├── middleware/
│       │   └── authMiddleware.js # JWT + assinatura de carteira
│       └── services/
│           ├── blockchainService.js  # Oráculo: chama o contrato
│           └── encryptionService.js  # AES-256-CBC + HMAC
├── client/
│   ├── index.html               # Leitor (browser)
│   └── DLMViewer.js             # SDK cliente
├── hardhat.config.js
└── package.json
```

---

## Instalação e Execução

### Pré-requisitos

- Node.js >= 20
- MetaMask (para o cliente)
- Ganache (rede local) **ou** Hardhat Node

### 1. Instalar dependências

```bash
# Dependências do Hardhat (contrato + testes)
npm install

# Dependências do servidor
npm run node:install
```

### 2. Configurar variáveis de ambiente

```bash
cp server/.env.example server/.env
# Edite server/.env com suas configurações
```

### 3. Subir a rede local

```bash
# Terminal 1: Hardhat node (fornece 20 contas de teste com ETH)
npm run chain:node
```

### 4. Fazer deploy do contrato

```bash
# Terminal 2
npm run chain:deploy
# Anote o endereço do contrato e atualize server/.env → CONTRACT_ADDRESS
```

### 5. Rodar os testes do contrato

```bash
npm run chain:test
```

### 6. Iniciar o servidor

```bash
# Terminal 3
npm run node:dev
# Servidor em http://localhost:3000/api/v1
```

### 7. Abrir o cliente

```bash
# Sirva os arquivos estáticos com qualquer servidor HTTP
npx serve client/
# Acesse http://localhost:3001
```

---

## Endpoints da API

| Método | Rota | Descrição |
|--------|------|-----------|
| GET    | `/auth/challenge` | Solicita nonce para assinatura |
| POST   | `/auth/login`     | Autentica com assinatura e recebe JWT |
| GET    | `/licenses/mine`  | Lista licenças do usuário |
| GET    | `/licenses/:id`   | Detalhes de uma licença |
| GET    | `/licenses/:id/access` | Verifica acesso (view, sem gas) |
| **POST** | **`/licenses/:id/open`** | **Handshake principal: valida on-chain** |
| GET    | `/books/:id`      | Metadados públicos de um livro |
| POST   | `/publisher/books`           | Registra livro (editora) |
| POST   | `/publisher/books/:id/mint`  | Emite licença (editora) |
| POST   | `/publisher/encrypt`         | Encripta PDF → .dlm |
| GET    | `/health`         | Status do servidor + blockchain |

---

## Smart Contract — Funções Principais

```solidity
// Valida acesso e registra evento on-chain (com gas)
function validateAccess(uint256 licenseId, address requester) external returns (bool)

// Valida acesso sem gas (consulta rápida)
function checkAccess(uint256 licenseId, address requester) external view returns (bool)

// Revenda P2P com royalty automático para a editora
function transferLicense(uint256 licenseId, address to) external payable

// Empréstimo temporário (max 30 dias)
function lendLicense(uint256 licenseId, address borrower, uint256 duration) external

// Devolução (pode ser chamado pelo dono ou tomador)
function returnLicense(uint256 licenseId) external
```

---

## Limitações Conhecidas

- **Dependência de conectividade**: o handshake de abertura exige conexão com o node blockchain.
- **Gas cost**: cada chamada de `validateAccess` consome ~50k gas. Em mainnet, use L2 (Polygon, Arbitrum).
- **Oráculo centralizado**: o servidor atual é um ponto único de falha; em produção, distribua múltiplos oráculos.

---

## Referências

- Gaber & Zhang (2010) — Fairness in digital license reselling
- Dashti et al. (2007) — Formal verification of DRM protocols (Nuovo DRM)
- Nair et al. (2005) — Super-distribution preserving DRM in P2P
- BlockCAM (2023) — Blockchain-based cross-domain authentication
