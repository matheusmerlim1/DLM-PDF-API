# DLM-PDF API — Gestão de Posse Digital de E-books via Blockchain

> Plataforma centralizada de DRM para e-books: criptografia, cadeia de custódia e transferência de posse com identificação por nome e CPF. Toda a responsabilidade de criptografia fica na API — os sites clientes apenas chamam os métodos disponíveis.

---

## Arquitetura

```
┌──────────────────────────────────────────────────────────────────┐
│            Livraria DLM (client)          DML-PDF Platform       │
│  usa: POST /encrypt, POST /transfer   usa: POST /decrypt         │
└────────────────┬──────────────────────────────┬─────────────────┘
                 │          HTTPS / JSON         │
┌────────────────▼──────────────────────────────▼─────────────────┐
│                    DLM PDF API  (este servidor)                  │
│                                                                  │
│  ── Métodos DRM (sem JWT, auth por assinatura MetaMask) ──       │
│  POST /api/v1/encrypt          cifra PDF v3 + registra titular   │
│  POST /api/v1/decrypt          decifra com cadeia de custódia    │
│  POST /api/v1/transfer/preview consulta nome+CPF do destinatário │
│  POST /api/v1/transfer         transfere posse da licença        │
│  POST /api/v1/users/register   cadastra endereço → nome + CPF   │
│  GET  /api/v1/users/:address   consulta usuário por endereço     │
│                                                                  │
│  ── Auth JWT (blockchain) ──                                     │
│  GET  /api/v1/auth/challenge   nonce para MetaMask               │
│  POST /api/v1/auth/login       emite JWT                         │
│  POST /api/v1/licenses/:id/open  valida via Smart Contract       │
└────────────────────────────────┬────────────────────────────────┘
                                 │ ethers.js / JSON-RPC
┌────────────────────────────────▼────────────────────────────────┐
│           SMART CONTRACT (Solidity 0.8.20 / Ethereum)            │
│  DLMPDFLicense.sol:  validateAccess, transferLicense, lendLicense│
└──────────────────────────────────────────────────────────────────┘
```

---

## Métodos DRM — Referência Rápida

### POST `/api/v1/encrypt`
Encripta um PDF no formato `.dlm v3` e registra o titular inicial.

```json
// Body (JSON)
{
  "pdfBase64":  "<PDF em base64>",
  "publicKey":  "0x...",
  "userName":   "João Silva",
  "userCPF":    "123.456.789-00",
  "licenseId":  "opcional — gerado automaticamente se ausente"
}

// Resposta 200
{
  "dlmBase64":  "<.dlm v3 em base64>",
  "licenseId":  "12345678",
  "contentHash":"0x...",
  "version":    3,
  "owner":      { "address": "0x...", "name": "João Silva", "cpf": "123.456.789-00" }
}
```

### POST `/api/v1/decrypt`
Decifra um `.dlm v3` usando cadeia de custódia e re-cifra para o dono atual.

Itera por todos os donos históricos até encontrar a chave que satisfaz o **número verificador** (`SHA256(pdf)[0:4]` embutido no ciphertext).

```json
// Body (JSON)
{
  "dlmBase64":  "<.dlm em base64>",
  "publicKey":  "0x...",
  "signature":  "<assinatura MetaMask>",
  "message":    "DLM:decrypt:12345678:1716000000000"
}

// Resposta 200
{
  "pdfBase64":    "<PDF em base64>",
  "dlmBase64":    "<novo .dlm re-cifrado para o dono atual>",
  "licenseId":    "12345678",
  "decryptedWith":"0x...",
  "owner":        { "address": "0x...", "name": "...", "cpf": "..." }
}
```

### POST `/api/v1/transfer/preview`
Consulta nome e CPF do destinatário antes da confirmação da transferência.

```json
// Body (JSON)
{ "toPublicKey": "0x...", "licenseId": "12345678" }

// Resposta 200
{
  "newOwner":     { "address": "0x...", "name": "Maria Santos", "cpf": "987.654.321-00" },
  "currentOwner": { "address": "0x..." },
  "licenseId":    "12345678"
}
```

### POST `/api/v1/transfer`
Executa a transferência de posse. O arquivo `.dlm` será re-cifrado com as chaves do novo dono na próxima chamada a `/decrypt`.

```json
// Body (JSON)
{
  "fromPublicKey": "0x...",
  "toPublicKey":   "0x...",
  "licenseId":     "12345678",
  "signature":     "<assinatura MetaMask do cedente>",
  "message":       "DLM:transfer:12345678:1716000000000"
}
```

---

## Formato do arquivo `.dlm v3`

```
[MAGIC      4B : "DLM\x03"                           ]
[licenseId  8B : uint64 big-endian                   ]
[ownerAddr 42B : endereço Ethereum ASCII do cifrador  ]
[IV        16B : AES-256-CBC IV                       ]
[HMAC      32B : HMAC-SHA256(licId+ownerAddr+IV+ct)  ]
[ciphertext NB : AES-256-CBC(verifyCode 4B || pdf NB)]
```

**Número verificador** (`verifyCode`): `SHA256(pdf)[0:4]` pré-pendido ao plaintext antes de cifrar. Após decifrar, recomputa-se e compara — garante que a chave correta foi usada sem expor o conteúdo. Funciona como o dígito verificador do CPF.

**Cadeia de custódia**: ao decifrar, o servidor tenta as chaves na ordem `[encryptedWithAddress, ...histórico reverso]` até o `verifyCode` conferir. Re-cifra automaticamente com a chave do dono atual e atualiza o registro.

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
