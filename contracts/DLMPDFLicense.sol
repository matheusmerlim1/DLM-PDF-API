// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title DLMPDFLicense
 * @notice Gerencia a custódia de licenças de e-books como ativos digitais únicos.
 * @dev Implementa o conceito de "Escassez Digital": cada exemplar (cópia) de um livro
 *      possui um único dono registrado na blockchain. A transferência revoga o acesso
 *      do vendedor instantaneamente. Empréstimo é suportado via custódia temporária.
 */
contract DLMPDFLicense {
    // ─── Structs ────────────────────────────────────────────────────────────────

    struct Book {
        string  title;
        string  author;
        bytes32 contentHash;      // SHA-256 do arquivo original (integridade)
        address publisher;
        uint256 totalCopies;
        uint256 royaltyBps;       // Royalty em basis points (ex: 500 = 5%)
        bool    active;
    }

    struct License {
        uint256 bookId;
        address owner;
        address borrower;         // address(0) se não emprestado
        uint256 borrowUntil;      // timestamp unix; 0 se não emprestado
        bool    exists;
    }

    // ─── State ───────────────────────────────────────────────────────────────────

    address public admin;

    uint256 private _nextBookId   = 1;
    uint256 private _nextLicenseId = 1;

    mapping(uint256 => Book)    public books;
    mapping(uint256 => License) public licenses;

    // bookId => lista de licenseIds emitidos
    mapping(uint256 => uint256[]) private _bookLicenses;

    // owner => lista de licenseIds que ele possui
    mapping(address => uint256[]) private _ownerLicenses;

    // ─── Events ──────────────────────────────────────────────────────────────────

    event BookRegistered(uint256 indexed bookId, string title, address indexed publisher);
    event LicenseMinted(uint256 indexed licenseId, uint256 indexed bookId, address indexed owner);
    event LicenseTransferred(uint256 indexed licenseId, address indexed from, address indexed to, uint256 price);
    event LicenseLent(uint256 indexed licenseId, address indexed borrower, uint256 until);
    event LicenseReturned(uint256 indexed licenseId, address indexed borrower);
    event AccessValidated(uint256 indexed licenseId, address indexed requester, bool granted);

    // ─── Modifiers ───────────────────────────────────────────────────────────────

    modifier onlyAdmin() {
        require(msg.sender == admin, "DLM: somente admin");
        _;
    }

    modifier onlyPublisher(uint256 bookId) {
        require(books[bookId].publisher == msg.sender, "DLM: somente a editora");
        _;
    }

    modifier licenseExists(uint256 licenseId) {
        require(licenses[licenseId].exists, "DLM: licenca inexistente");
        _;
    }

    modifier onlyOwner(uint256 licenseId) {
        require(licenses[licenseId].owner == msg.sender, "DLM: somente o dono");
        _;
    }

    // ─── Constructor ─────────────────────────────────────────────────────────────

    constructor() {
        admin = msg.sender;
    }

    // ─── Funções de Editora ──────────────────────────────────────────────────────

    /**
     * @notice Registra um novo livro na blockchain.
     * @param title        Título do livro
     * @param author       Autor(a)
     * @param contentHash  Hash SHA-256 do arquivo PDF original
     * @param royaltyBps   Percentual de royalty em basis points (max 3000 = 30%)
     */
    function registerBook(
        string  calldata title,
        string  calldata author,
        bytes32 contentHash,
        uint256 royaltyBps
    ) external returns (uint256 bookId) {
        require(royaltyBps <= 3000, "DLM: royalty max 30%");

        bookId = _nextBookId++;
        books[bookId] = Book({
            title:       title,
            author:      author,
            contentHash: contentHash,
            publisher:   msg.sender,
            totalCopies: 0,
            royaltyBps:  royaltyBps,
            active:      true
        });

        emit BookRegistered(bookId, title, msg.sender);
    }

    /**
     * @notice Emite (mint) um exemplar de licença para um comprador.
     * @dev Apenas a editora do livro pode mintar. Cada mint cria um ativo único.
     * @param bookId   ID do livro registrado
     * @param buyer    Endereço do comprador/proprietário inicial
     */
    function mintLicense(uint256 bookId, address buyer)
        external
        onlyPublisher(bookId)
        returns (uint256 licenseId)
    {
        require(books[bookId].active, "DLM: livro inativo");
        require(buyer != address(0), "DLM: comprador invalido");

        licenseId = _nextLicenseId++;
        licenses[licenseId] = License({
            bookId:      bookId,
            owner:       buyer,
            borrower:    address(0),
            borrowUntil: 0,
            exists:      true
        });

        books[bookId].totalCopies++;
        _bookLicenses[bookId].push(licenseId);
        _ownerLicenses[buyer].push(licenseId);

        emit LicenseMinted(licenseId, bookId, buyer);
    }

    // ─── Transferência (Revenda P2P) ─────────────────────────────────────────────

    /**
     * @notice Transfere a posse de uma licença (revenda). 
     * @dev A regra 1-para-1 é garantida: o vendedor PERDE acesso imediatamente.
     *      O royalty da editora é descontado do valor enviado (msg.value).
     * @param licenseId  ID da licença a transferir
     * @param to         Endereço do novo proprietário
     */
    function transferLicense(uint256 licenseId, address to)
        external
        payable
        licenseExists(licenseId)
        onlyOwner(licenseId)
    {
        require(to != address(0), "DLM: destinatario invalido");
        require(to != msg.sender, "DLM: auto-transferencia");
        require(licenses[licenseId].borrower == address(0), "DLM: licenca emprestada");

        uint256 bookId    = licenses[licenseId].bookId;
        uint256 salePrice = msg.value;

        // Calcula e distribui royalty para a editora
        if (salePrice > 0) {
            uint256 royalty = (salePrice * books[bookId].royaltyBps) / 10000;
            if (royalty > 0) {
                (bool ok,) = books[bookId].publisher.call{value: royalty}("");
                require(ok, "DLM: falha no royalty");
            }
            // Resto vai para o vendedor
            uint256 sellerAmount = salePrice - royalty;
            if (sellerAmount > 0) {
                (bool ok2,) = msg.sender.call{value: sellerAmount}("");
                require(ok2, "DLM: falha pagamento vendedor");
            }
        }

        // Revoga acesso do vendedor; concede ao comprador
        licenses[licenseId].owner = to;
        _ownerLicenses[to].push(licenseId);

        emit LicenseTransferred(licenseId, msg.sender, to, salePrice);
    }

    // ─── Empréstimo Digital ──────────────────────────────────────────────────────

    /**
     * @notice Empresta temporariamente uma licença.
     * @param licenseId  ID da licença
     * @param borrower   Endereço do tomador
     * @param duration   Duração em segundos
     */
    function lendLicense(uint256 licenseId, address borrower, uint256 duration)
        external
        licenseExists(licenseId)
        onlyOwner(licenseId)
    {
        require(borrower != address(0), "DLM: tomador invalido");
        require(borrower != msg.sender, "DLM: auto-emprestimo");
        require(licenses[licenseId].borrower == address(0), "DLM: ja emprestado");
        require(duration > 0 && duration <= 30 days, "DLM: duracao invalida");

        uint256 until = block.timestamp + duration;
        licenses[licenseId].borrower    = borrower;
        licenses[licenseId].borrowUntil = until;

        emit LicenseLent(licenseId, borrower, until);
    }

    /**
     * @notice Devolve uma licença emprestada (pode ser chamado pelo dono ou tomador).
     */
    function returnLicense(uint256 licenseId)
        external
        licenseExists(licenseId)
    {
        License storage lic = licenses[licenseId];
        require(
            msg.sender == lic.owner || msg.sender == lic.borrower,
            "DLM: nao autorizado"
        );
        require(lic.borrower != address(0), "DLM: nao emprestado");

        address oldBorrower     = lic.borrower;
        lic.borrower    = address(0);
        lic.borrowUntil = 0;

        emit LicenseReturned(licenseId, oldBorrower);
    }

    // ─── Oráculo de Autenticação (leitura on-chain) ──────────────────────────────

    /**
     * @notice Valida se um endereço tem acesso a uma licença neste momento.
     * @dev Este é o endpoint central chamado pelo servidor de autenticação (oráculo).
     *      Retorna true se: (a) o endereço é dono E não está emprestado, OU
     *                       (b) o endereço é tomador E empréstimo ainda é válido.
     * @param licenseId  ID da licença
     * @param requester  Endereço que solicita acesso
     * @return granted   true se acesso concedido
     */
    function validateAccess(uint256 licenseId, address requester)
        external
        licenseExists(licenseId)
        returns (bool granted)
    {
        License storage lic = licenses[licenseId];

        // Empréstimo expirado — limpa automaticamente
        if (lic.borrower != address(0) && block.timestamp > lic.borrowUntil) {
            emit LicenseReturned(licenseId, lic.borrower);
            lic.borrower    = address(0);
            lic.borrowUntil = 0;
        }

        if (lic.borrower == address(0)) {
            // Sem empréstimo ativo: somente o dono tem acesso
            granted = (lic.owner == requester);
        } else {
            // Com empréstimo ativo: somente o tomador tem acesso
            granted = (lic.borrower == requester);
        }

        emit AccessValidated(licenseId, requester, granted);
    }

    /**
     * @notice Versão view (sem gas) para consultas off-chain rápidas.
     */
    function checkAccess(uint256 licenseId, address requester)
        external
        view
        licenseExists(licenseId)
        returns (bool granted)
    {
        License storage lic = licenses[licenseId];
        bool loanExpired = (lic.borrower != address(0) && block.timestamp > lic.borrowUntil);

        if (lic.borrower == address(0) || loanExpired) {
            granted = (lic.owner == requester);
        } else {
            granted = (lic.borrower == requester);
        }
    }

    // ─── Consultas ────────────────────────────────────────────────────────────────

    function getLicensesByOwner(address owner) external view returns (uint256[] memory) {
        return _ownerLicenses[owner];
    }

    function getLicensesByBook(uint256 bookId) external view returns (uint256[] memory) {
        return _bookLicenses[bookId];
    }

    function getLicenseInfo(uint256 licenseId)
        external
        view
        licenseExists(licenseId)
        returns (
            uint256 bookId,
            address owner,
            address borrower,
            uint256 borrowUntil,
            bool    isLoanActive
        )
    {
        License storage lic = licenses[licenseId];
        bookId      = lic.bookId;
        owner       = lic.owner;
        borrower    = lic.borrower;
        borrowUntil = lic.borrowUntil;
        isLoanActive = (lic.borrower != address(0) && block.timestamp <= lic.borrowUntil);
    }

    // ─── Admin ────────────────────────────────────────────────────────────────────

    function deactivateBook(uint256 bookId) external onlyAdmin {
        books[bookId].active = false;
    }

    function transferAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "DLM: admin invalido");
        admin = newAdmin;
    }
}
