/**
 * test/DLMPDFLicense.test.js
 * Testes do Smart Contract usando Hardhat + Chai.
 *
 * Executar: npx hardhat test
 */

const { expect }        = require("chai");
const { ethers }        = require("hardhat");
const { loadFixture }   = require("@nomicfoundation/hardhat-toolbox/network-helpers");

describe("DLMPDFLicense", function () {
  // ─── Fixture ────────────────────────────────────────────────────────────────
  async function deployFixture() {
    const [admin, publisher, buyer1, buyer2, borrower] = await ethers.getSigners();

    const DLMPDFLicense = await ethers.getContractFactory("DLMPDFLicense");
    const contract      = await DLMPDFLicense.deploy();

    // Registra um livro como publisher
    const contentHash = ethers.encodeBytes32String("sha256-test-hash");
    await contract.connect(publisher).registerBook(
      "Livro Teste",
      "Autor Teste",
      contentHash,
      500 // 5%
    );
    const bookId = 1n;

    return { contract, admin, publisher, buyer1, buyer2, borrower, bookId };
  }

  // ─── Registro de Livro ───────────────────────────────────────────────────────
  describe("registerBook", function () {
    it("deve registrar um livro e emitir BookRegistered", async function () {
      const { contract, publisher } = await loadFixture(deployFixture);
      const hash = ethers.encodeBytes32String("outro-hash");

      await expect(contract.connect(publisher).registerBook("Livro 2", "Autor 2", hash, 300))
        .to.emit(contract, "BookRegistered")
        .withArgs(2n, "Livro 2", publisher.address);
    });

    it("deve rejeitar royalty acima de 30%", async function () {
      const { contract, publisher } = await loadFixture(deployFixture);
      const hash = ethers.encodeBytes32String("hash3");

      await expect(
        contract.connect(publisher).registerBook("Livro 3", "Autor", hash, 3001)
      ).to.be.revertedWith("DLM: royalty max 30%");
    });
  });

  // ─── Mint de Licença ─────────────────────────────────────────────────────────
  describe("mintLicense", function () {
    it("deve emitir uma licença para o comprador", async function () {
      const { contract, publisher, buyer1, bookId } = await loadFixture(deployFixture);

      await expect(contract.connect(publisher).mintLicense(bookId, buyer1.address))
        .to.emit(contract, "LicenseMinted")
        .withArgs(1n, bookId, buyer1.address);

      const info = await contract.getLicenseInfo(1n);
      expect(info.owner).to.equal(buyer1.address);
    });

    it("apenas a editora pode mintar", async function () {
      const { contract, buyer1, buyer2, bookId } = await loadFixture(deployFixture);
      await expect(
        contract.connect(buyer1).mintLicense(bookId, buyer2.address)
      ).to.be.revertedWith("DLM: somente a editora");
    });
  });

  // ─── Oráculo de Acesso ────────────────────────────────────────────────────────
  describe("checkAccess / validateAccess", function () {
    it("dono deve ter acesso", async function () {
      const { contract, publisher, buyer1, bookId } = await loadFixture(deployFixture);
      await contract.connect(publisher).mintLicense(bookId, buyer1.address);

      expect(await contract.checkAccess(1n, buyer1.address)).to.be.true;
    });

    it("não-dono não deve ter acesso", async function () {
      const { contract, publisher, buyer1, buyer2, bookId } = await loadFixture(deployFixture);
      await contract.connect(publisher).mintLicense(bookId, buyer1.address);

      expect(await contract.checkAccess(1n, buyer2.address)).to.be.false;
    });
  });

  // ─── Transferência (Revenda) ──────────────────────────────────────────────────
  describe("transferLicense", function () {
    it("deve transferir posse e revogar acesso do vendedor", async function () {
      const { contract, publisher, buyer1, buyer2, bookId } = await loadFixture(deployFixture);
      await contract.connect(publisher).mintLicense(bookId, buyer1.address);

      // Antes: buyer1 tem acesso
      expect(await contract.checkAccess(1n, buyer1.address)).to.be.true;

      // Transfere (revenda por 0 ETH)
      await contract.connect(buyer1).transferLicense(1n, buyer2.address);

      // Depois: buyer1 perde acesso, buyer2 tem acesso
      expect(await contract.checkAccess(1n, buyer1.address)).to.be.false;
      expect(await contract.checkAccess(1n, buyer2.address)).to.be.true;
    });

    it("deve distribuir royalty para a editora", async function () {
      const { contract, publisher, buyer1, buyer2, bookId } = await loadFixture(deployFixture);
      await contract.connect(publisher).mintLicense(bookId, buyer1.address);

      const salePrice     = ethers.parseEther("1.0");
      const publisherBefore = await ethers.provider.getBalance(publisher.address);

      await contract.connect(buyer1).transferLicense(1n, buyer2.address, { value: salePrice });

      const publisherAfter = await ethers.provider.getBalance(publisher.address);
      const royaltyExpected = salePrice * 500n / 10000n; // 5%

      expect(publisherAfter - publisherBefore).to.equal(royaltyExpected);
    });

    it("não deve transferir licença emprestada", async function () {
      const { contract, publisher, buyer1, buyer2, borrower, bookId } = await loadFixture(deployFixture);
      await contract.connect(publisher).mintLicense(bookId, buyer1.address);
      await contract.connect(buyer1).lendLicense(1n, borrower.address, 3600);

      await expect(
        contract.connect(buyer1).transferLicense(1n, buyer2.address)
      ).to.be.revertedWith("DLM: licenca emprestada");
    });
  });

  // ─── Empréstimo ───────────────────────────────────────────────────────────────
  describe("lendLicense / returnLicense", function () {
    it("durante empréstimo: tomador tem acesso, dono não tem", async function () {
      const { contract, publisher, buyer1, borrower, bookId } = await loadFixture(deployFixture);
      await contract.connect(publisher).mintLicense(bookId, buyer1.address);
      await contract.connect(buyer1).lendLicense(1n, borrower.address, 3600);

      expect(await contract.checkAccess(1n, buyer1.address)).to.be.false;
      expect(await contract.checkAccess(1n, borrower.address)).to.be.true;
    });

    it("após devolução: dono recupera acesso", async function () {
      const { contract, publisher, buyer1, borrower, bookId } = await loadFixture(deployFixture);
      await contract.connect(publisher).mintLicense(bookId, buyer1.address);
      await contract.connect(buyer1).lendLicense(1n, borrower.address, 3600);
      await contract.connect(borrower).returnLicense(1n);

      expect(await contract.checkAccess(1n, buyer1.address)).to.be.true;
      expect(await contract.checkAccess(1n, borrower.address)).to.be.false;
    });

    it("deve rejeitar empréstimo com duração inválida (> 30 dias)", async function () {
      const { contract, publisher, buyer1, borrower, bookId } = await loadFixture(deployFixture);
      await contract.connect(publisher).mintLicense(bookId, buyer1.address);

      await expect(
        contract.connect(buyer1).lendLicense(1n, borrower.address, 31 * 24 * 3600)
      ).to.be.revertedWith("DLM: duracao invalida");
    });
  });

  // ─── Consultas ────────────────────────────────────────────────────────────────
  describe("getLicensesByOwner", function () {
    it("deve retornar todos os licenseIds do proprietário", async function () {
      const { contract, publisher, buyer1, bookId } = await loadFixture(deployFixture);
      await contract.connect(publisher).mintLicense(bookId, buyer1.address);
      await contract.connect(publisher).mintLicense(bookId, buyer1.address);

      const ids = await contract.getLicensesByOwner(buyer1.address);
      expect(ids.length).to.equal(2);
    });
  });
});
