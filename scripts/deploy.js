/**
 * scripts/deploy.js
 * Script de deploy do contrato DLMPDFLicense via Hardhat.
 *
 * Uso:
 *   npx hardhat run scripts/deploy.js --network localhost
 *   npx hardhat run scripts/deploy.js --network sepolia
 */

const { ethers } = require("hardhat");
const fs         = require("fs");
const path       = require("path");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log(`\n🚀 Iniciando deploy com a conta: ${deployer.address}`);

  const balance = await ethers.provider.getBalance(deployer.address);
  console.log(`   Saldo: ${ethers.formatEther(balance)} ETH`);

  // Deploy
  console.log("\n📄 Compilando e fazendo deploy de DLMPDFLicense...");
  const DLMPDFLicense = await ethers.getContractFactory("DLMPDFLicense");
  const contract      = await DLMPDFLicense.deploy();
  await contract.waitForDeployment();

  const address = await contract.getAddress();
  console.log(`✅ Contrato deployado em: ${address}`);

  // Persiste o endereço em um arquivo JSON para uso pelo servidor
  const deployInfo = {
    address,
    network:   (await ethers.provider.getNetwork()).name,
    chainId:   (await ethers.provider.getNetwork()).chainId.toString(),
    deployer:  deployer.address,
    timestamp: new Date().toISOString(),
  };

  const outPath = path.join(__dirname, "../server/.contract-address.json");
  fs.writeFileSync(outPath, JSON.stringify(deployInfo, null, 2));
  console.log(`📁 Endereço salvo em: ${outPath}`);

  // Registra um livro de exemplo
  console.log("\n📚 Registrando livro de exemplo...");
  const contentHash = ethers.encodeBytes32String("exemplo-hash-sha256");
  const tx = await contract.registerBook(
    "O Senhor dos Anéis",
    "J.R.R. Tolkien",
    contentHash,
    500 // 5% de royalty
  );
  await tx.wait();
  console.log("✅ Livro de exemplo registrado (bookId=1).");

  console.log("\n─────────────────────────────────────────────");
  console.log("Atualize o .env do servidor:");
  console.log(`CONTRACT_ADDRESS=${address}`);
  console.log("─────────────────────────────────────────────\n");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
