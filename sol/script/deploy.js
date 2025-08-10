// scripts/deploy.js
const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  
  console.log("Deploying contracts with:", deployer.address);

  // Deploy ProofAnchor
  const ProofAnchor = await ethers.getContractFactory("ProofAnchor");
  const proofAnchor = await ProofAnchor.deploy();
  await proofAnchor.deployed();

  // Deploy FragmentVault
  const FragmentVault = await ethers.getContractFactory("FragmentVault");
  const fragmentVault = await FragmentVault.deploy();
  await fragmentVault.deployed();

  // Deploy AnomalyOracle
  const AnomalyOracle = await ethers.getContractFactory("AnomalyOracle");
  const anomalyOracle = await AnomalyOracle.deploy();
  await anomalyOracle.deployed();

  console.log("ProofAnchor deployed to:", proofAnchor.address);
  console.log("FragmentVault deployed to:", fragmentVault.address);
  console.log("AnomalyOracle deployed to:", anomalyOracle.address);

  // Setup permissions
  await proofAnchor.grantRole(proofAnchor.PROVER_ROLE(), fragmentVault.address);
  await fragmentVault.transferOwnership(anomalyOracle.address);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});