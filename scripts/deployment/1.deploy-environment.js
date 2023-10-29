'use strict';

// Imports.
const { ethers } = require('hardhat');
import HashTree from '../HashTree';

async function logTransactionGas(transaction) {
	let transactionReceipt = await transaction.wait();
	let transactionGasCost = transactionReceipt.gasUsed;
	console.log(` -> Gas cost: ${transactionGasCost.toString()}`);
	return transactionGasCost;
}

async function main() {
	const signers = await ethers.getSigners();
	const addresses = await Promise.all(
		signers.map(async signer => signer.getAddress())
	);
	const deployer = {
		provider: signers[0].provider,
		signer: signers[0],
		address: addresses[0]
	};
	console.log(`Operator: ${deployer.address}`);

	const { ETH_AMOUNT, MERKLE_TREE_HEIGHT } = process.env

	let totalGasCost = ethers.utils.parseEther('0');

	const Verifier = await ethers.getContractFactory('Groth16Verifier');
	const verifier = await Verifier.connect(deployer.signer).deploy();
	let verifierDeployed = await verifier.deployed();

	console.log('');
	console.log(`* Verifier deployed to: ${verifier.address}`);
	totalGasCost = totalGasCost.add(
		await logTransactionGas(verifierDeployed.deployTransaction)
	);

	console.log(`[VERIFY] npx hardhat verify --network goerli ${verifier.address}`);

	let hasherCompiled = require('../../build/Hasher.json');
	let Hasher = new ethers.ContractFactory(
		hasherCompiled.abi,
		hasherCompiled.bytecode
	);
	const hasher = await Hasher.connect(deployer.signer).deploy();
	let hasherDeployed = await hasher.deployed();

	console.log('');
	console.log(`* Hasher deployed to: ${hasher.address}`);
	totalGasCost = totalGasCost.add(
		await logTransactionGas(hasherDeployed.deployTransaction)
	);

	console.log(`[VERIFY] npx hardhat verify --network goerli ${hasher.address}`);

	const GovernmentCheeseETH = await ethers.getContractFactory('GovernmentCheeseETH');
	const governmentCheese = await GovernmentCheeseETH.connect(deployer.signer).deploy(
		verifier.address, 
		hasher.address, 
		ETH_AMOUNT,
		MERKLE_TREE_HEIGHT
	);
	let governmentCheeseDeployed = await governmentCheese.deployed();

	console.log('');
	console.log(`* GovernmentCheese deployed to: ${governmentCheese.address}`);
	totalGasCost = totalGasCost.add(
		await logTransactionGas(governmentCheeseDeployed.deployTransaction)
	);

	console.log(`[VERIFY] npx hardhat verify --network goerli \
	${governmentCheese.address} ${verifier.address} ${hasher.address} \
	${ETH_AMOUNT} ${MERKLE_TREE_HEIGHT}`);

	// generate hash tree for testing
	let balances = { };
	let recipients = [
		'0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
		'0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
		'0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC',
		'0x90F79bf6EB2c4f870365E785982E1f101E93b906',
		'0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65',
		'0x2425124064f82bf68c6844fec4515b071d4b821a',
		'0xA374a008F63494c4530695eeEbD93f9bb94E7320'
	];
	for (let i = 0; i < recipients.length; i++) {
		balances[recipients[i].toLowerCase()] = 1;
	}
	const distribution = new HashTree(balances);

	const updateRootTx = await governmentCheese.connect(deployer.signer).updateRoot(
		distribution.rootHash
	);

	console.log('');
	console.log(`* Privilege root hash set successfully`);
	totalGasCost = totalGasCost.add(
		await logTransactionGas(updateRootTx)
	);

	console.log('');
	console.log(`=> Final gas cost of deployment: ${totalGasCost.toString()}`);
}

// Execute the script and catch errors.
main()
  .then(() => process.exit(0))
  .catch(error => {
    console.error(error);
    process.exit(1);
  });