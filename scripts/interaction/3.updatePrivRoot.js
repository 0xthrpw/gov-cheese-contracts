'use strict';

// Imports.
const { ethers } = require('hardhat');
const fs = require('fs')
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

	let totalGasCost = ethers.utils.parseEther('0');

	const GOVERNMENT_CHEESE_ADDRESS = '0xE5db16CC0Cefbd94e80B39c8218D29b6C8CD8467';
	const GovernmentCheese = await ethers.getContractFactory("GovernmentCheeseETH");
	const governmentCheese = await GovernmentCheese.attach(GOVERNMENT_CHEESE_ADDRESS);

	let userSet = [];
	let allowedUsers = [];
	const whitelistInfo = fs.readFileSync('./priv/masterwhitelist', 'utf-8');
	whitelistInfo.split(/\r?\n/).forEach(function (address) {
		if (address.length > 0) {
			// Sanitize addresses.
			try {
				let sanitizedAddress = ethers.utils.getAddress(address);
				allowedUsers.push(sanitizedAddress);
			} catch (error) {
				console.error('malformed address', address, error);
			}
		}
	});

	// Convert the userSet array into a hash tree.
	for (let i = 0; i < allowedUsers.length; i++) {
		userSet[allowedUsers[i].toLowerCase()] = 1;
	}
	console.log('Constructing privilege hash tree ...');
	let distribution = new HashTree(userSet);

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