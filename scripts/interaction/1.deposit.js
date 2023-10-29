'use strict';

// Imports.
const { ethers } = require('hardhat');
import HashTree from '../HashTree';

const fs = require('fs')
import * as crypto from 'crypto'
import { buildMimcSponge } from 'circomlibjs';
let mimcsponge;

const value = process.env.ETH_AMOUNT

const hexStringify = function (n) {
	return ethers.BigNumber.from(n).toHexString();
}

async function generateCommitment() {
    const mimc = await buildMimcSponge();
    const nullifier = ethers.BigNumber.from(crypto.randomBytes(31)).toString()
    const secret = ethers.BigNumber.from(crypto.randomBytes(31)).toString()
    const commitment = mimc.F.toString(mimc.multiHash([nullifier, secret]))
    const nullifierHash = mimc.F.toString(mimc.multiHash([nullifier]))
    
	return {
        nullifier: nullifier,
        secret: secret,
        commitment: commitment,
        nullifierHash: nullifierHash
    }
}
// let tree = new MerkleTree(levels)

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

	const GOVERNMENT_CHEESE_ADDRESS = '0xE5db16CC0Cefbd94e80B39c8218D29b6C8CD8467';
	const GovernmentCheese = await ethers.getContractFactory("GovernmentCheeseETH");
	const governmentCheese = await GovernmentCheese.attach(GOVERNMENT_CHEESE_ADDRESS);

	// build the privilege hash tree
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

	// begin deposit
	let callerIndex = distribution.getIndex(deployer.address);
	let privproof = distribution.getProof(callerIndex)

	const deposit = await generateCommitment();
	// tree.insert(deposit.commitment)

	let depositTx = await governmentCheese.connect(deployer.signer).deposit(
		hexStringify(deposit.commitment), 
		callerIndex,
		1,
		privproof,
		{ value }
	)
	await depositTx.wait();

	let timestamp = Math.floor(Date.now() / 1000);
	console.log(`Writing commitment ${timestamp} ...`);
	fs.writeFileSync(`./scripts/interaction/commitments/commitmentHash-${timestamp}.json`, JSON.stringify(
			{
				commitmentHash: {
					commitment: ethers.BigNumber.from(deposit.commitment).toHexString(),
					nullifier: ethers.BigNumber.from(deposit.nullifier).toHexString(),
					secret: ethers.BigNumber.from(deposit.secret).toHexString()
				}
			},
			null,
			2
		)
	);
}

// Execute the script and catch errors.
main()
	.then(() => process.exit(0))
	.catch(error => {
		console.error(error);
		process.exit(1);
	});