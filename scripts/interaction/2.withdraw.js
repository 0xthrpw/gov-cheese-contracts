'use strict';

// Imports.
const { ethers } = require('hardhat');
const fs = require("fs");
require('dotenv').config();
import HashTree from '../HashTree';
import axios from 'axios';
import path from "path";

import { buildMimcSponge } from 'circomlibjs';
import * as snarkjs from 'snarkjs';

const wasmPath = path.join(process.cwd(), 'circuits/build/withdraw_js/withdraw.wasm');
const provingKeyPath = path.join(process.cwd(), 'circuits/build/proving_key.zkey')

const commitmentHash = '0x16113a2ed43787b50846e506382a8dd9dc596aabe3cf1d37558072d44d7f89ff';
const nullifier = '0x334cb55ef0610c9a3150917b2dec5c8156c849413200a4e9da79204598c2fe';
const secret = '0xa4b025055dc96b5928c4e57b4bd7ab0d1111315c0519d710cea67106b59a8c';

const hexStringify = function (n) {
	return ethers.BigNumber.from(n).toHexString();
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

	let callerIndex = distribution.getIndex(deployer.address);
	let privproof = distribution.getProof(callerIndex)

	// call the indexer to get tree data
	let response, root, index, elements, indices;
	try {
		response = await axios.get(`${process.env.INDEXER_URL}/getPath/${commitmentHash}`);
		// console.log(response);
	} catch (error) {
		console.error(error);
	}
	// if call successful then build proof
	if(response){
		root = response.data.root;
		index = response.data.index;
		elements = response.data.elements;
		indices = response.data.indices;
	}else{
		console.log("ERROR BAD RESPONSE");
	}

	const mimc = await buildMimcSponge();
	const commitmentHex = mimc.F.toString(mimc.multiHash([nullifier, secret]));
	const nullifierHash = mimc.F.toString(mimc.multiHash([nullifier]));

	const inputs =  {
		root: root,
		nullifierHash: nullifierHash,
		relayer: ethers.constants.AddressZero,
		recipient: deployer.address,
		fee: ethers.constants.HashZero,
		refund: ethers.constants.HashZero,

		nullifier: nullifier,
		secret: secret,
		pathElements: elements,
		pathIndices: indices,
	};
	const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, wasmPath, provingKeyPath);
	
	const output = {
		pi_A: [ hexStringify(proof.pi_a[0]), hexStringify(proof.pi_a[1]) ],
		pi_B: [
			[hexStringify(proof.pi_b[0][1]), hexStringify(proof.pi_b[0][0])],
			[hexStringify(proof.pi_b[1][1]), hexStringify(proof.pi_b[1][0])]
		],
		pi_C: [ hexStringify(proof.pi_c[0]), hexStringify(proof.pi_c[1]) ]
	}

	const args = [
		hexStringify(publicSignals[0]), //root
		hexStringify(publicSignals[1]), //nullHash
		hexStringify(publicSignals[2]), //recip
		inputs.relayer, //relayer
		hexStringify(publicSignals[4]), //fee
		inputs.refund  //refund
	]

	console.log('tx submitted...');
	let withdrawTx = await governmentCheese.withdraw(
		output, 
		...args,
		callerIndex,
		1,
		privproof
	)

	let withdrawReceipt = await withdrawTx.wait();
	console.log("tx receipt", withdrawReceipt);
}


// Execute the script and catch errors.
main()
	.then(() => process.exit(0))
	.catch(error => {
		console.error(error);
		process.exit(1);
	});