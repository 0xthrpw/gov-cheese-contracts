const { ethers } = require('hardhat')
import { expect } from 'chai';

import path from "path";
import * as snarkjs from 'snarkjs';
import { buildBabyjub, buildPedersenHash, buildMimcSponge } from 'circomlibjs';

// import MerkleTree from '../utils/merkleTree'
import MerkleTree from 'fixed-merkle-tree';
import HashTree from '../scripts/HashTree';

const crypto = require('crypto')

const { ETH_AMOUNT, MERKLE_TREE_HEIGHT } = process.env
let babyJub, pedersenHash, mimcsponge;


function p256(n) {
	return ethers.BigNumber.from(n).toHexString();
}

const toFixedHex = (number, length = 32) =>
	ethers.utils.hexZeroPad(ethers.BigNumber.from(number), length)

// const createPedersenHash = (data) => babyJub.unpackPoint(pedersenHash.hash(data))[0]
const createPedersenHash = (data) => babyJub.unpackPoint(pedersenHash.hash(data))[0]

const rbigint =  (nbytes) => ethers.BigNumber.from(crypto.randomBytes(nbytes)); 
const getRandomRecipient = () => rbigint(20)
function generateDeposit() {
	let secretBuffer = crypto.randomBytes(31);
	let nullfierBuffer = crypto.randomBytes(31);
	let deposit = {
		secret: ethers.BigNumber.from(secretBuffer).toString(),
		nullifier: ethers.BigNumber.from(nullfierBuffer).toString(),
		nullfierBuffer
	}
	// const preimage = ethers.utils.concat([nullfierBuffer, secretBuffer]);
	const preimage = Buffer.concat([nullfierBuffer, secretBuffer])
	deposit.commitment = createPedersenHash(preimage)
	return deposit

	// let secretBuffer = ethers.BigNumber.from(crypto.randomBytes(31)).toString();
	// let nullfierBuffer = ethers.BigNumber.from(crypto.randomBytes(31)).toString();
	
	// const commitment = mimcsponge.multiHash([nullfierBuffer, secretBuffer])
	// 		// console.log({result})
	// 		// return ethers.BigNumber.from(result).toString()
	// const formattedCommitment = mimcsponge.F.toString(commitment);
	// let deposit = {
	// 	secret: secretBuffer,
	// 	nullifier: nullfierBuffer,
	// 	commitment: formattedCommitment
	// }
	// return deposit;
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

describe('GC Testing General', () => {

	const levels = MERKLE_TREE_HEIGHT || 20
	const value = ETH_AMOUNT || '1000000000000000000' // 1 ether
	const recipient = getRandomRecipient()
	const fee = ethers.BigNumber.from(ETH_AMOUNT).shr(1) || ethers.BigNumber.from(1e17)
	const refund = ethers.BigNumber.from(0)

	let signers, addresses, admin, relayer, privUser, unprivilegedUser;
	let verifier, hasher, governmentCheese, GovernmentCheeseETH;
	let tree, distribution;

	before(async () => {
		signers = await ethers.getSigners();
		addresses = await Promise.all(
			signers.map(async signer => signer.getAddress())
		);
		admin = {
			provider: signers[0].provider,
			signer: signers[0],
			address: addresses[0]
		};

		relayer = {
			provider: signers[1].provider,
			signer: signers[1],
			address: addresses[1]
		}

		privUser = {
			provider: signers[4].provider,
			signer: signers[4],
			address: addresses[4]
		}

		unprivilegedUser = {
			provider: signers[9].provider,
			signer: signers[9],
			address: addresses[9]
		}

		const Verifier = await ethers.getContractFactory('Groth16Verifier');
		verifier = await Verifier.connect(admin.signer).deploy();

		let hasherCompiled = require('../build/Hasher.json');
		let Hasher = new ethers.ContractFactory(
			hasherCompiled.abi,
			hasherCompiled.bytecode
		);
		hasher = await Hasher.connect(admin.signer).deploy();

		GovernmentCheeseETH = await ethers.getContractFactory('GovernmentCheeseETH');
		governmentCheese = await GovernmentCheeseETH.connect(admin.signer).deploy(
			verifier.address, 
			hasher.address, 
			value,
			levels
		);

		/// snarks
		babyJub = await buildBabyjub();
		pedersenHash = await buildPedersenHash();
		mimcsponge  = await buildMimcSponge();
		const hashFunction = (left, right) => {
			const result = mimcsponge.multiHash([left, right])
			// console.log({result})
			// return ethers.BigNumber.from(result).toString()
			const formatted = mimcsponge.F.toString(result);
			// console.log({formatted: ethers.BigNumber.from(formatted).toHexString()});
			return formatted;
		}
		const ZERO_ELEMENT = await governmentCheese.ZERO_VALUE();
		const treeOptions = {
			hashFunction: hashFunction,
			zeroElement: ZERO_ELEMENT.toString()
		}
		tree = new MerkleTree(levels, [], treeOptions)			

		/// privileges
		let balances = { };
		let recipients = [
		  '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
		  '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
		  '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC',
		  '0x90F79bf6EB2c4f870365E785982E1f101E93b906',
		  '0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65'
		];
		for (let i = 0; i < recipients.length; i++) {
		  balances[recipients[i].toLowerCase()] = 1;
		}
		distribution = new HashTree(balances);

		await governmentCheese.connect(admin.signer).updateRoot(distribution.rootHash);
	});

	context('Zero Hashes', async function() {
		it('default tree verification', async () => {

			/// deposit
			const deposit = await generateCommitment()
			// console.log(deposit, toFixedHex(deposit.commitment), ethers.BigNumber.from(deposit.commitment).toString());

			tree.insert(deposit.commitment)

			let callerIndex = distribution.getIndex(privUser.address);
			let privproof = distribution.getProof(callerIndex)
			
			let depositTx = await governmentCheese.connect(privUser.signer).deposit(
				// toFixedHex(deposit.commitment), 
				ethers.BigNumber.from(deposit.commitment).toHexString(),
				callerIndex,
				1,
				privproof,
				{ value }
			)
			let depositReceipt = await depositTx.wait();

			/// withdrawal
			const nextIndex = await governmentCheese.nextIndex();
			const lastDepositIndex = nextIndex - 1

			const { pathElements, pathIndices } = tree.path(lastDepositIndex)
			// const { pathElements, pathIndices } = tree.path(0)
		// console.log("tree path", tree.path(0));
			const wasmPath = path.join(process.cwd(), 'circuits/build/withdraw_js/withdraw.wasm');
			const provingKeyPath = path.join(process.cwd(), 'circuits/build/proving_key.zkey')
			
			// const nullHash = mimcsponge.multiHash([deposit.nullifier.toString()])
			// // console.log({result})
			// // return ethers.BigNumber.from(result).toString()
			// const formattedNullHash = mimcsponge.F.toString(nullHash);

			const inputs =  {
				root: tree.root,
				// nullifierHash: ethers.BigNumber.from(createPedersenHash(deposit.nullfierBuffer)).toString(),
				// nullifierHash: formattedNullHash,
				nullifierHash: deposit.nullifierHash,
				relayer: 0,
				recipient: recipient.toString(),
				fee: fee.toString(),
				refund: refund.toString(),

				// nullifier: ethers.BigNumber.from(deposit.nullifier).toString(),
				nullifier: deposit.nullifier,
				// secret: ethers.BigNumber.from(deposit.secret).toString(),
				secret: deposit.secret,
				pathElements: pathElements,
				pathIndices: pathIndices,
			};
		
			// console.log("hex translated", ethers.BigNumber.from(createPedersenHash(deposit.nullifier.toString())).toString())

			const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, wasmPath, provingKeyPath);
// console.log({proof, publicSignals})
			// const converted = proof;
			// console.log("converted", converted);

			let pInputs = "";
			for (let i=0; i<publicSignals.length; i++) {
				if (pInputs != "") pInputs = pInputs + ",";
				pInputs = pInputs + p256(publicSignals[i]);
			}

			const output = {
				pi_A: [ p256(proof.pi_a[0]), p256(proof.pi_a[1]) ],
				pi_B: [
					[p256(proof.pi_b[0][1]), p256(proof.pi_b[0][0])],
					[p256(proof.pi_b[1][1]), p256(proof.pi_b[1][0])]
				],
				pi_C: [ p256(proof.pi_c[0]), p256(proof.pi_c[1]) ],
				publicInputs: [ pInputs ]

			}

			console.log("output", output);

			// // call contract to verify proof
			// const proofResultTx = await simpleMultiplier.submitProof(
			// 	output.pi_A,
			// 	output.pi_B,
			// 	output.pi_C,
			// 	output.publicInputs
			// );
			// const proofResult = await proofResultTx.wait();
			// console.log("proof validation", proofResult.events[0].args.result);
		})
		
		it('change keyword for zero hash', async () => {

		})

	})

});