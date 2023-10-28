const { ethers } = require('hardhat')
import { expect } from 'chai';

import path from "path";
import * as snarkjs from 'snarkjs';
import { buildMimcSponge } from 'circomlibjs';

// import MerkleTree from '../utils/merkleTree'
import MerkleTree from 'fixed-merkle-tree';
import HashTree from '../scripts/HashTree';

const crypto = require('crypto')

const { ETH_AMOUNT, MERKLE_TREE_HEIGHT } = process.env
let mimcsponge;

function p256(n) {
	return ethers.BigNumber.from(n).toHexString();
}

const rbigint =  (nbytes) => ethers.BigNumber.from(crypto.randomBytes(nbytes)); 
const getRandomRecipient = () => rbigint(20)

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
		mimcsponge  = await buildMimcSponge();
		const hashFunction = (left, right) => {
			const result = mimcsponge.multiHash([left, right])
			const formatted = mimcsponge.F.toString(result);
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
			tree.insert(deposit.commitment)

			let callerIndex = distribution.getIndex(privUser.address);
			let privproof = distribution.getProof(callerIndex)
			
			let depositTx = await governmentCheese.connect(privUser.signer).deposit(
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

			const inputs =  {
				root: tree.root,
				nullifierHash: deposit.nullifierHash,
				relayer: ethers.constants.AddressZero,
				recipient: recipient.toString(),
				fee: fee.toString(),
				refund: ethers.constants.HashZero,

				nullifier: deposit.nullifier,
				secret: deposit.secret,
				pathElements: pathElements,
				pathIndices: pathIndices,
			};

			const wasmPath = path.join(process.cwd(), 'circuits/build/withdraw_js/withdraw.wasm');
			const provingKeyPath = path.join(process.cwd(), 'circuits/build/proving_key.zkey')
			
			const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, wasmPath, provingKeyPath);

			const output = {
				pi_A: [ p256(proof.pi_a[0]), p256(proof.pi_a[1]) ],
				pi_B: [
					[p256(proof.pi_b[0][1]), p256(proof.pi_b[0][0])],
					[p256(proof.pi_b[1][1]), p256(proof.pi_b[1][0])]
				],
				pi_C: [ p256(proof.pi_c[0]), p256(proof.pi_c[1]) ]
			}
			
			console.log("output", output);
			
			const args = [
				ethers.BigNumber.from(publicSignals[0]).toHexString(), //root
				ethers.BigNumber.from(publicSignals[1]).toHexString(), //nullHash
				ethers.BigNumber.from(publicSignals[2]).toHexString(), //recip
				inputs.relayer, //relayer
				ethers.BigNumber.from(publicSignals[4]).toHexString(), //fee
				inputs.refund  //refund
			]
			console.log("publicSignals", args);
			let withdrawCallerIndex = distribution.getIndex(admin.address);
			let withdrawPrivproof = distribution.getProof(withdrawCallerIndex)

			let withdrawTx = await governmentCheese.connect(admin.signer).withdraw(
				output, 
				...args,
				withdrawCallerIndex,
				1,
				withdrawPrivproof
			)
		})
		
		it('change keyword for zero hash', async () => {

		})

	})

});