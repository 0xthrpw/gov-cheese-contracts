const { ethers } = require('hardhat')
import { expect } from 'chai';
const { should } = require('chai').should();

import path from "path";
import * as snarkjs from 'snarkjs';
import { buildMimcSponge } from 'circomlibjs';

// import MerkleTree from '../utils/merkleTree'
import MerkleTree from 'fixed-merkle-tree';
import HashTree from '../scripts/HashTree';

const crypto = require('crypto')

const { ETH_AMOUNT, MERKLE_TREE_HEIGHT } = process.env
let mimcsponge;

function hexStringify(n) {
	return ethers.BigNumber.from(n).toHexString();
}

const rbigint =  (nbytes) => ethers.BigNumber.from(crypto.randomBytes(nbytes)); 
const getRandomRecipient = () => rbigint(20)

async function generateCommitment () {
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

function formatSolidity (proof) {
	const output = {
		pi_A: [ hexStringify(proof.pi_a[0]), hexStringify(proof.pi_a[1]) ],
		pi_B: [
			[hexStringify(proof.pi_b[0][1]), hexStringify(proof.pi_b[0][0])],
			[hexStringify(proof.pi_b[1][1]), hexStringify(proof.pi_b[1][0])]
		],
		pi_C: [ hexStringify(proof.pi_c[0]), hexStringify(proof.pi_c[1]) ]
	}
	return output;
}

describe('GC Testing General', () => {

	const levels = MERKLE_TREE_HEIGHT || 20
	const value = ETH_AMOUNT || '1000000000000000000' // 1 ether
	const recipient = getRandomRecipient()
	const fee = ethers.BigNumber.from(ETH_AMOUNT).shr(1) || ethers.BigNumber.from(1e17)

	const wasmPath = path.join(process.cwd(), 'circuits/build/withdraw_js/withdraw.wasm');
	const provingKeyPath = path.join(process.cwd(), 'circuits/build/proving_key.zkey')
	
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

	context('GateKeeper', async function() {
		it('should revert deployment on bad denomination check', async () => {
			await expect(
				GovernmentCheeseETH.connect(admin.signer).deploy(
					verifier.address, 
					hasher.address, 
					0,
					levels
				)
			).to.be.revertedWith('denomination should be greater than 0');
		})

		it('should allow valid deposit', async () => {
			const deposit = await generateCommitment()
			tree.insert(deposit.commitment)

			let callerIndex = distribution.getIndex(privUser.address);
			let privproof = distribution.getProof(callerIndex)
			
			let depositTx = await governmentCheese.connect(privUser.signer).deposit(
				hexStringify(deposit.commitment),
				callerIndex,
				1,
				privproof,
				{ value }
			)
			let { events } = await depositTx.wait();
			events[0].event.should.be.equal('Deposit')
			events[0].args.commitment.should.be.equal(hexStringify(deposit.commitment))
			events[0].args.leafIndex.should.be.equal(0)
		})

		it('should allow valid deposit and withdrawal with proof', async () => {

			/// deposit
			const deposit = await generateCommitment()
			tree.insert(deposit.commitment)

			let callerIndex = distribution.getIndex(privUser.address);
			let privproof = distribution.getProof(callerIndex)
			
			let depositTx = await governmentCheese.connect(privUser.signer).deposit(
				hexStringify(deposit.commitment),
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

			const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, wasmPath, provingKeyPath);

			const proofCalldata = formatSolidity(proof);
			
			const args = [
				hexStringify(publicSignals[0]), //root
				hexStringify(publicSignals[1]), //nullHash
				hexStringify(publicSignals[2]), //recip
				inputs.relayer, //relayer
				hexStringify(publicSignals[4]), //fee
				inputs.refund  //refund
			]

			let withdrawCallerIndex = distribution.getIndex(admin.address);
			let withdrawPrivproof = distribution.getProof(withdrawCallerIndex)

			let withdrawTx = await governmentCheese.connect(admin.signer).withdraw(
				proofCalldata, 
				...args,
				withdrawCallerIndex,
				1,
				withdrawPrivproof
			)
		})
		
		it('should prevent double spend', async () => {

			/// deposit
			const deposit = await generateCommitment()
			tree.insert(deposit.commitment)

			let callerIndex = distribution.getIndex(privUser.address);
			let privproof = distribution.getProof(callerIndex)
			
			let depositTx = await governmentCheese.connect(privUser.signer).deposit(
				hexStringify(deposit.commitment),
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

			const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, wasmPath, provingKeyPath);

			const proofCalldata = formatSolidity(proof);
			
			const args = [
				hexStringify(publicSignals[0]), //root
				hexStringify(publicSignals[1]), //nullHash
				hexStringify(publicSignals[2]), //recip
				inputs.relayer, //relayer
				hexStringify(publicSignals[4]), //fee
				inputs.refund  //refund
			]

			let withdrawCallerIndex = distribution.getIndex(admin.address);
			let withdrawPrivproof = distribution.getProof(withdrawCallerIndex)

			expect(
				await governmentCheese.connect(admin.signer).withdraw(
					proofCalldata, 
					...args,
					withdrawCallerIndex,
					1,
					withdrawPrivproof
				)
			).to.be.ok

			await expect(
				governmentCheese.connect(admin.signer).withdraw(
					proofCalldata, 
					...args,
					withdrawCallerIndex,
					1,
					withdrawPrivproof
				)
			).to.be.revertedWith('The note has been already spent');
		})

		it('should prevent double spend with overflow', async () => {

			/// deposit
			const deposit = await generateCommitment()
			tree.insert(deposit.commitment)

			let callerIndex = distribution.getIndex(privUser.address);
			let privproof = distribution.getProof(callerIndex)
			
			let depositTx = await governmentCheese.connect(privUser.signer).deposit(
				hexStringify(deposit.commitment),
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

			const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, wasmPath, provingKeyPath);

			const proofCalldata = formatSolidity(proof);
			
			const args = [
				hexStringify(publicSignals[0]), //root
					ethers.BigNumber.from(deposit.nullifierHash).add(
						ethers.BigNumber.from('21888242871839275222246405745257275088548364400416034343698204186575808495617'),
					).toHexString() , //nullHash
				hexStringify(publicSignals[2]), //recip
				inputs.relayer, //relayer
				hexStringify(publicSignals[4]), //fee
				inputs.refund  //refund
			]

			let withdrawCallerIndex = distribution.getIndex(admin.address);
			let withdrawPrivproof = distribution.getProof(withdrawCallerIndex)


			await expect(
				governmentCheese.connect(admin.signer).withdraw(
					proofCalldata, 
					...args,
					withdrawCallerIndex,
					1,
					withdrawPrivproof
				)
	
			).to.be.revertedWith('Invalid withdraw proof');
		})

		it('fee should be less or equal transfer value', async () => {
			/// deposit
			const deposit = await generateCommitment()
			tree.insert(deposit.commitment)

			let callerIndex = distribution.getIndex(privUser.address);
			let privproof = distribution.getProof(callerIndex)

			let depositTx = await governmentCheese.connect(privUser.signer).deposit(
				hexStringify(deposit.commitment),
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

			const largeFee = ethers.BigNumber.from(value).add(1)

			const inputs =  {
				root: tree.root,
				nullifierHash: deposit.nullifierHash,
				relayer: ethers.constants.AddressZero,
				recipient: recipient.toString(),
				fee: largeFee.toString(),
				refund: ethers.constants.HashZero,

				nullifier: deposit.nullifier,
				secret: deposit.secret,
				pathElements: pathElements,
				pathIndices: pathIndices,
			};

			const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, wasmPath, provingKeyPath);

			const proofCalldata = formatSolidity(proof);

			const args = [
				hexStringify(publicSignals[0]), //root
				hexStringify(publicSignals[1]), //nullHash
				hexStringify(publicSignals[2]), //recip
				inputs.relayer, //relayer
				hexStringify(publicSignals[4]), //fee
				inputs.refund  //refund
			]

			let withdrawCallerIndex = distribution.getIndex(admin.address);
			let withdrawPrivproof = distribution.getProof(withdrawCallerIndex)

			await expect(
				governmentCheese.connect(admin.signer).withdraw(
					proofCalldata, 
					...args,
					withdrawCallerIndex,
					1,
					withdrawPrivproof
				)
			).to.be.revertedWith('Fee exceeds transfer value');
		})

		it('should throw for corrupted merkle tree root', async () => {
			/// deposit
			const deposit = await generateCommitment()
			tree.insert(deposit.commitment)

			let callerIndex = distribution.getIndex(privUser.address);
			let privproof = distribution.getProof(callerIndex)

			let depositTx = await governmentCheese.connect(privUser.signer).deposit(
				hexStringify(deposit.commitment),
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

			const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, wasmPath, provingKeyPath);

			const proofCalldata = formatSolidity(proof);

			const args = [
				hexStringify(ethers.utils.keccak256([0x55])), //bad root
				hexStringify(publicSignals[1]), //nullHash
				hexStringify(publicSignals[2]), //recip
				inputs.relayer, //relayer
				hexStringify(publicSignals[4]), //fee
				inputs.refund  //refund
			]

			let withdrawCallerIndex = distribution.getIndex(admin.address);
			let withdrawPrivproof = distribution.getProof(withdrawCallerIndex)

			await expect(
				governmentCheese.connect(admin.signer).withdraw(
					proofCalldata, 
					...args,
					withdrawCallerIndex,
					1,
					withdrawPrivproof
				)
			).to.be.revertedWith('Cannot find your merkle root');
		})

		it('should reject with tampered public inputs', async () => {
			/// deposit
			const deposit = await generateCommitment()
			tree.insert(deposit.commitment)

			let callerIndex = distribution.getIndex(privUser.address);
			let privproof = distribution.getProof(callerIndex)
			
			let depositTx = await governmentCheese.connect(privUser.signer).deposit(
				hexStringify(deposit.commitment),
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

			const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, wasmPath, provingKeyPath);

			const proofCalldata = formatSolidity(proof);
			
			const args = [
				hexStringify(publicSignals[0]), //root
				hexStringify(publicSignals[1]), //nullHash
				hexStringify(publicSignals[2]), //recip
				inputs.relayer, //relayer
				hexStringify(publicSignals[4]), //fee
				inputs.refund  //refund
			]

			let withdrawCallerIndex = distribution.getIndex(admin.address);
			let withdrawPrivproof = distribution.getProof(withdrawCallerIndex)

			let incorrectArgs

			// recipient
			incorrectArgs = [
				hexStringify(publicSignals[0]), //root
				hexStringify(publicSignals[1]), //nullHash
				hexStringify('0x0000000000000000000000007a1f9131357404ef86d7c38dbffed2da70321337'), //recip
				inputs.relayer, //relayer
				hexStringify(publicSignals[4]), //fee
				inputs.refund  //refund
			]

			await expect(
				governmentCheese.connect(admin.signer).withdraw(
					proofCalldata, 
					...incorrectArgs,
					withdrawCallerIndex,
					1,
					withdrawPrivproof
				)
			).to.be.revertedWith('Invalid withdraw proof');
			
			// nullifier
			incorrectArgs = [
				hexStringify(publicSignals[0]), //root
				hexStringify('0x00abdfc78211f8807b9c6504a6e537e71b8788b2f529a95f1399ce124a8642ad'), //nullHash
				hexStringify(publicSignals[2]), //recip
				inputs.relayer, //relayer
				hexStringify(publicSignals[4]), //fee
				inputs.refund  //refund
			]
			withdrawCallerIndex = distribution.getIndex(relayer.address);
			withdrawPrivproof = distribution.getProof(withdrawCallerIndex)

			await expect(
				governmentCheese.connect(relayer.signer).withdraw(
					proofCalldata, 
					...incorrectArgs,
					withdrawCallerIndex,
					1,
					withdrawPrivproof
				)
			).to.be.reverted;

			let badProof = {
				pi_A: ['0x01', '0x0F'],
				pi_B: [
					['0x01', '0x0F'],
					['0x01', '0x0F']
				],
				pi_C: ['0x01', '0x0F']
			};

			await expect(
				governmentCheese.connect(relayer.signer).withdraw(
					badProof, 
					...args,
					withdrawCallerIndex,
					1,
					withdrawPrivproof
				)
			).to.be.revertedWith('Invalid withdraw proof');

			withdrawCallerIndex = distribution.getIndex(admin.address);
			withdrawPrivproof = distribution.getProof(withdrawCallerIndex)

			expect(
				await governmentCheese.connect(admin.signer).withdraw(
					proofCalldata, 
					...args,
					withdrawCallerIndex,
					1,
					withdrawPrivproof
				)
			).to.be.ok
		})

		it('should reject non zero refund', async () => {

			/// deposit
			const deposit = await generateCommitment()
			tree.insert(deposit.commitment)

			let callerIndex = distribution.getIndex(privUser.address);
			let privproof = distribution.getProof(callerIndex)
			
			let depositTx = await governmentCheese.connect(privUser.signer).deposit(
				hexStringify(deposit.commitment),
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
				refund: ethers.BigNumber.from(1).toString(),

				nullifier: deposit.nullifier,
				secret: deposit.secret,
				pathElements: pathElements,
				pathIndices: pathIndices,
			};

			const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, wasmPath, provingKeyPath);

			const proofCalldata = formatSolidity(proof);
			
			const args = [
				hexStringify(publicSignals[0]), //root
				hexStringify(publicSignals[1]), //nullHash
				hexStringify(publicSignals[2]), //recip
				inputs.relayer, //relayer
				hexStringify(publicSignals[4]), //fee
				hexStringify(publicSignals[5])  //refund
			]

			let withdrawCallerIndex = distribution.getIndex(admin.address);
			let withdrawPrivproof = distribution.getProof(withdrawCallerIndex)

			await expect(
				governmentCheese.connect(admin.signer).withdraw(
					proofCalldata, 
					...args,
					withdrawCallerIndex,
					1,
					withdrawPrivproof
				)
			).to.be.revertedWith('Refund value is supposed to be zero for ETH instance');
		})

		it('should reflect accurate isSpentArray', async () => {

			/// deposit
			const deposit1 = await generateCommitment()
			const deposit2 = await generateCommitment()
			tree.insert(deposit1.commitment)
			tree.insert(deposit2.commitment)

			let callerIndex = distribution.getIndex(privUser.address);
			let privproof = distribution.getProof(callerIndex)
			
			await governmentCheese.connect(privUser.signer).deposit(
				hexStringify(deposit1.commitment),
				callerIndex,
				1,
				privproof,
				{ value }
			)
			await governmentCheese.connect(privUser.signer).deposit(
				hexStringify(deposit2.commitment),
				callerIndex,
				1,
				privproof,
				{ value }
			)

			/// withdrawal
			const nextIndex = await governmentCheese.nextIndex();
			const lastDepositIndex = nextIndex - 1
			const { pathElements, pathIndices } = tree.path(lastDepositIndex)

			const inputs =  {
				root: tree.root,
				nullifierHash: deposit2.nullifierHash,
				relayer: ethers.constants.AddressZero,
				recipient: recipient.toString(),
				fee: fee.toString(),
				refund: ethers.constants.HashZero,

				nullifier: deposit2.nullifier,
				secret: deposit2.secret,
				pathElements: pathElements,
				pathIndices: pathIndices,
			};

			const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, wasmPath, provingKeyPath);

			const proofCalldata = formatSolidity(proof);
			
			const args = [
				hexStringify(publicSignals[0]), //root
				hexStringify(publicSignals[1]), //nullHash
				hexStringify(publicSignals[2]), //recip
				inputs.relayer, //relayer
				hexStringify(publicSignals[4]), //fee
				inputs.refund //refund
			]

			let withdrawCallerIndex = distribution.getIndex(relayer.address);
			let withdrawPrivproof = distribution.getProof(withdrawCallerIndex)

			await governmentCheese.connect(relayer.signer).withdraw(
				proofCalldata, 
				...args,
				withdrawCallerIndex,
				1,
				withdrawPrivproof
			)
			const spentArray = await governmentCheese.isSpentArray(
				[
					hexStringify(deposit1.nullifierHash), 
					hexStringify(deposit2.nullifierHash)
				]
			)
			spentArray.should.be.deep.equal([false, true])
		})

		it('should prevent re-submitting duplicate commitment', async () => {
			const deposit = await generateCommitment()
			tree.insert(deposit.commitment)

			let callerIndex = distribution.getIndex(privUser.address);
			let privproof = distribution.getProof(callerIndex)

			expect(
				await governmentCheese.connect(privUser.signer).deposit(
					hexStringify(deposit.commitment),
					callerIndex,
					1,
					privproof,
					{ value }
				)
			).to.be.ok

			await expect(
				governmentCheese.connect(privUser.signer).deposit(
					hexStringify(deposit.commitment),
					callerIndex,
					1,
					privproof,
					{ value }
				)
			).to.be.revertedWith('The commitment has been submitted');
		})

		it('should revert deposit with bad permission', async () => {
			const deposit = await generateCommitment()
			let callerIndex = distribution.getIndex(privUser.address);
			await expect(
				governmentCheese.connect(privUser.signer).deposit(
					hexStringify(deposit.commitment),
					callerIndex,
					1,
					[ ethers.utils.keccak256( 0x777 ) ],
					{ value }
				)
			).to.be.revertedWith('No Privileges');
		})

		it('should revert withdrawal with bad permission and non zero msg value', async () => {

			/// deposit
			const deposit = await generateCommitment()
			tree.insert(deposit.commitment)

			let callerIndex = distribution.getIndex(privUser.address);
			let privproof = distribution.getProof(callerIndex)
			
			let depositTx = await governmentCheese.connect(privUser.signer).deposit(
				hexStringify(deposit.commitment),
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

			const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, wasmPath, provingKeyPath);

			const proofCalldata = formatSolidity(proof);
			
			const args = [
				hexStringify(publicSignals[0]), //root
				hexStringify(publicSignals[1]), //nullHash
				hexStringify(publicSignals[2]), //recip
				inputs.relayer, //relayer
				hexStringify(publicSignals[4]), //fee
				inputs.refund  //refund
			]

			let withdrawCallerIndex = distribution.getIndex(relayer.address);
			let withdrawPrivproof = distribution.getProof(withdrawCallerIndex)

			await expect(
				governmentCheese.connect(relayer.signer).withdraw(
					proofCalldata, 
					...args,
					withdrawCallerIndex,
					1,
					[ ethers.utils.keccak256( 0x888 ) ]
				)
			).to.be.revertedWith('No Privileges');

			await expect(
				governmentCheese.connect(relayer.signer).withdraw(
					proofCalldata, 
					...args,
					withdrawCallerIndex,
					1,
					withdrawPrivproof,
					{ value }
				)
			).to.be.revertedWith('Message value is supposed to be zero for ETH instance');
		})
				
		it('should revert deposit with bad denomination', async () => {
			const deposit = await generateCommitment()

			const callerIndex = distribution.getIndex(privUser.address);
			const privproof = distribution.getProof(callerIndex)

			await expect(
				governmentCheese.connect(privUser.signer).deposit(
					hexStringify(deposit.commitment),
					callerIndex,
					1,
					privproof,
					{ value: 0 }
				)
			).to.be.revertedWith('Please send `denomination` ETH along with transaction');
		})
	})

});