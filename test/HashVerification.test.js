const { ethers } = require('hardhat')
import { expect } from 'chai';

describe('Zero Values for Empty Hash Trees', () => {

	let signers, addresses, admin;
	let hasher, merkleTreeWithHistory;
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

		let hasherCompiled = require('../build/Hasher.json');
		let Hasher = new ethers.ContractFactory(
			hasherCompiled.abi,
			hasherCompiled.bytecode
		);
		hasher = await Hasher.connect(admin.signer).deploy();

		const MerkleTreeWithHistory = await ethers.getContractFactory('MerkleTreeWithHistory');
		merkleTreeWithHistory = await MerkleTreeWithHistory.connect(admin.signer).deploy(
			process.env.MERKLE_TREE_HEIGHT,
			hasher.address
		);

	});

	context('Zero Hashes', async function() {
		it('default tree verification', async () => {
			let fieldSize = await merkleTreeWithHistory.FIELD_SIZE();
			let keyword = "government-cheese";

			let zeroHash = ethers.BigNumber.from(ethers.utils.id(keyword)).mod(fieldSize);
			// console.log("zero value int", zeroHash.toString());
			
			let zeroValue = await merkleTreeWithHistory.ZERO_VALUE();
			expect(zeroHash).to.be.equal(zeroValue)

			let zeroes = [
				zeroValue.toHexString() //0
			]

			let nodeHash, pairHash;
			
			pairHash = zeroValue.toHexString();
			for(let i = 0; i < 32; i++){
				nodeHash = pairHash;
				//combine hashes
				pairHash = await merkleTreeWithHistory.hashLeftRight(
					hasher.address,
					nodeHash,
					nodeHash
				)
				zeroes.push(pairHash);

				let zeroHash = await merkleTreeWithHistory.zeros(i);
				expect(zeroHash).to.be.equal(nodeHash);
			}
			// console.log("zero nodes", zeroes)
		})

		it('change keyword for zero hash', async () => {
			// let fieldSize = await merkleTreeWithHistory.FIELD_SIZE();
			// let keyword = "tornado";

			// let zeroHash = ethers.BigNumber.from(ethers.utils.id(keyword)).mod(fieldSize);
			// console.log("zero value int", zeroHash.toString());
			// // let zeroValue = await merkleTreeWithHistory.ZERO_VALUE();
			// // expect(zeroHash).to.be.equal(zeroValue)

			// let zeroes = [
			// 	zeroHash.toHexString() //0
			// ]

			// let nodeHash, pairHash;
			
			// pairHash = zeroHash.toHexString();
			// for(let i = 0; i < 32; i++){
			// 	nodeHash = pairHash;
			// 	//combine hashes
			// 	pairHash = await merkleTreeWithHistory.hashLeftRight(
			// 		hasher.address,
			// 		nodeHash,
			// 		nodeHash
			// 	)
			// 	zeroes.push(pairHash);

			// 	// let zeroHash = await merkleTreeWithHistory.zeros(i);
			// 	// expect(zeroHash).to.be.equal(nodeHash);
			// }
			// console.log("zero nodes", zeroes)
		})

	})

});