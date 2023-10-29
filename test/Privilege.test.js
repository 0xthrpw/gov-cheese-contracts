const { ethers } = require('hardhat')
const { should } = require('chai').should();
import { expect } from 'chai';
import HashTree from '../scripts/HashTree';

describe('Hash Tree Gatekeeping', () => {
	let signers, addresses, admin, user;
	let gatekeeper;
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

		user = {
			provider: signers[1].provider,
			signer: signers[1],
			address: addresses[1]
		}

		const Gatekeeper = await ethers.getContractFactory('MockPrivilege');
		gatekeeper = await Gatekeeper.connect(admin.signer).deploy();

		// generate hash tree for testing
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

		await gatekeeper.connect(admin.signer).updateRoot(distribution.rootHash);
	});

	context('Check yr privilege', async function() {
		it('should allow valid proof', async () => {
			let callerIndex = distribution.getIndex(user.address);
			let proof = distribution.getProof(callerIndex)

			expect(
				await gatekeeper.connect(user.signer).checkYrPrivilege(
					callerIndex, //index
					1, //privilege,
					proof //proof
				)
			).to.be.ok;
		})

		it('should revert invalid proof', async () => {
			// Generate an invalid proof.
			let zeroLeaf = ethers.utils.solidityKeccak256(
				[ 'uint256', 'address', 'uint256' ],
				[ 1, ethers.constants.AddressZero, 0 ]
			);

			await expect(
				gatekeeper.connect(user.signer).checkYrPrivilege(
					1, // index
					1, // privilege
					[ zeroLeaf, zeroLeaf, zeroLeaf ] // bad proof
				)
			).to.be.revertedWith("No Privileges");
		})

		it('should revert empty proof', async () => {
			await expect(
				gatekeeper.connect(user.signer).checkYrPrivilege(
					1, // index
					1, // privilege
					[ ] // bad proof
				)
			).to.be.revertedWith("Empty Proof");
		})

		it('should revert zero privs', async () => {
			let callerIndex = distribution.getIndex(user.address);
			let proof = distribution.getProof(callerIndex)

			await expect(
				gatekeeper.connect(user.signer).checkYrPrivilege(
					callerIndex, // index
					0, // privilege
					proof
				)
			).to.be.revertedWith("No Privileges");
		})

		it('should prevent non-admin from changing root hash', async () => {
			await expect(
				gatekeeper.connect(user.signer).updateRoot(
					ethers.utils.keccak256([0x69])
				)
			).to.be.revertedWith("Not Admin");
		})

		it('should prevent non-admin from changing admin account', async () => {
			await expect(
				gatekeeper.connect(user.signer).updateAdministrator(
					user.address
				)
			).to.be.revertedWith("Not Admin");
		})


		it('should allow admin to change admin account', async () => {
			expect(
				await gatekeeper.connect(admin.signer).updateAdministrator(
					user.address
				)
			).to.be.ok;

			expect(
				await gatekeeper.connect(user.signer).updateAdministrator(
					admin.address
				)
			).to.be.ok;
		})
	})

});