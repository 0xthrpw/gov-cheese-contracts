// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

contract MerklePrivilege {
	/// current hash tree root
	bytes32 public root;

	/// priv to update root
	address public administrator;

	constructor( ) {
		administrator = msg.sender;
	}

	/**
		A function to update the root of the hash tree

		@param _root The new hash tree root.
	*/
	function updateRoot(bytes32 _root) external {
		require(msg.sender == administrator, "Not Admin");
		root = _root;
	}

	/**
		A function to update the root administrator account.  This function 
		can only be called by the current administrator.

		@param _administrator The address of the new administrator.
	*/
	function updateAdministrator(address _administrator) external {
		require(msg.sender == administrator, "Not Admin");
		administrator = _administrator;
	}

	/**
		A helper function to verify a proof is part of on-chain hash tree and
		has the same root.

		@param _index The index of the hashed node from the list.
		@param _merkleProof An array of one required hash per level.

		@return privileged Whether root of the provided proof matches stored root
	*/
	function hasPrivilege (
		uint256 _index,
		uint256 _priv,
		bytes32[] calldata _merkleProof
	) public view returns (bool privileged) {
		require(_merkleProof.length > 0, "Empty Proof");
		require(_priv > 0, "No Privileges");

		assembly {
			// save free mem ptr for later
			let memPtr := mload(0x40)

			// compute leaf hash
			mstore(0, _index)
			mstore(
				0x20,
				shl(0x60, caller())
			)
			mstore(0x34, _priv)
			let node := keccak256(0, 0x54)

			// copy _index on the stack 
			let path := _index

			// store node in 2nd slot
			mstore(0x20, node)

			// loop through proofs
			for { let i := 0 } lt(i, _merkleProof.length) { i := add(i, 1) } {
				// calc proof offset
				let proofIdx := add(
					_merkleProof.offset,
					mul(0x20, i)
				)
				// load proof
				let proof := calldataload(proofIdx)

				/*
					based on the path store proof on the left or right of 0x20 slot, 
					and then compute hash from 0, 0x20 slots or 0x20, 0x40 slots
				*/
				switch and(path, 0x01)
					case 1 {
						mstore(0, proof)
						mstore(0x20, keccak256(0, 0x40))
					}
					default {
						mstore(0x40, proof)
						mstore(0x20, keccak256(0x20, 0x40))
					}
				
				path := div(path, 2)
			}

			// read computation result
			node := mload(0x20)

			// return free mem ptr to original value
			mstore(0x40, memPtr)

			privileged := eq(
				node,
				sload(root.slot)
			)
		}
	}
}