// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./MerkleTreeWithHistory.sol";
import "./MerklePrivilege.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

interface IVerifier {
	function verifyProof(
		uint[2] calldata _pA, 
		uint[2][2] calldata _pB, 
		uint[2] calldata _pC, 
		uint[6] calldata _pubSignals
	) external returns (bool);
}

abstract contract GovernmentCheese is MerkleTreeWithHistory, MerklePrivilege, ReentrancyGuard {
	IVerifier public immutable verifier;
	uint256 public denomination;

	mapping(bytes32 => bool) public nullifierHashes;
	// we store all commitments just to prevent accidental deposits with the same commitment
	mapping(bytes32 => bool) public commitments;

	event Deposit(bytes32 indexed commitment, uint32 leafIndex, uint256 timestamp);
	event Withdrawal(address to, bytes32 nullifierHash, address indexed relayer, uint256 fee);

	/**
		@dev The constructor
		@param _verifier the address of SNARK verifier for this contract
		@param _hasher the address of MiMC hash contract
		@param _denomination transfer amount for each deposit
		@param _merkleTreeHeight the height of deposits' Merkle Tree
	*/
	constructor(
		IVerifier _verifier,
		IHasher _hasher,
		uint256 _denomination,
		uint32 _merkleTreeHeight
	) MerkleTreeWithHistory(_merkleTreeHeight, _hasher) {
		require(_denomination > 0, "denomination should be greater than 0");
		verifier = _verifier;
		denomination = _denomination;
	}

	/**
		@dev Deposit funds into the contract. The caller must send (for ETH) or 
			approve (for ERC20) value equal to or `denomination` of this instance.
		
		@param _index ;
		@param _priv ;
		@param _merkleProof;
		@param _commitment the note commitment, which is 
			PedersenHash(nullifier + secret)
	*/
	function deposit(
		bytes32 _commitment, 
		uint256 _index,
		uint256 _priv,
		bytes32[] calldata _merkleProof
	) external payable nonReentrant {
		require(hasPrivilege(_index, _priv, _merkleProof), "No Privileges");
		require(!commitments[_commitment], "The commitment has been submitted");

		uint32 insertedIndex = _insert(_commitment);
		commitments[_commitment] = true;
		_processDeposit();

		emit Deposit(_commitment, insertedIndex, block.timestamp);
	}

	/** @dev this function is defined in a child contract */
	function _processDeposit() internal virtual;

	function _verifyProof(
		bytes memory proof, 
		uint[6] memory inputs
	) internal returns (bool r) {
        // solidity does not support decoding uint[2][2] yet
        (uint[2] memory a, uint[2] memory b1, uint[2] memory b2, uint[2] memory c) = abi.decode(proof, (uint[2], uint[2], uint[2], uint[2]));
        return verifier.verifyProof(a, [b1, b2], c, inputs);
    }

	/**
		@dev Withdraw a deposit from the contract. `proof` is a zkSNARK proof data, and input is an array of circuit public inputs
		`input` array consists of:
		- merkle root of all deposits in the contract
		- hash of unique deposit nullifier to prevent double spends
		- the recipient of funds
		- optional fee that goes to the transaction sender (usually a relay)
	*/
	function withdraw(
		bytes calldata proof,
		// uint[1] calldata _pubSignals,
		bytes32 _root,
		bytes32 _nullifierHash,
		address _recipient,
		address _relayer,
		uint _fee,
		uint _refund,
		uint _index,
		uint _priv,
		bytes32[] calldata _merkleProof
	) external payable nonReentrant {
		require(_fee <= denomination, "Fee exceeds transfer value");
		require(!nullifierHashes[_nullifierHash], "The note has been already spent");
		require(isKnownRoot(_root), "Cannot find your merkle root"); 
		require(hasPrivilege(_index, _priv, _merkleProof), "No Privileges");

		require(
			_verifyProof(
				proof,
				[
					uint(_root), 
					uint(_nullifierHash), 
					uint(uint160(_recipient)), 
					uint(uint160(_relayer)), 
					_fee, 
					_refund
				]
			),
			"Invalid withdraw proof"
		);

		nullifierHashes[_nullifierHash] = true;
		_processWithdraw(_recipient, _relayer, _fee, _refund);
		emit Withdrawal(_recipient, _nullifierHash, _relayer, _fee);
	}

	/** @dev this function is defined in a child contract */
	function _processWithdraw(
		address _recipient,
		address _relayer,
		uint256 _fee,
		uint256 _refund
	) internal virtual;

	/** @dev whether a note is already spent */
	function isSpent(bytes32 _nullifierHash) public view returns (bool) {
		return nullifierHashes[_nullifierHash];
	}

	/** @dev whether an array of notes is already spent */
	function isSpentArray(bytes32[] calldata _nullifierHashes) external view returns (bool[] memory spent) {
		spent = new bool[](_nullifierHashes.length);
		for (uint256 i = 0; i < _nullifierHashes.length; i++) {
			if (isSpent(_nullifierHashes[i])) {
				spent[i] = true;
			}
		}
	}
}
