// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import "./MerklePrivilege.sol";

contract MockPrivilege is MerklePrivilege {

	constructor( ) { }

	function checkYrPrivilege(
		uint256 _index,
		uint256 _priv,
		bytes32[] calldata _merkleProof
	) external view {
		bool privileged = hasPrivilege(_index, _priv, _merkleProof);
		require(privileged, "No Privileges");
	}
}