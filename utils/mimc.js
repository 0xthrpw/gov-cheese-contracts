const { buildMimcSponge } = require('circomlibjs')
const { ethers } = require('hardhat')

let mimcsponge;
async function buildSponge() {
	mimcsponge  = await buildMimcSponge();
}
buildSponge();
// const bigInt = require("./bigInteger");
import bigInt from './bigInteger'

module.exports = (left, right) => {
	
	const result = mimcsponge.multiHash([left, right])
	// console.log("mimcsponge", mimcsponge);
	console.log({
	// 	// left,
	// 	// right,
	// 	left: ethers.BigNumber.from(left).toString(),
	// 	leftHex: ethers.BigNumber.from(left).toHexString(),
	// 	right: ethers.BigNumber.from(right).toString(),
	// 	rightHex: ethers.BigNumber.from(right).toHexString(),
	// 	result: ethers.BigNumber.from(result).toString(),
		resultHex: ethers.BigNumber.from(result).toHexString()
	});
	return ethers.BigNumber.from(result)
}
