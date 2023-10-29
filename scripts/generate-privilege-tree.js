'use strict';

// Imports.
import { ethers } from 'hardhat';
import * as fs from 'fs';
import HashTree from './HashTree';

// Prepare the whitelist.
let userSet = [];
let privilegedUsers = [];
console.log(`Generating merkle roots ...`);

// Further populate the whitelist from external file.
const whitelistInfo = fs.readFileSync('./priv/masterwhitelist', 'utf-8');
whitelistInfo.split(/\r?\n/).forEach(function (address) {
  if (address.length > 0) {

    // Sanitize addresses.
    try {
      let sanitizedAddress = ethers.utils.getAddress(address);
      privilegedUsers.push(sanitizedAddress);
    } catch (error) {
      console.error('malformed address', address, error);
    }
  }
});

// Convert the userSet array into a hash tree.
for (let i = 0; i < privilegedUsers.length; i++) {
	userSet[privilegedUsers[i].toLowerCase()] = 1;
}
console.log('Constructing hash tree ...');
let distribution = new HashTree(userSet);

/*
  Export the generated whitelist hash trees to a file for inclusion in the
  frontend interface.
*/
let timestamp = Math.floor(Date.now() / 1000);
console.log(`Writing hash tree ${timestamp} ...`);
fs.writeFileSync(`./priv/privilege-tree-${timestamp}.json`, JSON.stringify({
  tree: distribution.getTree()
}, null, 2));

// Output the root hashes for consumption.
console.log('Privilege root hash', distribution.rootHash);
