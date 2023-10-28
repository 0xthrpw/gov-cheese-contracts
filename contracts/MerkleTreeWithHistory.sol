// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IHasher {
  function MiMCSponge(uint256 in_xL, uint256 in_xR, uint256 k) external pure returns (uint256 xL, uint256 xR);
}

contract MerkleTreeWithHistory {
  uint256 public constant FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
  uint256 public constant ZERO_VALUE = 8193930025208840132363453561112394811274827055571186741018591741257504285324; // = keccak256("government-cheese") % FIELD_SIZE
  IHasher public immutable hasher;

  uint32 public levels;

  // the following variables are made public for easier testing and debugging and
  // are not supposed to be accessed in regular code

  // filledSubtrees and roots could be bytes32[size], but using mappings makes it cheaper because
  // it removes index range check on every interaction
  mapping(uint256 => bytes32) public filledSubtrees;
  mapping(uint256 => bytes32) public roots;
  uint32 public constant ROOT_HISTORY_SIZE = 30;
  uint32 public currentRootIndex = 0;
  uint32 public nextIndex = 0;

  constructor(uint32 _levels, IHasher _hasher) {
    require(_levels > 0, "_levels should be greater than zero");
    require(_levels < 32, "_levels should be less than 32");
    levels = _levels;
    hasher = _hasher;

    for (uint32 i = 0; i < _levels; i++) {
      filledSubtrees[i] = zeros(i);
    }

    roots[0] = zeros(_levels - 1);
  }

  /**
    @dev Hash 2 tree leaves, returns MiMC(_left, _right)
  */
  function hashLeftRight(
    IHasher _hasher,
    bytes32 _left,
    bytes32 _right
  ) public pure returns (bytes32) {
    require(uint256(_left) < FIELD_SIZE, "_left should be inside the field");
    require(uint256(_right) < FIELD_SIZE, "_right should be inside the field");
    uint256 R = uint256(_left);
    uint256 C = 0;
    (R, C) = _hasher.MiMCSponge(R, C, 0);
    R = addmod(R, uint256(_right), FIELD_SIZE);
    (R, C) = _hasher.MiMCSponge(R, C, 0);
    return bytes32(R);
  }

  function _insert(bytes32 _leaf) internal returns (uint32 index) {
    uint32 _nextIndex = nextIndex;
    require(_nextIndex != uint32(2)**levels, "Merkle tree is full. No more leaves can be added");
    uint32 currentIndex = _nextIndex;
    bytes32 currentLevelHash = _leaf;
    bytes32 left;
    bytes32 right;

    for (uint32 i = 0; i < levels; i++) {
      if (currentIndex % 2 == 0) {
        left = currentLevelHash;
        right = zeros(i);
        filledSubtrees[i] = currentLevelHash;
      } else {
        left = filledSubtrees[i];
        right = currentLevelHash;
      }
      currentLevelHash = hashLeftRight(hasher, left, right);
      currentIndex /= 2;
    }

    uint32 newRootIndex = (currentRootIndex + 1) % ROOT_HISTORY_SIZE;
    currentRootIndex = newRootIndex;
    roots[newRootIndex] = currentLevelHash;
    nextIndex = _nextIndex + 1;
    return _nextIndex;
  }

  /**
    @dev Whether the root is present in the root history
  */
  function isKnownRoot(bytes32 _root) public view returns (bool) {
    if (_root == 0) {
      return false;
    }
    uint32 _currentRootIndex = currentRootIndex;
    uint32 i = _currentRootIndex;
    do {
      if (_root == roots[i]) {
        return true;
      }
      if (i == 0) {
        i = ROOT_HISTORY_SIZE;
      }
      i--;
    } while (i != _currentRootIndex);
    return false;
  }

  /**
    @dev Returns the last root
  */
  function getLastRoot() public view returns (bytes32) {
    return roots[currentRootIndex];
  }

  /// @dev provides Zero (Empty) elements for a MiMC MerkleTree. Up to 32 levels
  function zeros(uint256 i) public pure returns (bytes32) {
    if (i == 0) return bytes32(0x121d999c7a62c637057e76d9c1776cafe8e66e1592db74aeac0771ab38a4628c);
    else if (i == 1) return bytes32(0x2400d3dfda70d78bd14c4b0a27a545c405e5ebb2768eb63617d8b43482f54724);
    else if (i == 2) return bytes32(0x2a3f4a5f94c18e17e78d1d6032c51fed991a531212b1d16e97930d63459a5604);
    else if (i == 3) return bytes32(0x261029cc889685b5bc26d7ed6ea356d94cd2368b32bb9ee9df48e817618f8bce);
    else if (i == 4) return bytes32(0x1019ccc154229d1b477231eeb5817aa9426a115dc03b17edc7887499185f150c);
    else if (i == 5) return bytes32(0x25988a43877d5cb936a306e9beda5c5926448ef63863254d832087d4b90bd8b3);
    else if (i == 6) return bytes32(0x1639be54865948b774323a4ffd0c60990e2728175098a5a6fa5fd6954c25dbd7);
    else if (i == 7) return bytes32(0x2d7c51f9941d2acac77ff26697daba2f33b17764fc68de9be42451489797b918);
    else if (i == 8) return bytes32(0x0900c965c8b7fc4c3a3a0b3ae50a0110aedc4f7433fc26e40eaaf6e712cda5ea);
    else if (i == 9) return bytes32(0x0353d1c18b3a822d75baa4aec8b2994250f92b98054eb8427c7509ce8a5f3243);
    else if (i == 10) return bytes32(0x0fbeff1afd8becfd8f42b477490019b109179f8888936d10976509cd5c6085be);
    else if (i == 11) return bytes32(0x2ac59380e65bc9310ea3775a5c7587cc89d82cd8a8728c0b514f998aa541598c);
    else if (i == 12) return bytes32(0x1de018a0b141ba580aeeb32248787fc5cb9c7a777d7c19d04fb93d63c9b42047);
    else if (i == 13) return bytes32(0x072c2e141624764e1ef08e444ddd735155a3ff7965d01bf4de7fd3f08d3b5e16);
    else if (i == 14) return bytes32(0x13330191cdddeebf0ae7ece0aeb1b409d93549df567889b24c0ce64eaeaf45cc);
    else if (i == 15) return bytes32(0x0c5377645a02c2873f1efae133e8d82682ab25f86986661b84624b1c5ae6b2c1);
    else if (i == 16) return bytes32(0x0841931aa38c155186cc8f472a304e413b9a57443e0dfffa833a6c60155aee94);
    else if (i == 17) return bytes32(0x099be7b45866e12f22a40fff57bc139b3cbdb124928a7cb91249d78b7e7e8410);
    else if (i == 18) return bytes32(0x27ab96456eda0acbbb177e5f2c70c129d4fb0df555afbe3e5bd0f61269451181);
    else if (i == 19) return bytes32(0x1ee2ad41ce2074c29f639a5497eb58d896e946efcc402a5c77e1e779fd736127);
    else if (i == 20) return bytes32(0x1db28f766217cbe0178d272999b3ef33acb833d118f21169d532c6ce4b0554f3);
    else if (i == 21) return bytes32(0x14e9ed8a72577dc3385792c126c7a8c40fa6cee6e78e16a91032808c321d3b7e);
    else if (i == 22) return bytes32(0x25fcc13407899b688f30ced9dd84f65e9be345a97bf197a36804e223fef32d42);
    else if (i == 23) return bytes32(0x22666fb855acea8159c817e94b24dee7cfdc0b4ad3c55d874d8424146d7bb937);
    else if (i == 24) return bytes32(0x21113298df41e8609c6386c44ee2db735c99e1d0d3b58d883e351afc952e2ee3);
    else if (i == 25) return bytes32(0x191337d8b48c173612499647f06f0dd664aa058f00a980edfd1f7b69d14e5844);
    else if (i == 26) return bytes32(0x19182697fd3a2ed9a1423cd434ced15a9b5c6876be38344e11c59ce85b9483d4);
    else if (i == 27) return bytes32(0x1e8df90e3853dda1b391a2b8f91d5afa80821a1c03baba40d4c3bb003b7ec626);
    else if (i == 28) return bytes32(0x23e69900762ef099999cb310a9188d6aaba1f02e58a5bdc5a6d436170f209018);
    else if (i == 29) return bytes32(0x00375761599965acae0256811363c8a6622ea71e44a98439af5c7946b404ace8);
    else if (i == 30) return bytes32(0x27b6916b31995a3917b66d8ee00b89fc89b7404755f10a631edde758b25e1fca);
    else if (i == 31) return bytes32(0x15197c08b72c62fbd96c22361b3d2301ec17bb8eaaea37798db688a9eae1358c);
    else revert("Index out of bounds");
  }
}
