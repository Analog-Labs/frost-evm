//SPDX-License-Identifier: LGPLv3
pragma solidity ^0.8.0;

import "./SECP256K1.sol";
import "./Schnorr.sol";

contract Signer {
    SECP256K1 math;
    Schnorr verifier;
    uint256 s;
    uint256 px;
    uint256 py;

    constructor(uint256 secret) {
        require(secret != 0);
        s = secret;
        math = new SECP256K1();
        verifier = new Schnorr();
        (px, py) = math.publicKey(s);
    }
    
    function xCoord() public view returns (uint256) {
        return px;
    }

    function yParity() public view returns (uint8) {
        return uint8(py % 2) + 27;
    }

    function _challenge(uint256 hash, address r) internal view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(r, yParity(), xCoord(), hash)));
    }

    function signPrehashed(uint256 hash, uint256 nonce) public view returns (uint256, uint256) {
        (uint256 rx, uint256 ry) = math.publicKey(nonce);
        address r = math.point_hash(rx, ry);
        uint256 c = _challenge(hash, r);
        uint256 z = nonce + mulmod(c, s, verifier.Q());
        return (c, z);
    }

    function sign(bytes memory message, uint256 nonce) public view returns (uint256, uint256) {
        return signPrehashed(uint256(keccak256(message)), nonce);
    }
}
