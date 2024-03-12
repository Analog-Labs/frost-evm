//SPDX-License-Identifier: LGPLv3
pragma solidity ^0.8.0;

import "./Schnorr.sol";
import "./Signer.sol";
import "forge-std/Test.sol";

contract FuzzSchnorr is Test {
    function testFuzz_schnorr(uint256 secret, uint256 nonce, uint256 message) public {
        vm.assume(secret != 0);
        vm.assume(nonce != 0);
        vm.assume(message != 0);
        Signer signer = new Signer(secret);
        (uint256 e, uint256 s) = signer.signPrehashed(message, nonce);
        assert(Schnorr.verify(signer.yParity(), signer.xCoord(), message, e, s));
    }
}
