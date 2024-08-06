// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../adrs.sol";

contract Shake256Tweak {
    string public variant;
    uint public messageDigestLength;
    uint public n;

    constructor(string memory _variant, uint _messageDigestLength, uint _n) {
        variant = _variant;
        messageDigestLength = _messageDigestLength;
        n = _n;
    }

    // Keyed hash function Hmsg
    function hmsg(bytes memory R, bytes memory PKseed, bytes memory PKroot, bytes memory M) public view returns (bytes memory) {
        bytes memory output = new bytes(messageDigestLength);
        bytes32 hash = keccak256(abi.encodePacked(R, PKseed, PKroot, M));
        output = abi.encodePacked(hash);
        return output;
    }

    // Pseudorandom function PRF
    function prf(bytes memory SEED, Address.ADRS memory adrs) public view returns (bytes memory) {
        bytes memory output = new bytes(n);
        bytes32 hash = keccak256(abi.encodePacked(SEED, Address.getBytes(adrs)));
        output = abi.encodePacked(hash);
        return output;
    }

    // Pseudorandom function PRFmsg
    function prfmsg(bytes memory SKprf, bytes memory OptRand, bytes memory M) public view returns (bytes memory) {
        bytes memory output = new bytes(n);
        bytes32 hash = keccak256(abi.encodePacked(SKprf, OptRand, M));
        output = abi.encodePacked(hash);
        return output;
    }

    // Tweakable hash function F
    function f(bytes memory PKseed, Address.ADRS memory adrs, bytes memory tmp) public view returns (bytes memory) {
        bytes memory M1;

        if (keccak256(abi.encodePacked(variant)) == keccak256(abi.encodePacked("robust"))) {
            bytes memory bitmask = generateBitmask(PKseed, adrs, tmp.length);
            M1 = new bytes(tmp.length);
            for (uint i = 0; i < tmp.length; i++) {
                M1[i] = tmp[i] ^ bitmask[i]; // XOR
            }
        } else {
            M1 = tmp;
        }

        bytes32 hash = keccak256(abi.encodePacked(PKseed, adrs.getBytes(), M1));
        return abi.encodePacked(hash);
    }

    // Tweakable hash function H
    function h(bytes memory PKseed, Address.ADRS memory adrs, bytes memory tmp) public view returns (bytes memory) {
        return f(PKseed, adrs, tmp);
    }

    // Tweakable hash function T_l
    function t_l(bytes memory PKseed, Address.ADRS memory adrs, bytes memory tmp) public view returns (bytes memory) {
        return f(PKseed, adrs, tmp);
    }

    function generateBitmask(bytes memory PKseed, Address.ADRS memory adrs, uint messageLength) public view returns (bytes memory) {
        bytes memory output = new bytes(messageLength);
        bytes32 hash = keccak256(abi.encodePacked(PKseed, adrs.getBytes()));
        output = abi.encodePacked(hash);
        return output;
    }
}