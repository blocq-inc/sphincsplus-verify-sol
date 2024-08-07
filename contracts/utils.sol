// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Utils {
    function Hmsg(bytes memory R, bytes memory PKseed, bytes memory PKroot, bytes memory M) public pure returns (bytes memory) {
        // Using sha256 for hashing
        return abi.encodePacked(sha256(abi.encodePacked(R, PKseed, PKroot, M)));
    }

    function slice(bytes memory data, uint start, uint length) public pure returns (bytes memory) {
        bytes memory result = new bytes(length);
        for (uint i = 0; i < length; i++) {
            result[i] = data[start + i];
        }
        return result;
    }

    function bytesToUint64(bytes memory b) public pure returns (uint64) {
        uint64 number;
        for(uint i = 0; i < b.length; i++) {
            number = number + uint64(uint8(b[i])) * uint64(2**(8*(b.length-(i+1))));
        }
        return number;
    }

    function bytesToUint32(bytes memory b) public pure returns (uint32) {
        uint32 number;
        for(uint i = 0; i < b.length; i++) {
            number = number + uint32(uint8(b[i])) * uint32(2**(8*(b.length-(i+1))));
        }
        return number;
    }
}