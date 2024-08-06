// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library Util {
    function toBytes(uint256 value, uint256 length) internal pure returns (bytes memory) {
        bytes memory buffer = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            buffer[length - 1 - i] = bytes1(uint8(value >> (i * 8)));
        }
        return buffer;
    }
}