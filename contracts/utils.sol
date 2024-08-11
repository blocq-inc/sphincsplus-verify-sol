// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ITweakableHashFunction} from "./tweakable-hash/itweakable.sol";
import {SpxParameters} from "./parameters.sol";
import {SPHINCSPlus} from "./sphincsplus.sol";
import {SHA256Tweak} from "./tweakable-hash/sha256.sol";

contract Utils {

    constructor() {}

    function slice(
        bytes memory data,
        uint start,
        uint length
    ) public pure returns (bytes memory) {
        bytes memory result = new bytes(length);
        for (uint i = 0; i < length; i++) {
            result[i] = data[start + i];
        }
        return result;
    }

    function base_w(
        bytes memory input,
        uint256 w,
        uint256 outputLength
    ) public pure returns (bytes memory) {
        uint256 inLength = input.length;
        // TODO: Check if this is correct
        uint256 totalBits = inLength * 8;
        uint256 log_w = log2(w);
        uint256 totalOutputBits = outputLength * log_w;
        bytes memory result = new bytes(outputLength);

        uint256 inPos = 0;
        uint256 outPos = 0;
        uint256 bitBuffer = 0;
        uint256 bitsInBuffer = 0;

        while (outPos < outputLength) {
            if (bitsInBuffer < log_w) {
                if (inPos < inLength) {
                    bitBuffer = (bitBuffer << 8) | uint8(input[inPos]);
                    bitsInBuffer += 8;
                    inPos++;
                } else {
                    bitBuffer = bitBuffer << (log_w - bitsInBuffer);
                    bitsInBuffer = log_w;
                }
            }

            bitsInBuffer -= log_w;
            result[outPos] = bytes1(
                uint8((bitBuffer >> bitsInBuffer) & (w - 1))
            );
            outPos++;
        }

        return result;
    }

    function toBytes(
        uint256 x,
        uint256 length
    ) public pure returns (bytes memory) {
        bytes memory result = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            result[i] = bytes1(uint8(x >> (8 * (length - 1 - i))));
        }
        return result;
    }

    function log2(uint256 x) public pure returns (uint256) {
        uint256 result = 0;
        while (x > 1) {
            x >>= 1;
            result++;
        }
        return result;
    }

    function bytesToUint64(bytes memory b) public pure returns (uint64) {
        uint64 number;
        for (uint i = 0; i < b.length; i++) {
            number =
                number +
                uint64(uint8(b[i])) *
                uint64(2 ** (8 * (b.length - (i + 1))));
        }
        return number;
    }

    function bytesToUint32(bytes memory b) public pure returns (uint32) {
        uint32 number;
        for (uint i = 0; i < b.length; i++) {
            number =
                number +
                uint32(uint8(b[i])) *
                uint32(2 ** (8 * (b.length - (i + 1))));
        }
        return number;
    }
}
