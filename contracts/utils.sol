// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SPHINCSPlus} from "./sphincsplus.sol";

contract Utils {
    function Hmsg(
        bytes memory R,
        bytes memory PKseed,
        bytes memory PKroot,
        bytes memory M
    ) public pure returns (bytes memory) {
        // Using sha256 for hashing
        return abi.encodePacked(sha256(abi.encodePacked(R, PKseed, PKroot, M)));
    }

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

    function sha256ToBytes(bytes32 data) public pure returns (bytes memory) {
        bytes memory result = new bytes(32);
        for (uint i = 0; i < 32; i++) {
            result[i] = data[i];
        }
        return result;
    }

    function adrsToBytes(
        SPHINCSPlus.ADRS memory adrs
    ) public pure returns (bytes memory) {
        bytes memory result = new bytes(32);
        // Fill in the bytes as per the ADRS structure fields
        result[0] = bytes1(uint8(adrs.layerAddress >> 24));
        result[1] = bytes1(uint8(adrs.layerAddress >> 16));
        result[2] = bytes1(uint8(adrs.layerAddress >> 8));
        result[3] = bytes1(uint8(adrs.layerAddress));
        for (uint i = 0; i < 8; i++) {
            result[4 + i] = bytes1(uint8(adrs.treeAddress >> (56 - 8 * i)));
        }
        result[12] = bytes1(uint8(adrs.adrsType >> 24));
        result[13] = bytes1(uint8(adrs.adrsType >> 16));
        result[14] = bytes1(uint8(adrs.adrsType >> 8));
        result[15] = bytes1(uint8(adrs.adrsType));
        result[16] = bytes1(uint8(adrs.keyPairAddress >> 24));
        result[17] = bytes1(uint8(adrs.keyPairAddress >> 16));
        result[18] = bytes1(uint8(adrs.keyPairAddress >> 8));
        result[19] = bytes1(uint8(adrs.keyPairAddress));
        result[20] = bytes1(uint8(adrs.chainAddress >> 24));
        result[21] = bytes1(uint8(adrs.chainAddress >> 16));
        result[22] = bytes1(uint8(adrs.chainAddress >> 8));
        result[23] = bytes1(uint8(adrs.chainAddress));
        result[24] = bytes1(uint8(adrs.hashAddress >> 24));
        result[25] = bytes1(uint8(adrs.hashAddress >> 16));
        result[26] = bytes1(uint8(adrs.hashAddress >> 8));
        result[27] = bytes1(uint8(adrs.hashAddress));
        result[28] = bytes1(uint8(adrs.treeHeight >> 24));
        result[29] = bytes1(uint8(adrs.treeHeight >> 16));
        result[30] = bytes1(uint8(adrs.treeHeight >> 8));
        result[31] = bytes1(uint8(adrs.treeHeight));
        result[32] = bytes1(uint8(adrs.treeIndex >> 24));
        result[33] = bytes1(uint8(adrs.treeIndex >> 16));
        result[34] = bytes1(uint8(adrs.treeIndex >> 8));
        result[35] = bytes1(uint8(adrs.treeIndex));
        return result;
    }

    function chain(
        SPHINCSPlus.Parameters memory params,
        bytes memory input,
        uint8 start,
        uint8 steps,
        bytes memory PKseed,
        SPHINCSPlus.ADRS memory adrs
    ) public pure returns (bytes memory) {
        bytes memory result = input;

        for (uint8 i = start; i < (start + steps) && i < params.W; i++) {
            adrs.hashAddress = uint32(i);
            result = sha256ToBytes(
                sha256(abi.encodePacked(PKseed, adrsToBytes(adrs), result))
            );
        }

        return result;
    }

    function T_l(
        bytes memory PKseed,
        SPHINCSPlus.ADRS memory adrs,
        bytes memory tmp
    ) public pure returns (bytes memory) {
        return
            sha256ToBytes(
                sha256(abi.encodePacked(PKseed, adrsToBytes(adrs), tmp))
            );
    }
}
