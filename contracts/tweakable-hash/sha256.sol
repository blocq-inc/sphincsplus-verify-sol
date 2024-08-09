// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ITweakableHashFunction} from "./itweakable.sol";
import {SPHINCSPlus} from "../sphincsplus.sol";
import {Utils} from "../utils.sol";

contract SHA256Tweak {
    Utils utils;

    constructor(address _utils) {
        utils = Utils(_utils);
    }

    struct Sha256Tweak {
        string Variant;
        uint256 MessageDigestLength;
        uint256 N;
    }

    function Hmsg(
        Sha256Tweak memory h,
        bytes memory R,
        bytes memory PKseed,
        bytes memory PKroot,
        bytes memory M
    ) public pure returns (bytes memory) {
        bytes32 hash = sha256(abi.encodePacked(R, PKseed, PKroot, M));
        bytes memory bitmask = mgf1sha256(
            abi.encodePacked(hash),
            h.MessageDigestLength
        );
        return bitmask;
    }

    // function PRF(Sha256Tweak memory h, bytes memory SEED, SPHINCSPlus.ADRS memory adrs) public pure returns (bytes memory) {
    //     bytes memory compressedADRS = compressADRS(adrs);
    //     return abi.encodePacked(sha256(abi.encodePacked(SEED, compressedADRS)));
    //     // bytes memory compressedADRS = compressADRS(adrs);
    //     // return sha256(abi.encodePacked(SEED, compressedADRS));
    // }

    // function PRFmsg(Sha256Tweak memory h, bytes memory SKprf, bytes memory OptRand, bytes memory M) public pure returns (bytes memory) {
    //     return hmac(sha256, SKprf, abi.encodePacked(OptRand, M))[:h.N];
    // }

    function PRFmsg(
        Sha256Tweak memory h,
        bytes memory SKprf,
        bytes memory OptRand,
        bytes memory M
    ) public view returns (bytes memory) {
        bytes memory hmacResult = hmacSha256(
            SKprf,
            abi.encodePacked(OptRand, M)
        );
        return utils.slice(hmacResult, 0, h.N);
    }
    // function PRFmsg(Sha256Tweak memory h, bytes memory SKprf, bytes memory OptRand, bytes memory M) public pure returns (bytes memory) {
    //     return hmac(SKprf, abi.encodePacked(OptRand, M))[:h.N];
    // }
    // function PRFmsg(Sha256Tweak memory h, bytes memory SKprf, bytes memory OptRand, bytes memory M) public pure returns (bytes memory) {
    //     bytes memory hmacResult = hmac(sha256, SKprf, abi.encodePacked(OptRand, M));
    //     return utils.slice(hmacResult, 0, h.N);
    // }

    function F(
        Sha256Tweak memory h,
        bytes memory PKseed,
        SPHINCSPlus.ADRS memory adrs,
        bytes memory tmp
    ) public pure returns (bytes memory) {
        bytes memory compressedADRS = compressADRS(adrs);
        bytes memory M1;

        if (keccak256(bytes(h.Variant)) == keccak256("Robust")) {
            bytes memory bitmask = mgf1sha256(
                abi.encodePacked(PKseed, compressedADRS),
                tmp.length
            );
            M1 = xorBytes(tmp, bitmask);
        } else if (keccak256(bytes(h.Variant)) == keccak256("Simple")) {
            M1 = tmp;
        }

        bytes memory padding = new bytes(64 - h.N);
        bytes32 hashValue = sha256(
            abi.encodePacked(PKseed, padding, compressedADRS, M1)
        );
        return abi.encodePacked(hashValue);
        // return sha256(abi.encodePacked(PKseed, padding, compressedADRS, M1));
    }

    function H(
        Sha256Tweak memory h,
        bytes memory PKseed,
        SPHINCSPlus.ADRS memory adrs,
        bytes memory tmp
    ) public pure returns (bytes memory) {
        return F(h, PKseed, adrs, tmp);
    }

    function T_l(
        Sha256Tweak memory h,
        bytes memory PKseed,
        SPHINCSPlus.ADRS memory adrs,
        bytes memory tmp
    ) public pure returns (bytes memory) {
        return F(h, PKseed, adrs, tmp);
    }

    function compressADRS(
        SPHINCSPlus.ADRS memory adrs
    ) public pure returns (bytes memory) {
        bytes memory ADRSc = new bytes(32);

        ADRSc[0] = adrs.layerAddress[0];
        ADRSc[1] = adrs.layerAddress[1];
        ADRSc[2] = adrs.layerAddress[2];
        ADRSc[3] = adrs.layerAddress[3];

        for (uint i = 0; i < 12; i++) {
            ADRSc[4 + i] = adrs.treeAddress[i];
        }

        ADRSc[16] = adrs.adrsType[0];
        ADRSc[17] = adrs.adrsType[1];
        ADRSc[18] = adrs.adrsType[2];
        ADRSc[19] = adrs.adrsType[3];

        if (adrs.adrsType == bytes4(0)) {
            ADRSc[20] = adrs.keyPairAddress[0];
            ADRSc[21] = adrs.keyPairAddress[1];
            ADRSc[22] = adrs.keyPairAddress[2];
            ADRSc[23] = adrs.keyPairAddress[3];

            ADRSc[24] = adrs.chainAddress[0];
            ADRSc[25] = adrs.chainAddress[1];
            ADRSc[26] = adrs.chainAddress[2];
            ADRSc[27] = adrs.chainAddress[3];
        } else if (adrs.adrsType == bytes4(uint32(1))) {
            ADRSc[20] = adrs.treeHeight[0];
            ADRSc[21] = adrs.treeHeight[1];
            ADRSc[22] = adrs.treeHeight[2];
            ADRSc[23] = adrs.treeHeight[3];

            ADRSc[24] = adrs.treeIndex[0];
            ADRSc[25] = adrs.treeIndex[1];
            ADRSc[26] = adrs.treeIndex[2];
            ADRSc[27] = adrs.treeIndex[3];
        }

        return ADRSc;
    }

    // function compressADRS(
    //     SPHINCSPlus.ADRS memory adrs
    // ) public pure returns (bytes memory) {
    //     bytes memory ADRSc = new bytes(22);

    //     ADRSc[0] = bytes1(uint8(adrs.layerAddress >> 24));
    //     ADRSc[1] = bytes1(uint8(adrs.layerAddress >> 16));
    //     ADRSc[2] = bytes1(uint8(adrs.layerAddress >> 8));
    //     ADRSc[3] = bytes1(uint8(adrs.layerAddress));

    //     for (uint i = 0; i < 8; i++) {
    //         ADRSc[4 + i] = bytes1(uint8(adrs.treeAddress >> (56 - 8 * i)));
    //     }

    //     ADRSc[12] = bytes1(uint8(adrs.adrsType >> 24));
    //     ADRSc[13] = bytes1(uint8(adrs.adrsType >> 16));
    //     ADRSc[14] = bytes1(uint8(adrs.adrsType >> 8));
    //     ADRSc[15] = bytes1(uint8(adrs.adrsType));

    //     if (adrs.adrsType == 0) {
    //         for (uint i = 0; i < 4; i++) {
    //             ADRSc[16 + i] = bytes1(
    //                 uint8(adrs.keyPairAddress >> (24 - 8 * i))
    //             );
    //         }
    //         for (uint i = 0; i < 4; i++) {
    //             ADRSc[20 + i] = bytes1(
    //                 uint8(adrs.chainAddress >> (24 - 8 * i))
    //             );
    //         }
    //     } else if (adrs.adrsType == 1) {
    //         for (uint i = 0; i < 4; i++) {
    //             ADRSc[16 + i] = bytes1(uint8(adrs.treeHeight >> (24 - 8 * i)));
    //         }
    //         for (uint i = 0; i < 4; i++) {
    //             ADRSc[20 + i] = bytes1(uint8(adrs.treeIndex >> (24 - 8 * i)));
    //         }
    //     }

    //     return ADRSc;
    // }

    function mgf1sha256(
        bytes memory seed,
        uint length
    ) public pure returns (bytes memory) {
        bytes memory T;
        uint counter = 0;

        while (T.length < length) {
            bytes memory C = abi.encodePacked(uint32(counter));
            T = abi.encodePacked(T, sha256(abi.encodePacked(seed, C)));
            counter++;
        }

        bytes memory result = new bytes(length);
        for (uint i = 0; i < length; i++) {
            result[i] = T[i];
        }
        return result;
    }

    function xorBytes(
        bytes memory a,
        bytes memory b
    ) public pure returns (bytes memory) {
        require(a.length == b.length, "Input lengths must match");
        bytes memory result = new bytes(a.length);

        for (uint i = 0; i < a.length; i++) {
            result[i] = a[i] ^ b[i];
        }

        return result;
    }

    function hmacSha256(
        bytes memory key,
        bytes memory data
    ) public pure returns (bytes memory) {
        bytes memory o_key_pad = new bytes(64);
        bytes memory i_key_pad = new bytes(64);

        for (uint i = 0; i < key.length; i++) {
            o_key_pad[i] = key[i] ^ 0x5c;
            i_key_pad[i] = key[i] ^ 0x36;
        }

        bytes32 innerHash = sha256(abi.encodePacked(i_key_pad, data));
        return abi.encodePacked(sha256(abi.encodePacked(o_key_pad, innerHash)));
    }
}
