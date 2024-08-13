// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SPHINCSPlus} from "../sphincsplus.sol";
import {Utils} from "../utils.sol";
import {SpxParameters} from "../parameters.sol";
import "hardhat/console.sol";

interface ITweakableHashFunction {
    function Hmsg(
        bytes memory R,
        bytes memory PKseed,
        bytes memory PKroot,
        bytes memory M
    ) external view returns (bytes memory);

    function PRF(
        bytes memory SEED,
        SPHINCSPlus.ADRS memory adrs
    ) external view returns (bytes memory);

    function PRFmsg(
        bytes memory SKprf,
        bytes memory OptRand,
        bytes memory M
    ) external view returns (bytes memory);

    function F(
        bytes memory PKseed,
        SPHINCSPlus.ADRS memory adrs,
        bytes memory tmp
    ) external view returns (bytes memory);

    function H(
        bytes memory PKseed,
        SPHINCSPlus.ADRS memory adrs,
        bytes memory tmp
    ) external view returns (bytes memory);

    function T_l(
        bytes memory PKseed,
        SPHINCSPlus.ADRS memory adrs,
        bytes memory tmp
    ) external view returns (bytes memory);

    function chain(
        SpxParameters.Parameters memory params,
        bytes memory input,
        uint8 start,
        uint8 steps,
        bytes memory PKseed,
        SPHINCSPlus.ADRS memory adrs
    ) external view returns (bytes memory); 
}

contract SHA256Tweak is ITweakableHashFunction {  
    Utils utils;
    TweakParams tweakParams;

    struct TweakParams {
        string Variant;
        uint256 MessageDigestLength;
        uint256 N;
    }

    constructor(string memory variant, uint256 m, uint256 n) {
        utils = new Utils();
        tweakParams = TweakParams(variant, m, n);
    }

    function Hmsg(
        bytes memory R,
        bytes memory PKseed,
        bytes memory PKroot,
        bytes memory M
    ) external view override returns (bytes memory) {
        bytes32 hash = sha256(abi.encodePacked(R, PKseed, PKroot, M));
        bytes memory bitmask = mgf1sha256(
            abi.encodePacked(hash),
            tweakParams.MessageDigestLength
        );
        return bitmask;
    }

    function PRF(
        bytes memory SEED,
        SPHINCSPlus.ADRS memory adrs
    ) external pure override returns (bytes memory) {
        bytes memory compressedADRS = compressADRS(adrs);
        return abi.encodePacked(sha256(abi.encodePacked(SEED, compressedADRS)));
    }

    function PRFmsg(
        bytes memory SKprf,
        bytes memory OptRand,
        bytes memory M
    ) external view override returns (bytes memory) {
        bytes memory hmacResult = hmacSha256(
            SKprf,
            abi.encodePacked(OptRand, M)
        );
        return utils.slice(hmacResult, 0, tweakParams.N);
    }

    function F(
        bytes memory PKseed,
        SPHINCSPlus.ADRS memory adrs,
        bytes memory tmp
    ) external view override returns (bytes memory) {
        console.log("F:start");
        bytes memory compressedADRS = compressADRS(adrs);
        bytes memory M1;

        if (keccak256(bytes(tweakParams.Variant)) == keccak256("Robust")) {
            bytes memory bitmask = mgf1sha256(
                abi.encodePacked(PKseed, compressedADRS),
                tmp.length
            );
            M1 = xorBytes(tmp, bitmask);
        } else if (keccak256(bytes(tweakParams.Variant)) == keccak256("Simple")) {
            M1 = tmp;
        }

        bytes memory padding = new bytes(64 - tweakParams.N);
        bytes32 hashValue = sha256(
            abi.encodePacked(PKseed, padding, compressedADRS, M1)
        );
        console.log("F:end");
        return abi.encodePacked(hashValue);
    }

    function H(
        bytes memory PKseed,
        SPHINCSPlus.ADRS memory adrs,
        bytes memory tmp
    ) external view override returns (bytes memory) {
        return this.F(PKseed, adrs, tmp);
    }

    function T_l(
        bytes memory PKseed,
        SPHINCSPlus.ADRS memory adrs,
        bytes memory tmp
    ) external view override returns (bytes memory) {
        return this.F(PKseed, adrs, tmp);
    }

    function compressADRS(
        SPHINCSPlus.ADRS memory adrs
    ) internal pure returns (bytes memory) {
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

    function mgf1sha256(
        bytes memory seed,
        uint length
    ) internal pure returns (bytes memory) {
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
    ) internal pure returns (bytes memory) {
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
    ) internal pure returns (bytes memory) {
        bytes memory o_key_pad = new bytes(64);
        bytes memory i_key_pad = new bytes(64);

        for (uint i = 0; i < key.length; i++) {
            o_key_pad[i] = key[i] ^ 0x5c;
            i_key_pad[i] = key[i] ^ 0x36;
        }

        bytes32 innerHash = sha256(abi.encodePacked(i_key_pad, data));
        return abi.encodePacked(sha256(abi.encodePacked(o_key_pad, innerHash)));
    }

    function chain(
        SpxParameters.Parameters memory params,
        bytes memory input,
        uint8 start,
        uint8 steps,
        bytes memory PKseed,
        SPHINCSPlus.ADRS memory adrs
    ) external view override returns (bytes memory) {
        bytes memory result = input;

        console.log("chain:start");

        for (uint8 i = start; i < (start + steps) && i < params.W; i++) {
            adrs.hashAddress = bytes4(uint32(i));
            result = this.H(PKseed, adrs, result);
        }

        return result;
    }
}
