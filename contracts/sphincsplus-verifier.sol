// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Utils} from "./utils.sol";
import {SpxParameters} from "./parameters.sol";
import {SHA256Tweak} from "./tweakable-hash/sha256.sol";
import {SPHINCSPlus} from "./sphincsplus.sol";
import "hardhat/console.sol";

contract SPHINCSPlusVerifier {
    SPHINCSPlus sphincsPlus;
    Utils utils;
    SpxParameters spxParams;

    constructor(address _utils, address _spxParams, address _sphincsPlus) {
        sphincsPlus = SPHINCSPlus(_sphincsPlus); 
        spxParams = SpxParameters(_spxParams);
        utils = Utils(_utils);
    }

    // TODO: params should bytes for all args
    // need to decode sig, pk to each struct
    // function desirealizeSignature(bytes memory sig) public pure returns (SPHINCSPlus.SPHINCS_SIG memory) {
    //     SPHINCSPlus.SPHINCS_SIG memory signature;
    //     uint256 offset = 0;

    //     for (uint256 i = 0; i < 32; i++) {
    //         signature.R[i] = sig[offset + i];
    //     }
    //     offset += 32;

    //     for (uint256 i = 0; i < 32; i++) {
    //         signature.S[i] = sig[offset + i];
    //     }

    //     return signature;
    // }

    // TODO
    // function desirealizePk(bytes memory pk) public pure returns (SPHINCSPlus.SPHINCS_PK memory) {
    //     SPHINCSPlus.SPHINCS_PK memory publicKey;
    //     uint256 offset = 0;

    //     for (uint256 i = 0; i < 32; i++) {
    //         publicKey.root[i] = pk[offset + i];
    //     }
    //     offset += 32;

    //     for (uint256 i = 0; i < 32; i++) {
    //         publicKey.seed[i] = pk[offset + i];
    //     }

    //     return publicKey;
    // }

    function verify(
        bytes memory message,
        SPHINCSPlus.SPHINCS_SIG memory sig,
        SPHINCSPlus.SPHINCS_PK memory pk
    ) public returns (bool) {
        SpxParameters.Parameters memory params = spxParams.MakeSphincsPlusSHA256256sSimple(false);

        SPHINCSPlus.VerificationParams memory vParams = SPHINCSPlus
            .VerificationParams({params: params, M: message, SIG: sig, PK: pk});

        console.log("verify");
        return sphincsPlus.Spx_verify(vParams);
    }
}
