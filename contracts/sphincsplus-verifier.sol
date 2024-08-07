// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SPHINCSPlus} from "./sphincsplus.sol";

contract SPHINCSPlusVerifier {
    SPHINCSPlus sphincsPlus;

    constructor() {
        sphincsPlus = new SPHINCSPlus();
    }

    function verify(
        bytes memory message,
        SPHINCSPlus.SPHINCS_SIG memory sig,
        SPHINCSPlus.SPHINCS_PK memory pk
    ) public view returns (bool) {
        SPHINCSPlus.Parameters memory params = sphincsPlus
            .MakeSphincsPlusSHA256256sSimple(false);
        SPHINCSPlus.VerificationParams memory vParams = SPHINCSPlus.VerificationParams({
            params: params,
            M: message,
            SIG: sig,
            PK: pk
        });

        return sphincsPlus.Spx_verify(vParams);
    }
}
