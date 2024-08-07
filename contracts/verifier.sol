// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { SPHINCSPlus } from "./sphincsplus.sol";

contract Verifier {
    SPHINCSPlus sphincsPlus;

    constructor() {
        sphincsPlus = new SPHINCSPlus();
    }

    function verify(bytes memory message, SPHINCSPlus.SPHINCS_SIG memory sig, SPHINCSPlus.SPHINCS_PK memory pk) public pure returns (bool) {
        SPHINCSPlus.Parameters memory params = sphincsPlus.MakeSphincsPlusSHA256256sSimple(false);
        return sphincsPlus.Spx_verify(params, message, sig, pk);
    }
}