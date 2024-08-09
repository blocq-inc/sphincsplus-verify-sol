// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SPHINCSPlus} from "../sphincsplus.sol";

interface ITweakableHashFunction {
    function Hmsg(
        bytes memory R,
        bytes memory PKseed,
        bytes memory PKroot,
        bytes memory M
    ) external pure returns (bytes memory);

    function PRF(
        bytes memory SEED,
        SPHINCSPlus.ADRS memory adrs
    ) external pure returns (bytes memory);

    function PRFmsg(
        bytes memory SKprf,
        bytes memory OptRand,
        bytes memory M
    ) external pure returns (bytes memory);

    function F(
        bytes memory PKseed,
        SPHINCSPlus.ADRS memory adrs,
        bytes memory tmp
    ) external pure returns (bytes memory);

    function H(
        bytes memory PKseed,
        SPHINCSPlus.ADRS memory adrs,
        bytes memory tmp
    ) external pure returns (bytes memory);

    function T_l(
        bytes memory PKseed,
        SPHINCSPlus.ADRS memory adrs,
        bytes memory tmp
    ) external pure returns (bytes memory);
}