// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../adrs.sol";

interface ITweakableHashFunction {
    function hmsg(
        bytes memory R,
        bytes memory PKseed,
        bytes memory PKroot,
        bytes memory M
    ) external view returns (bytes memory);

    function prf(
        bytes memory SEED,
        Address.ADRS memory adrs
    ) external view returns (bytes memory);

    function prfmsg(
        bytes memory SKprf,
        bytes memory OptRand,
        bytes memory M
    ) external view returns (bytes memory);

    function f(
        bytes memory PKseed,
        Address.ADRS memory adrs,
        bytes memory tmp
    ) external view returns (bytes memory);

    function h(
        bytes memory PKseed,
        Address.ADRS memory adrs,
        bytes memory tmp
    ) external view returns (bytes memory);

    function t_l(
        bytes memory PKseed,
        Address.ADRS memory adrs,
        bytes memory tmp
    ) external view returns (bytes memory);
}