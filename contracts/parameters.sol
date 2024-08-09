
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ITweakableHashFunction} from "./tweakable-hash/itweakable.sol";
import {Utils} from "./utils.sol";
import {SHA256Tweak} from "./tweakable-hash/sha256.sol";

contract SpxParameters {
    Utils utils;

    constructor(address _utils) {
        utils = Utils(_utils);
    }

    struct Parameters {
        uint256 N;
        uint256 W;
        uint256 H;
        uint256 D;
        uint256 K;
        uint256 T;
        uint256 LogT;
        uint256 Hprime;
        uint256 A;
        bool RANDOMIZE;
        ITweakableHashFunction Tweak; 
        uint256 Len1;
        uint256 Len2;
        uint256 Len;
    }

    struct Sha256Tweak {
        string Variant;
        uint256 m;
        uint256 N;
    }

    struct Shake256Tweak {
        string Variant;
        uint256 m;
        uint256 N;
    }

    function MakeSphincsPlus(
        uint256 n,
        uint256 w,
        uint256 h,
        uint256 d,
        uint256 k,
        uint256 logt,
        string memory hashFunc,
        bool RANDOMIZE
    ) public pure returns (Parameters memory) {
        Parameters memory params;
        params.N = n;
        params.W = w;
        params.H = h;
        params.D = d;
        params.K = k;
        params.LogT = logt;
        params.Hprime = h / d;
        params.T = 1 << logt;
        params.A = logt;
        params.RANDOMIZE = RANDOMIZE;
        params.Len1 = (8 * n + utils.log2(w) - 1) / utils.log2(w); // Ceil operation
        params.Len2 = (utils.log2(params.Len1 * (w - 1)) + utils.log2(w) - 1) / utils.log2(w) + 1; // Floor operation
        params.Len = params.Len1 + params.Len2;

        uint256 md_len = (params.K * logt + 7) / 8;
        uint256 idx_tree_len = (h - h / d + 7) / 8;
        uint256 idx_leaf_len = (h / d + 7) / 8;
        uint256 m = md_len + idx_tree_len + idx_leaf_len;

        if (keccak256(abi.encodePacked(hashFunc)) == keccak256(abi.encodePacked("SHA256-robust"))) {
            params.Tweak = new SHA256Tweak(address(utils), "Robust", m, n);
        } else if (keccak256(abi.encodePacked(hashFunc)) == keccak256(abi.encodePacked("SHA256-simple"))) {
            params.Tweak = new SHA256Tweak(address(utils), "Simple", m, n);
        // TODO: Add SHAKE256 variants later
        // } else if (keccak256(abi.encodePacked(hashFunc)) == keccak256(abi.encodePacked("SHAKE256-robust"))) {
        //     params.Tweak = Shake256Tweak("Robust", m, n);
        // } else if (keccak256(abi.encodePacked(hashFunc)) == keccak256(abi.encodePacked("SHAKE256-simple"))) {
        //     params.Tweak = Shake256Tweak("Robust", m, n);
        // } else {
            params.Tweak = new SHA256Tweak(address(utils), "Simple", m, n); // Default to SHA256-simple
        }
        return params;
    }

    function MakeSphincsPlusSHA256256sSimple(bool RANDOMIZE) public pure returns (Parameters memory) {
        return MakeSphincsPlus(32, 16, 64, 8, 22, 14, "SHA256-simple", RANDOMIZE);
    }
    // TODO:Other MakeSphincsPlus variants...
    // function MakeSphincsPlusSHA256256fRobust(bool RANDOMIZE) public pure returns (Parameters memory) {
    //     return MakeSphincsPlus(32, 16, 68, 17, 35, 9, "SHA256-robust", RANDOMIZE);
    // }

    // function MakeSphincsPlusSHA256256sRobust(bool RANDOMIZE) public pure returns (Parameters memory) {
    //     return MakeSphincsPlus(32, 16, 64, 8, 22, 14, "SHA256-robust", RANDOMIZE);
    // }


    // function log2(uint x) internal pure returns (uint y) {
    //     assembly {
    //         let arg := x
    //         x := sub(x, 1)
    //         x := or(x, div(x, 0x02))
    //         x := or(x, div(x, 0x04))
    //         x := or(x, div(x, 0x10))
    //         x := or(x, div(x, 0x100))
    //         x := or(x, div(x, 0x10000))
    //         x := or(x, div(x, 0x100000000))
    //         x := or(x, div(x, 0x10000000000000000))
    //         x := or(x, div(x, 0x100000000000000000000000000000000))
    //         x := add(x, 1)
    //         let m := mload(0x40)
    //         mstore(m, 0x01)
    //         mstore(add(m, 0x20), 0x02)
    //         mstore(add(m, 0x40), 0x04)
    //         mstore(add(m, 0x60), 0x08)
    //         mstore(add(m, 0x80), 0x10)
    //         mstore(add(m, 0xa0), 0x20)
    //         mstore(add(m, 0xc0), 0x40)
    //         mstore(add(m, 0xe0), 0x80)
    //         mstore(0x40, add(m, 0x100))
    //         let magic := mload(add(m, mul(lt(x, 0x100), 0x20)))
    //         magic := or(magic, mload(add(m, mul(lt(x, 0x10000), 0x40))))
    //         magic := or(magic, mload(add(m, mul(lt(x, 0x100000000), 0x60))))
    //         magic := or(magic, mload(add(m, mul(lt(x, 0x1000000000000), 0x80))))
    //         magic := or(magic, mload(add(m, mul(lt(x, 0x10000000000000000), 0xa0))))
    //         magic := or(magic, mload(add(m, mul(lt(x, 0x100000000000000000000), 0xc0))))
    //         magic := or(magic, mload(add(m, mul(lt(x, 0x1000000000000000000000000000000), 0xe0))))
    //         magic := or(magic, mload(add(m, mul(lt(x, 0x10000000000000000000000000000000000), 0x100))))
    //         y := sub(magic, div(mul(arg, 2), x))
    //     }
    // }
}