// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./tweakable/sha256Tweak.sol";

contract Parameters {
    struct Param {
        uint256 N;
        uint256 W;
        uint256 Hprime;
        uint256 H;
        uint256 D;
        uint256 K;
        uint256 T;
        uint256 LogT;
        uint256 A;
        bool RANDOMIZE;
        Tweakable.TweakableHashFunction Tweak;
        uint256 Len1;
        uint256 Len2;
        uint256 Len;
    }

    // function makeSphincsPlusSHA256256fRobust(bool RANDOMIZE) public pure returns (Param memory) {
    //     return makeSphincsPlus(32, 16, 68, 17, 35, 9, "SHA256-robust", RANDOMIZE);
    // }

    // function makeSphincsPlusSHA256256sRobust(bool RANDOMIZE) public pure returns (Param memory) {
    //     return makeSphincsPlus(32, 16, 64, 8, 22, 14, "SHA256-robust", RANDOMIZE);
    // }

    // function makeSphincsPlusSHA256256fSimple(bool RANDOMIZE) public pure returns (Param memory) {
    //     return makeSphincsPlus(32, 16, 68, 17, 35, 9, "SHA256-simple", RANDOMIZE);
    // }

    function makeSphincsPlusSHA256256sSimple(bool RANDOMIZE) public pure returns (Param memory) {
        return makeSphincsPlus(32, 16, 64, 8, 22, 14, "SHA256-simple", RANDOMIZE);
    }

    function makeSphincsPlus(
        uint256 n,
        uint256 w,
        uint256 h,
        uint256 d,
        uint256 k,
        uint256 logt,
        string memory hashFunc,
        bool RANDOMIZE
    ) internal pure returns (Param memory) {
        Param memory params;
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

        params.Len1 = (8 * n + (w - 1)) / w; // ceil(8 * n / log2(w))
        params.Len2 = (params.Len1 * (w - 1)).log2() + 1; // floor(log2(params.Len1 * (w - 1)) / log2(w)) + 1
        params.Len = params.Len1 + params.Len2;

        uint256 md_len = (k * logt + 7) / 8; // floor((K * logt + 7) / 8)
        uint256 idx_tree_len = (h - (h / d) + 7) / 8; // floor((h - h/d + 7) / 8)
        uint256 idx_leaf_len = (h / d + 7) / 8; // floor((h/d + 7) / 8)
        uint256 m = md_len + idx_tree_len + idx_leaf_len;

        if (keccak256(abi.encodePacked(hashFunc)) == keccak256(abi.encodePacked("SHA256-robust"))) {
            params.Tweak = new Tweakable.Sha256Tweak(Tweakable.Robust, m, n);
        } else if (keccak256(abi.encodePacked(hashFunc)) == keccak256(abi.encodePacked("SHA256-simple"))) {
            params.Tweak = new Tweakable.Sha256Tweak(Tweakable.Simple, m, n);
        } else if (keccak256(abi.encodePacked(hashFunc)) == keccak256(abi.encodePacked("SHAKE256-robust"))) {
            params.Tweak = new Tweakable.Shake256Tweak(Tweakable.Robust, m, n);
        } else if (keccak256(abi.encodePacked(hashFunc)) == keccak256(abi.encodePacked("SHAKE256-simple"))) {
            params.Tweak = new Tweakable.Shake256Tweak(Tweakable.Simple, m, n);
        } else {
            params.Tweak = new Tweakable.Sha256Tweak(Tweakable.Robust, m, n);
        }

        return params;
    }
}