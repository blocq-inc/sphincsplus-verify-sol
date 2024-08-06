// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// import "./sphincsplus.sol";

contract Verifier {
    struct SPHINCS_PK {
        bytes PKseed;  // 公開鍵のシード
        bytes PKroot;  // 公開鍵のルート
    }

    struct SPHINCS_SK {
        bytes SKseed;  // 秘密鍵のシード
        bytes SKprf;   // 秘密鍵PRF
        bytes PKseed;  // 公開鍵のシード
        bytes PKroot;  // 公開鍵のルート
    }

    struct SPHINCS_SIG {
        bytes R;                    // 署名のランダム値
        bytes SIG_FORS;             // FORS署名
        bytes SIG_HT;               // ヒープツリー署名
    }

    function verify(bytes memory message, SPHINCS_SIG memory sig, SPHINCS_PK memory pk) public pure returns (bool) {

    }
}