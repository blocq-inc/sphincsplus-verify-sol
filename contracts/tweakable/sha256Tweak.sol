// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../adrs.sol";
import "../parameters.sol";
import "./ITweakable.sol";

contract Tweakable is ITweakableHashFunction{
    enum Variant { Robust, Simple }
    
    struct Sha256Tweak {
        Variant variant;
        uint256 messageDigestLength;
        uint256 n;
    }

    function hmsg(
        Sha256Tweak storage _h,
        bytes memory R,
        bytes memory PKseed,
        bytes memory PKroot,
        bytes memory M
    ) internal view returns (bytes memory) {
        bytes32 hash = keccak256(abi.encodePacked(R, PKseed, PKroot, M));
        return mgf1sha256(hash, _h.messageDigestLength);
    }

    function prf(Sha256Tweak storage _h, bytes memory SEED, Address.ADRS memory adrs) internal view returns (bytes memory) {
        bytes memory compressedADRS = compressADRS(adrs);
        return keccak256(abi.encodePacked(SEED, compressedADRS))[0:h.n];
    }

    function prfmsg(Sha256Tweak storage _h, bytes memory SKprf, bytes memory OptRand, bytes memory M) internal view returns (bytes memory) {
        bytes32 mac = keccak256(abi.encodePacked(SKprf, OptRand, M));
        return bytes(mac)[0:_h.n];
    }

    function f(Sha256Tweak storage _h, bytes memory PKseed, Address.ADRS memory adrs, bytes memory tmp) internal view returns (bytes memory) {
        bytes memory M1;
        bytes memory compressedADRS = compressADRS(adrs);

        if (_h.variant == Variant.Robust) {
            bytes memory bitmask = mgf1sha256(abi.encodePacked(PKseed, compressedADRS), tmp.length);
            M1 = new bytes(tmp.length);
            for (uint256 i = 0; i < tmp.length; i++) {
                M1[i] = tmp[i] ^ bitmask[i];
            }
        } else if (_h.variant == Variant.Simple) {
            M1 = tmp;
        }

        bytes memory bytesVar = new bytes(64 - _h.n);
        bytes32 hash = keccak256(abi.encodePacked(PKseed, bytesVar, compressedADRS, M1));
        return bytes(hash)[0:_h.n];
    }

    function h(Sha256Tweak storage _h, bytes memory PKseed, Address.ADRS memory adrs, bytes memory tmp) internal view returns (bytes memory) {
        return f(_h, PKseed, adrs, tmp);
    }

    function t_l(Sha256Tweak storage _h, bytes memory PKseed, Address.ADRS memory adrs, bytes memory tmp) internal view returns (bytes memory) {
        return f(_h, PKseed, adrs, tmp);
    }

    function compressADRS(Address.ADRS memory adrs) internal pure returns (bytes memory) {
        bytes memory ADRSc = new bytes(22);
        ADRSc[0] = adrs.layerAddress[3];
        for (uint256 i = 0; i < 8; i++) {
            ADRSc[i + 1] = adrs.treeAddress[4 + i];
        }
        ADRSc[9] = adrs.Type[3];

        if (adrs.getType() == Address.WOTS_HASH) {
            for (uint256 i = 0; i < 4; i++) {
                ADRSc[i + 10] = adrs.keyPairAddress[i];
            }
            for (uint256 i = 0; i < 4; i++) {
                ADRSc[i + 14] = adrs.chainAddress[i];
            }
            for (uint256 i = 0; i < 4; i++) {
                ADRSc[i + 18] = adrs.hashAddress[i];
            }
        } else if (adrs.getType() == Address.WOTS_PK) {
            for (uint256 i = 0; i < 4; i++) {
                ADRSc[i + 10] = adrs.keyPairAddress[i];
            }
        } else if (adrs.getType() == Address.TREE) {
            for (uint256 i = 0; i < 4; i++) {
                ADRSc[i + 14] = adrs.treeHeight[i];
            }
            for (uint256 i = 0; i < 4; i++) {
                ADRSc[i + 18] = adrs.treeIndex[i];
            }
        } else if (adrs.getType() == Address.FORS_TREE) {
            for (uint256 i = 0; i < 4; i++) {
                ADRSc[i + 10] = adrs.keyPairAddress[i];
            }
            for (uint256 i = 0; i < 4; i++) {
                ADRSc[i + 14] = adrs.treeHeight[i];
            }
            for (uint256 i = 0; i < 4; i++) {
                ADRSc[i + 18] = adrs.treeIndex[i];
            }
        } else if (adrs.getType() == Address.FORS_ROOTS) {
            for (uint256 i = 0; i < 4; i++) {
                ADRSc[i + 10] = adrs.keyPairAddress[i];
            }
        }

        return ADRSc;
    }

    function mgf1sha256(bytes memory seed, uint256 length) internal view returns (bytes memory) {
        bytes memory T = new bytes(0);
        uint256 counter = 0;

        while (T.length < length) {
            bytes memory C = Util.toByte(counter);
            bytes32 hash = keccak256(abi.encodePacked(seed, C));
            T = abi.encodePacked(T, hash);
            counter++;
        }

        return T[:length];
    }
}