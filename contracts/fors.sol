// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./util/utils.sol";
import "./adrs.sol";
import "./parameters.sol";


contract Fors {
    struct TreePKAUTH {
        bytes privateKeyValue;
        bytes AUTH;
    }

    struct FORSSignature {
        TreePKAUTH[] forspkauth;
    }

    function fors_treehash(Parameters.Parameters memory params, bytes memory SKseed, uint256 startIndex, uint256 targetNodeHeight, bytes memory PKseed, Address.ADRS memory adrs) internal view returns (bytes memory) {
        require(startIndex % (1 << targetNodeHeight) == 0, "Invalid startIndex");

        Util.Stack memory stack;

        for (uint256 i = 0; i < (1 << targetNodeHeight); i++) {
            adrs.setTreeHeight(0);
            adrs.setTreeIndex(startIndex + i);
            bytes memory sk = params.tweak.PRF(SKseed, adrs);
            bytes memory node = params.tweak.F(PKseed, adrs, sk);

            adrs.setTreeHeight(1);
            adrs.setTreeIndex(startIndex + i);

            while (stack.length > 0 && stack.peek().nodeHeight == adrs.getTreeHeight()) {
                adrs.setTreeIndex((adrs.getTreeIndex() - 1) / 2);
                node = params.tweak.H(PKseed, adrs, abi.encodePacked(stack.pop().node, node));
                adrs.setTreeHeight(adrs.getTreeHeight() + 1);
            }

            stack.push(Util.StackEntry(node, adrs.getTreeHeight()));
        }

        return stack.pop().node;
    }

    function fors_PKgen(Parameters.Parameters memory params, bytes memory SKseed, bytes memory PKseed, Address.ADRS memory adrs) internal view returns (bytes memory) {
        Address.ADRS memory forsPKadrs = adrs.copy();
        bytes memory root = new bytes(params.K * params.N);

        for (uint256 i = 0; i < params.K; i++) {
            bytes memory hash = fors_treehash(params, SKseed, i * params.T, params.A, PKseed, adrs);
            for (uint256 j = 0; j < params.N; j++) {
                root[i * params.N + j] = hash[j];
            }
        }

        forsPKadrs.setType(Address.FORS_ROOTS);
        forsPKadrs.setKeyPairAddress(adrs.getKeyPairAddress());
        bytes memory pk = params.tweak.T_l(PKseed, forsPKadrs, root);

        return pk;
    }

    function message_to_indices(bytes memory M, uint256 k, uint256 a) internal pure returns (uint256[] memory) {
        uint256 offset = 0;
        uint256[] memory indices = new uint256[](k);

        for (uint256 i = 0; i < k; i++) {
            indices[i] = 0;
            for (uint256 j = 0; j < a; j++) {
                indices[i] ^= ((uint256(uint8(M[offset >> 3])) >> (offset & 0x7)) & 0x1) << j;
                offset++;
            }
        }
        return indices;
    }

    function fors_sign(Parameters.Parameters memory params, bytes memory M, bytes memory SKseed, bytes memory PKseed, Address.ADRS memory adrs) internal view returns (FORSSignature memory) {
        FORSSignature memory sigFORS;

        for (uint256 i = 0; i < params.K; i++) {
            uint256[] memory indices = message_to_indices(M, params.K, params.A);

            adrs.setTreeHeight(0);
            adrs.setTreeIndex(i * params.T + indices[i]);
            bytes memory PKElement = params.tweak.PRF(SKseed, adrs);

            bytes memory AUTH = new bytes(params.A * params.N);
            for (uint256 j = 0; j < params.A; j++) {
                uint256 s = indices[i] / (1 << j) ^ 1;
                bytes memory test = fors_treehash(params, SKseed, i * params.T + s * (1 << j), j, PKseed, adrs);
                for (uint256 k = 0; k < params.N; k++) {
                    AUTH[j * params.N + k] = test[k];
                }
            }

            sigFORS.forspkauth.push(TreePKAUTH(PKElement, AUTH));
        }
        return sigFORS;
    }

    function fors_pkFromSig(Parameters.Parameters memory params, FORSSignature memory sigFORS, bytes memory M, bytes memory PKseed, Address.ADRS memory adrs) internal view returns (bytes memory) {
        bytes memory root = new bytes(params.K * params.N);

        for (uint256 i = 0; i < params.K; i++) {
            uint256[] memory indices = message_to_indices(M, params.K, params.A);

            adrs.setTreeHeight(0);
            adrs.setTreeIndex(i * params.T + indices[i]);

            bytes memory sk = sigFORS.getSK(i);
            bytes memory node0 = params.tweak.F(PKseed, adrs, sk);
            bytes memory node1;

            bytes memory auth = sigFORS.getAUTH(i);

            for (uint256 j = 0; j < params.A; j++) {
                adrs.setTreeHeight(j + 1);
                if (indices[i] / (1 << j) % 2 == 0) {
                    adrs.setTreeIndex(adrs.getTreeIndex() / 2);
                    bytes memory bytesToHash = abi.encodePacked(node0, auth[j * params.N:(j + 1) * params.N]);
                    node1 = params.tweak.H(PKseed, adrs, bytesToHash);
                } else {
                    adrs.setTreeIndex((adrs.getTreeIndex() - 1) / 2);
                    bytes memory bytesToHash = abi.encodePacked(auth[j * params.N:(j + 1) * params.N], node0);
                    node1 = params.tweak.H(PKseed, adrs, bytesToHash);
                }

                node0 = node1;
            }
            for (uint256 k = 0; k < params.N; k++) {
                root[i * params.N + k] = node0[k];
            }
        }

        Address.ADRS memory forsPKadrs = adrs.copy();
        forsPKadrs.setType(Address.FORS_ROOTS);
        forsPKadrs.setKeyPairAddress(adrs.getKeyPairAddress());
        bytes memory pk = params.tweak.T_l(PKseed, forsPKadrs, root);

        return pk;
    }
}