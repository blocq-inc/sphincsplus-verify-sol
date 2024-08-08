// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Utils} from "./utils.sol";

contract SPHINCSPlus {
    Utils utils;

    constructor() {
        utils = new Utils();
    }

    struct Parameters {
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
        string HashType;
        uint256 Len1;
        uint256 Len2;
        uint256 Len;
    }

    struct SPHINCS_PK {
        bytes PKseed;
        bytes PKroot;
    }

    struct SPHINCS_SIG {
        bytes R;
        FORSSignature SIG_FORS;
        HTSignature SIG_HT;
    }

    struct FORSSignature {
        bytes[] SK;
        bytes[] AUTH;
    }

    struct HTSignature {
        bytes[] AUTH;
        XMSSSignature[] xmssSigs;
    }

    struct XMSSSignature {
        bytes wotsSig;
        bytes auth;
    }

    struct ADRS {
        uint256 layerAddress;
        uint256 treeAddress;
        uint256 hashAddress;
        uint256 adrsType;
        uint256 keyPairAddress;
        uint256 chainAddress; 
        uint256 treeHeight;
        uint256 treeIndex;
    }

    struct IndexResult {
        uint64 idx_tree;
        uint32 idx_leaf;
    }

    struct VerificationParams {
        Parameters params;
        bytes M;
        SPHINCS_SIG SIG;
        SPHINCS_PK PK;
    }

    function calculateIndexes(
        bytes memory tmp_idx_tree,
        bytes memory tmp_idx_leaf,
        Parameters memory params
    ) internal view returns (IndexResult memory) {
        IndexResult memory result;
        result.idx_tree =
            utils.bytesToUint64(tmp_idx_tree) &
            (type(uint64).max >> (64 - (params.H - params.H / params.D)));
        result.idx_leaf =
            utils.bytesToUint32(tmp_idx_leaf) &
            (type(uint32).max >> (32 - params.H / params.D));
        return result;
    }

    function computeIndexes(
        bytes memory R,
        bytes memory PKseed,
        bytes memory PKroot,
        bytes memory M,
        Parameters memory params
    ) internal view returns (bytes memory, IndexResult memory) {
        bytes memory digest = utils.Hmsg(R, PKseed, PKroot, M);

        uint tmp_md_bytes = (params.K * params.A + 7) / 8;
        uint tmp_idx_tree_bytes = (params.H - params.H / params.D + 7) / 8;
        uint tmp_idx_leaf_bytes = (params.H / params.D + 7) / 8;

        bytes memory tmp_md = utils.slice(digest, 0, tmp_md_bytes);
        bytes memory tmp_idx_tree = utils.slice(
            digest,
            tmp_md_bytes,
            tmp_idx_tree_bytes
        );
        bytes memory tmp_idx_leaf = utils.slice(
            digest,
            tmp_md_bytes + tmp_idx_tree_bytes,
            tmp_idx_leaf_bytes
        );

        IndexResult memory indexes = calculateIndexes(
            tmp_idx_tree,
            tmp_idx_leaf,
            params
        );

        return (tmp_md, indexes);
    }

    function Spx_verify(
        VerificationParams memory vParams
    ) public view returns (bool) {
        // init
        ADRS memory adrs;
        bytes memory R = vParams.SIG.R;
        FORSSignature memory SIG_FORS = vParams.SIG.SIG_FORS;
        HTSignature memory SIG_HT = vParams.SIG.SIG_HT;

        // compute message digest and index
        (bytes memory tmp_md, IndexResult memory indexes) = computeIndexes(
            R,
            vParams.PK.PKseed,
            vParams.PK.PKroot,
            vParams.M,
            vParams.params
        );

        uint64 idx_tree = indexes.idx_tree;
        uint32 idx_leaf = indexes.idx_leaf;

        // compute FORS public key
        adrs.layerAddress = 0;
        adrs.treeAddress = idx_tree;
        adrs.adrsType = 0; // FORS_TREE
        adrs.keyPairAddress = idx_leaf;

        bytes memory PKseed = vParams.PK.PKseed;
        bytes memory PKroot = vParams.PK.PKroot;

        bytes memory PK_FORS = Fors_pkFromSig(
            vParams.params,
            SIG_FORS,
            tmp_md,
            PKseed,
            adrs
        );

        // verify HT signature
        adrs.adrsType = 1; // TREE

        return
            Ht_verify(
                vParams.params,
                PK_FORS,
                SIG_HT,
                PKseed,
                idx_tree,
                idx_leaf,
                PKroot
            );
    }

    function MakeSphincsPlusSHA256256sSimple(
        bool RANDOMIZE
    ) public pure returns (Parameters memory) {
        return
            Parameters({
                N: 32,
                W: 16,
                Hprime: 64,
                H: 8,
                D: 22,
                K: 14,
                T: 0, // This will be set later
                LogT: 0, // This will be set later
                A: 14,
                RANDOMIZE: RANDOMIZE,
                HashType: "SHA256-simple",
                Len1: 0, // This will be set later
                Len2: 0, // This will be set later
                Len: 0 // This will be set later
            });
    }

    function Fors_pkFromSig(
        Parameters memory params,
        FORSSignature memory sig,
        bytes memory md,
        bytes memory PKseed,
        ADRS memory adrs
    ) internal view returns (bytes memory) {
        bytes memory node;
        bytes memory result;

        // md is the message digest from which we derive the indices
        uint numIndices = params.K;
        uint[] memory indices = new uint[](numIndices);

        // Convert md to indices
        for (uint i = 0; i < numIndices; i++) {
            uint startIdx = i * (params.A / 8);
            uint endIdx = startIdx + (params.A / 8);
            bytes memory indexBytes = utils.slice(
                md,
                startIdx,
                endIdx - startIdx
            );
            indices[i] =
                utils.bytesToUint32(indexBytes) &
                ((1 << params.A) - 1);
        }

        for (uint i = 0; i < params.K; i++) {
            adrs.treeAddress = i;
            node = sig.SK[i];

            for (uint j = 0; j < params.A; j++) {
                adrs.adrsType = j + 1;
                node = abi.encodePacked(
                    sha256(
                        abi.encodePacked(
                            PKseed,
                            utils.adrsToBytes(adrs),
                            node,
                            sig.AUTH[i * params.A + j]
                        )
                    )
                );
            }

            result = abi.encodePacked(result, node);
        }

        return result;
    }

    function Ht_verify(
        Parameters memory params,
        bytes memory M,
        HTSignature memory sig,
        bytes memory PKseed,
        uint64 idx_tree,
        uint32 idx_leaf,
        bytes memory PK_HT
    ) internal view returns (bool) {
        ADRS memory adrs;

        // Initialize address
        adrs.layerAddress = 0;
        adrs.treeAddress = idx_tree;

        // Verify the first XMSS signature
        XMSSSignature memory SIG_tmp = sig.xmssSigs[0];
        bytes memory node = Xmss_pkFromSig(
            params,
            idx_leaf,
            SIG_tmp,
            M,
            PKseed,
            adrs
        );

        // Verify subsequent XMSS signatures
        for (uint j = 1; j < params.D; j++) {
            idx_leaf = uint32(idx_tree % (1 << uint64(params.H / params.D)));
            idx_tree = idx_tree >> (params.H / params.D);

            SIG_tmp = sig.xmssSigs[j];
            adrs.layerAddress = j;
            adrs.treeAddress = idx_tree;
            node = Xmss_pkFromSig(
                params,
                idx_leaf,
                SIG_tmp,
                node,
                PKseed,
                adrs
            );
        }

        return keccak256(node) == keccak256(PK_HT);
    }

    function Xmss_pkFromSig(
        Parameters memory params,
        uint32 idx,
        XMSSSignature memory SIG_XMSS,
        bytes memory M,
        bytes memory PKseed,
        ADRS memory adrs
    ) internal view returns (bytes memory) {
        // Set address type to WOTS_HASH and set key pair address
        adrs.adrsType = 0;  // Assuming 0 is the address type for WOTS_HASH
        adrs.keyPairAddress = idx;

        // Compute WOTS+ pk from WOTS+ sig
        bytes memory node0 = WOTS_pkFromSig(params, SIG_XMSS.wotsSig, M, PKseed, adrs);
        bytes memory node1;

        // Set address type to TREE and set tree index
        adrs.adrsType = 1;  // Assuming 1 is the address type for TREE
        adrs.treeIndex = idx;

        // Compute root from WOTS+ pk and AUTH
        for (uint k = 0; k < params.Hprime; k++) {
            adrs.treeHeight = k + 1;
            if ((idx / (2 ** k)) % 2 == 0) {
                adrs.treeIndex = adrs.treeIndex / 2;

                node1 = utils.sha256ToBytes(sha256(abi.encodePacked(PKseed, utils.adrsToBytes(adrs), node0, utils.slice(SIG_XMSS.auth, k * params.N, params.N))));
            } else {
                adrs.treeIndex = (adrs.treeIndex - 1) / 2;

                node1 = utils.sha256ToBytes(sha256(abi.encodePacked(PKseed, utils.adrsToBytes(adrs), utils.slice(SIG_XMSS.auth, k * params.N, params.N), node0)));
            }
            node0 = node1;
        }
        return node0;
    }

    function WOTS_pkFromSig(
        Parameters memory params,
        bytes memory signature,
        bytes memory message,
        bytes memory PKseed,
        ADRS memory adrs
    ) internal view returns (bytes memory) {
        uint256 csum = 0;

        // Make a copy of adrs
        ADRS memory wotspkADRS = adrs;

        // Convert message to base w
        bytes memory _msg = utils.base_w(message, params.W, params.Len1);

        // Compute checksum
        for (uint256 i = 0; i < params.Len1; i++) {
            csum += params.W - 1 - uint8(_msg[i]);
        }

        csum <<= (8 - ((params.Len2 * utils.log2(params.W)) % 8));
        uint256 len2_bytes = (params.Len2 * utils.log2(params.W) + 7) / 8;  // Equivalent to math.Ceil
        _msg = abi.encodePacked(_msg, utils.base_w(utils.toBytes(csum, len2_bytes), params.W, params.Len2));

        bytes memory tmp = new bytes(params.Len * params.N);

        for (uint256 i = 0; i < params.Len; i++) {
            adrs.chainAddress = uint32(i);
            bytes memory result = utils.chain(params, utils.slice(signature, i * params.N, params.N), uint8(_msg[i]), uint8(params.W - 1 - uint8(_msg[i])), PKseed, adrs);
            for (uint256 j = 0; j < params.N; j++) {
                tmp[i * params.N + j] = result[j];
            }
        }

        wotspkADRS.adrsType = 2;  // Assuming 2 is the address type for WOTS_PK
        wotspkADRS.keyPairAddress = adrs.keyPairAddress;

        return utils.T_l(PKseed, wotspkADRS, tmp);
    }
}
