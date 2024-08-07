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
    }

    struct ADRS {
        uint256 layerAddress;
        uint256 treeAddress;
        uint256 adrsType;
        uint256 keyPairAddress;
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
        (bytes memory tmp_md, IndexResult memory indexes) =
            computeIndexes(R, vParams.PK.PKseed, vParams.PK.PKroot, vParams.M, vParams.params);

        // 計算結果を使用
        uint64 idx_tree = indexes.idx_tree;
        uint32 idx_leaf = indexes.idx_leaf;

        // compute FORS public key
        adrs.layerAddress = 0;
        adrs.treeAddress = idx_tree;
        adrs.adrsType = 0; // FORS_TREE
        adrs.keyPairAddress = idx_leaf;

        bytes memory PKseed = vParams.PK.PKseed;
        bytes memory PKroot = vParams.PK.PKroot;

        bytes memory PK_FORS = Fors_pkFromSig(vParams.params, SIG_FORS, tmp_md, PKseed, adrs);

        // verify HT signature
        adrs.adrsType = 1; // TREE

        return Ht_verify(vParams.params, PK_FORS, SIG_HT, PKseed, idx_tree, idx_leaf, PKroot);
    }
    // function computeIndexes(
    //     bytes memory R,
    //     bytes memory PKseed,
    //     bytes memory PKroot,
    //     bytes memory M,
    //     Parameters memory params
    // ) internal view returns (bytes memory, bytes memory, IndexResult memory) {
    //     bytes memory digest = utils.Hmsg(R, PKseed, PKroot, M);

    //     uint tmp_md_bytes = (params.K * params.A + 7) / 8;
    //     uint tmp_idx_tree_bytes = (params.H - params.H / params.D + 7) / 8;
    //     uint tmp_idx_leaf_bytes = (params.H / params.D + 7) / 8;

    //     bytes memory tmp_md = utils.slice(digest, 0, tmp_md_bytes);
    //     bytes memory tmp_idx_tree = utils.slice(digest, tmp_md_bytes, tmp_idx_tree_bytes);
    //     bytes memory tmp_idx_leaf = utils.slice(digest, tmp_md_bytes + tmp_idx_tree_bytes, tmp_idx_leaf_bytes);

    //     IndexResult memory indexes = calculateIndexes(tmp_idx_tree, tmp_idx_leaf, params);

    //     return (tmp_md, tmp_idx_tree, indexes);
    // }

    // function Spx_verify(
    //     Parameters memory params,
    //     bytes memory M,
    //     SPHINCS_SIG memory SIG,
    //     SPHINCS_PK memory PK
    // ) public view returns (bool) {
    //     // init
    //     ADRS memory adrs;
    //     bytes memory R = SIG.R;
    //     FORSSignature memory SIG_FORS = SIG.SIG_FORS;
    //     HTSignature memory SIG_HT = SIG.SIG_HT;

    //     // compute message digest and index
    //     (bytes memory tmp_md, IndexResult memory indexes) = computeIndexes(
    //         R,
    //         PK.PKseed,
    //         PK.PKroot,
    //         M,
    //         params
    //     );

    //     uint64 idx_tree = indexes.idx_tree;
    //     uint32 idx_leaf = indexes.idx_leaf;

    //     // compute FORS public key
    //     adrs.layerAddress = 0;
    //     adrs.treeAddress = idx_tree;
    //     adrs.adrsType = 0; // FORS_TREE
    //     adrs.keyPairAddress = idx_leaf;

    //     bytes memory PKseed = PK.PKseed;
    //     bytes memory PKroot = PK.PKroot;

    //     bytes memory PK_FORS = Fors_pkFromSig(
    //         params,
    //         SIG_FORS,
    //         tmp_md,
    //         PKseed,
    //         adrs
    //     );

    //     // verify HT signature
    //     adrs.adrsType = 1; // TREE

    //     return
    //         Ht_verify(
    //             params,
    //             PK_FORS,
    //             SIG_HT,
    //             PKseed,
    //             idx_tree,
    //             idx_leaf,
    //             PKroot
    //         );
    // }
    // function Spx_verify(
    //     Parameters memory params,
    //     bytes memory M,
    //     SPHINCS_SIG memory SIG,
    //     SPHINCS_PK memory PK
    // ) public view returns (bool) {
    //     // init
    //     ADRS memory adrs;
    //     bytes memory R = SIG.R;
    //     FORSSignature memory SIG_FORS = SIG.SIG_FORS;
    //     HTSignature memory SIG_HT = SIG.SIG_HT;

    //     // compute message digest and index
    //     (bytes memory tmp_md, bytes memory tmp_idx_tree, IndexResult memory indexes) =
    //         computeIndexes(R, PK.PKseed, PK.PKroot, M, params);

    //     // 計算結果を使用
    //     uint64 idx_tree = indexes.idx_tree;
    //     uint32 idx_leaf = indexes.idx_leaf;

    //     // compute FORS public key
    //     adrs.layerAddress = 0;
    //     adrs.treeAddress = idx_tree;
    //     adrs.adrsType = 0; // FORS_TREE
    //     adrs.keyPairAddress = idx_leaf;

    //     bytes memory PKseed = PK.PKseed;
    //     bytes memory PKroot = PK.PKroot;

    //     bytes memory PK_FORS = Fors_pkFromSig(params, SIG_FORS, tmp_md, PKseed, adrs);

    //     // verify HT signature
    //     adrs.adrsType = 1; // TREE

    //     return Ht_verify(params, PK_FORS, SIG_HT, PKseed, idx_tree, idx_leaf, PKroot);
    // }

    // struct IndexResult {
    //     uint64 idx_tree;
    //     uint32 idx_leaf;
    // }

    // function calculateIndexes(bytes memory tmp_idx_tree, bytes memory tmp_idx_leaf, Parameters memory params) internal view returns (IndexResult memory) {
    //     IndexResult memory result;
    //     result.idx_tree = utils.bytesToUint64(tmp_idx_tree) & (type(uint64).max >> (64 - (params.H - params.H / params.D)));
    //     result.idx_leaf = utils.bytesToUint32(tmp_idx_leaf) & (type(uint32).max >> (32 - params.H / params.D));
    //     return result;
    // }

    // function computeDigestAndIndexes(
    //     bytes memory R,
    //     bytes memory PKseed,
    //     bytes memory PKroot,
    //     bytes memory M,
    //     Parameters memory params
    // ) internal view returns (bytes memory, bytes memory, bytes memory, bytes memory) {
    //     bytes memory digest = utils.Hmsg(R, PKseed, PKroot, M);

    //     uint tmp_md_bytes = (params.K * params.A + 7) / 8;
    //     uint tmp_idx_tree_bytes = (params.H - params.H / params.D + 7) / 8;
    //     uint tmp_idx_leaf_bytes = (params.H / params.D + 7) / 8;

    //     bytes memory tmp_md = utils.slice(digest, 0, tmp_md_bytes);
    //     bytes memory tmp_idx_tree = utils.slice(digest, tmp_md_bytes, tmp_idx_tree_bytes);
    //     bytes memory tmp_idx_leaf = utils.slice(digest, tmp_md_bytes + tmp_idx_tree_bytes, tmp_idx_leaf_bytes);

    //     return (digest, tmp_md, tmp_idx_tree, tmp_idx_leaf);
    // }

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

    // function Spx_verify(
    //     Parameters memory params,
    //     bytes memory M,
    //     SPHINCS_SIG memory SIG,
    //     SPHINCS_PK memory PK
    // ) public view returns (bool) {
    //     // init
    //     ADRS memory adrs;
    //     bytes memory R = SIG.R;
    //     FORSSignature memory SIG_FORS = SIG.SIG_FORS;
    //     HTSignature memory SIG_HT = SIG.SIG_HT;

    //     // // init
    //     // ADRS memory adrs;
    //     // bytes memory R = SIG.R;
    //     // FORSSignature memory SIG_FORS = SIG.SIG_FORS;
    //     // HTSignature memory SIG_HT = SIG.SIG_HT;

    //     // // compute message digest and index
    //     // bytes memory digest = utils.Hmsg(R, PK.PKseed, PK.PKroot, M);

    //     // uint tmp_md_bytes = (params.K * params.A + 7) / 8;
    //     // uint tmp_idx_tree_bytes = (params.H - params.H / params.D + 7) / 8;
    //     // uint tmp_idx_leaf_bytes = (params.H / params.D + 7) / 8;

    //     // bytes memory tmp_md = utils.slice(digest, 0, tmp_md_bytes);
    //     // bytes memory tmp_idx_tree = utils.slice(
    //     //     digest,
    //     //     tmp_md_bytes,
    //     //     tmp_idx_tree_bytes
    //     // );
    //     // bytes memory tmp_idx_leaf = utils.slice(
    //     //     digest,
    //     //     tmp_md_bytes + tmp_idx_tree_bytes,
    //     //     tmp_idx_leaf_bytes
    //     // );
    //     // compute message digest and index
    //     (bytes memory digest, bytes memory tmp_md, bytes memory tmp_idx_tree, bytes memory tmp_idx_leaf) =
    //         computeDigestAndIndexes(R, PK.PKseed, PK.PKroot, M, params);

    //     IndexResult memory indexes = calculateIndexes(tmp_idx_tree, tmp_idx_leaf, params);

    //     uint64 idx_tree = indexes.idx_tree;
    //     uint32 idx_leaf = indexes.idx_leaf;
    //     // uint64 idx_tree = utils.bytesToUint64(tmp_idx_tree) &
    //     //     (type(uint64).max >> (64 - (params.H - params.H / params.D)));
    //     // uint32 idx_leaf = utils.bytesToUint32(tmp_idx_leaf) &
    //     //     (type(uint32).max >> (32 - params.H / params.D));

    //     // compute FORS public key
    //     adrs.layerAddress = 0;
    //     adrs.treeAddress = idx_tree;
    //     adrs.adrsType = 0; // FORS_TREE
    //     adrs.keyPairAddress = idx_leaf;

    //     bytes memory PKseed = PK.PKseed;
    //     bytes memory PKroot = PK.PKroot;

    //     bytes memory PK_FORS = Fors_pkFromSig(params, SIG_FORS, tmp_md, PKseed, adrs);

    //     // verify HT signature
    //     adrs.adrsType = 1; // TREE

    //     return Ht_verify(params, PK_FORS, SIG_HT, PKseed, idx_tree, idx_leaf, PKroot);
    //     // compute FORS public key
    //     // adrs.layerAddress = 0;
    //     // adrs.treeAddress = idx_tree;
    //     // adrs.adrsType = 0; // FORS_TREE
    //     // adrs.keyPairAddress = idx_leaf;

    //     // bytes memory PKseed = PK.PKseed;
    //     // bytes memory PKroot = PK.PKroot;

    //     // bytes memory PK_FORS = Fors_pkFromSig(
    //     //     params,
    //     //     SIG_FORS,
    //     //     tmp_md,
    //     //     PKseed,
    //     //     adrs
    //     // );

    //     // // verify HT signature
    //     // adrs.adrsType = 1; // TREE

    //     // return
    //     //     Ht_verify(
    //     //         params,
    //     //         PK_FORS,
    //     //         SIG_HT,
    //     //         PKseed,
    //     //         idx_tree,
    //     //         idx_leaf,
    //     //         PKroot
    //     //     );
    // }

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
                            abi.encode(adrs),
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
        bytes memory PK_FORS,
        HTSignature memory sig,
        bytes memory PKseed,
        uint64 idx_tree,
        uint32 idx_leaf,
        bytes memory PKroot
    ) internal pure returns (bool) {
        bytes memory node = PK_FORS;

        for (uint i = 0; i < params.D; i++) {
            ADRS memory adrs;
            adrs.layerAddress = i;
            adrs.treeAddress = idx_tree;
            adrs.keyPairAddress = idx_leaf;

            node = abi.encodePacked(
                sha256(
                    abi.encodePacked(
                        PKseed,
                        abi.encode(adrs),
                        node,
                        sig.AUTH[i]
                    )
                )
            );

            idx_tree >>= 1;
            idx_leaf >>= 1; // Moving up the tree level
        }

        return keccak256(node) == keccak256(PKroot);
    }
}
