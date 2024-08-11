// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Utils} from "./utils.sol";
import {ITweakableHashFunction} from "./tweakable-hash/itweakable.sol";
import {SpxParameters} from "./parameters.sol";
import {SHA256Tweak} from "./tweakable-hash/sha256.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import "hardhat/console.sol";


contract SPHINCSPlus {
    using Math for uint256;
    using SafeCast for uint256;
    Utils utils;
    SpxParameters spxParams;

    constructor(address _utils, address _spxParams) {
        utils = Utils(_utils);
        spxParams = SpxParameters(_spxParams);
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
        XMSSSignature[] xmssSigs;
    }

    struct XMSSSignature {
        bytes wotsSig;
        bytes auth;
    }

    struct ADRS {
        bytes4 layerAddress;
        bytes12 treeAddress;
        bytes4 hashAddress;
        bytes4 adrsType;
        bytes4 keyPairAddress;
        bytes4 chainAddress;
        bytes4 treeHeight;
        bytes4 treeIndex;
    }

    struct IndexResult {
        uint64 idx_tree;
        uint32 idx_leaf;
    }

    struct VerificationParams {
        SpxParameters.Parameters params;
        bytes M;
        SPHINCS_SIG SIG;
        SPHINCS_PK PK;
    }

    function calculateIndexes(
        bytes memory tmp_idx_tree,
        bytes memory tmp_idx_leaf,
        SpxParameters.Parameters memory params
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
        SpxParameters.Parameters memory params
    ) internal view returns (bytes memory, IndexResult memory) {
        bytes memory digest = ITweakableHashFunction(params.Tweak).Hmsg(R, PKseed, PKroot, M);

        require(params.K > 0 && params.A > 0 && params.H > 0 && params.D > 0, "Parameters must be positive");  
        // console.log((params.K*params.A + 7)/8 );
        // TODO: fix unchecked
        unchecked {

            uint256 tmp_md_bytes = Math.ceilDiv(params.K * params.A + 7, 8) - 1;
            uint256 tmp_idx_tree_bytes = Math.ceilDiv(params.H - params.H / params.D + 7, 8) - 1;
            uint256 tmp_idx_leaf_bytes = Math.ceilDiv(params.H / params.D + 7, 8) - 1;

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
    }

    function Spx_verify(
        VerificationParams memory vParams
    ) public view returns (bool) {
        // console.log("Spx_verify");
        // console.log("Spx_verify:init");
        // init
        ADRS memory adrs;
        bytes memory R = vParams.SIG.R;
        FORSSignature memory SIG_FORS = vParams.SIG.SIG_FORS;
        HTSignature memory SIG_HT = vParams.SIG.SIG_HT;

        // console.log("Spx_verify:computeIndexes");
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
        adrs.treeAddress = bytes12(uint96(idx_tree));
        adrs.adrsType = 0; // FORS_TREE
        adrs.keyPairAddress = bytes4(idx_leaf);

        bytes memory PKseed = vParams.PK.PKseed;
        bytes memory PKroot = vParams.PK.PKroot;

        // console.log("Spx_verify:ForS_pkFromSig:start");
        bytes memory PK_FORS = Fors_pkFromSig(
            vParams.params,
            SIG_FORS,
            tmp_md,
            PKseed,
            adrs
        );
        console.log("Spx_verify:ForS_pkFromSig:end");

        // verify HT signature
        adrs.adrsType = bytes4(0x00000001); // TREE

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

    // TODO: write a function to create a SPHINCS+ instance
    // ref: https://github.com/kasperdi/SPHINCSPLUS-golang/blob/c93d01211cb38fad0af614fe3e2c2579ff6c03f4/parameters/parameters.go#L110-L111
    // function MakeSPhincsPlus() public pure returns (Parameters memory) {

    // }

    function messageToIndices(bytes memory M, uint256 k, uint256 a) public pure returns (uint256[] memory) {
        uint256 offset = 0;
        uint256[] memory indices = new uint256[](k);

        for (uint256 i = 0; i < k; i++) {
            indices[i] = 0;
            for (uint256 j = 0; j < a; j++) {
                uint256 byteIndex = offset >> 3; // Calculate the byte index
                
                // Ensure the byteIndex is within the bounds of M
                // require(byteIndex < M.length, "Array index out of bounds");
                
                uint256 byteValue = uint256(uint8(M[byteIndex]));
                uint256 bitValue = (byteValue >> (offset & 0x7)) & 0x1;
                indices[i] ^= bitValue << j;
                
                offset++;
            }
        }

        return indices;
    }

    function Fors_pkFromSig(
        SpxParameters.Parameters memory params,
        FORSSignature memory sig,
        bytes memory md,
        bytes memory PKseed,
        ADRS memory adrs
    ) internal pure returns (bytes memory) {
        bytes memory node0;
        bytes memory node1;
        bytes memory root = new bytes(params.K * params.N);
        // console.log("Fors_pkFromSig:before for loop1");
        for (uint i = 0; i < params.K; i++) {
        
            uint[] memory indices = messageToIndices(md, params.K, params.A);

            node0 = sig.SK[i];

            adrs.treeHeight = bytes4(0);
            adrs.treeIndex = bytes4(uint32(i * params.T + indices[i]));

            // console.log("Fors_pkFromSig:before F");
            node0 = ITweakableHashFunction(params.Tweak).F(PKseed, adrs, node0);
            // console.log("Fors_pkFromSig:after F");

            bytes memory auth = sig.AUTH[i];
            // console.log("auth.length");
            // console.log(auth.length);
            adrs.treeIndex = bytes4(uint32(i * params.T + indices[i]));

            // console.log("Fors_pkFromSig:before for loop2");
            for (uint j = 0; j < params.A; j++) {
                adrs.treeHeight = bytes4(uint32(j + 1));

                // bytes memory bytesToHash = new bytes(params.N + node0.length);
                if ((indices[i] / (2 ** j)) % 2 == 0) {
                    adrs.treeIndex = bytes4(uint32(uint32(adrs.treeIndex) / 2));

                    // console.log("auth.length:");
                    // console.log(auth.length);    
                    bytes memory bytesToHash = new bytes(params.N + node0.length);

                    for (uint256 k = 0; k < node0.length; k++) {
                        bytesToHash[k] = node0[k];
                    }

                    // Copy auth[j*params.N:(j+1)*params.N] to the end of bytesToHash
                    for (uint256 l = 0; l < params.N; l++) {
                        // console.log("j*params.N + l");
                        // console.log(j * params.N + l);
                        // console.log("auth.length");

                        // // TODO: fix unchecked
                        // unchecked   {
                        //     bytesToHash[params.N + l] = auth[j * params.N + l - 1];
                        // }
                        bytesToHash[params.N + l] = auth[j * params.N + l];
                    }
                    node1 = ITweakableHashFunction(params.Tweak).H(PKseed, adrs, bytesToHash);
                } else {
                    adrs.treeIndex = bytes4(uint32((uint32(adrs.treeIndex) - 1) / 2));

                    bytes memory bytesToHash = new bytes(params.N + node0.length);

                    // Copy auth[j*params.N:(j+1)*params.N] to the beginning of bytesToHash
                    for (uint k = 0; k < params.N; k++) {
                        // console.log("j");
                        // console.log(j);
                        // console.log("params.N");
                        // console.log(params.N);
                        // console.log("k");
                        // console.log(k);
                        // console.log("j*params.N + k");
                        // console.log(j * params.N + k);

                        bytesToHash[k] = auth[j * params.N + k];
                    }

                    // Copy node0 to the end of bytesToHash
                    for (uint l = 0; l < node0.length; l++) {
                        bytesToHash[params.N + l] = node0[l];
                    }
                    node1 = ITweakableHashFunction(params.Tweak).H(PKseed, adrs, bytesToHash);
                }

                node0 = node1;
            }

            // console.log("Fors_pkFromSig:before for loop3");

            // TODO: fix
            for (uint k = 0; k < params.N; k++) {
                root[i * params.N + k] = node0[k];
            }
        }

        adrs.adrsType = bytes4(uint32(2)); // address.FORS_ROOTS
        adrs.keyPairAddress = adrs.keyPairAddress;

        // console.log("Fors_pkFromSig:T_l");
        return ITweakableHashFunction(params.Tweak).T_l(PKseed, adrs, root);
    }

    function Ht_verify(
        SpxParameters.Parameters memory params,
        bytes memory M,
        HTSignature memory sig,
        bytes memory PKseed,
        uint64 idx_tree,
        uint32 idx_leaf,
        bytes memory PK_HT
    ) internal view returns (bool) {
        ADRS memory adrs;
        bytes memory node;

        console.log("Ht_verify");
        // Initialize address
        adrs.layerAddress = 0;
        adrs.treeAddress = bytes12(uint96(idx_tree));

        // Verify the first XMSS signature
        XMSSSignature memory SIG_tmp = sig.xmssSigs[0];
        node = Xmss_pkFromSig(
            params,
            idx_leaf,
            SIG_tmp,
            M,
            PKseed,
            adrs
        );

        console.log("Ht_verify:before for loop");
        // Verify subsequent XMSS signatures
        for (uint j = 1; j < params.D; j++) {
            // console.log("params.D");
            // console.log(params.D);
            console.log("j");
            console.log(j);
            idx_leaf = uint32(idx_tree % (1 << uint64(params.H / params.D)));
            idx_tree = idx_tree >> (params.H / params.D);

            SIG_tmp = sig.xmssSigs[j];
            adrs.layerAddress = bytes4(uint32(j));
            adrs.treeAddress = bytes12(uint96(idx_tree));
            node = Xmss_pkFromSig(
                params,
                idx_leaf,
                SIG_tmp,
                node,
                PKseed,
                adrs
            );
        }

        console.log("Ht_verify:keccak256(node) == keccak256(PK_HT)");
        return keccak256(node) == keccak256(PK_HT);
    }

    function Xmss_pkFromSig(
        SpxParameters.Parameters memory params,
        uint32 idx,
        XMSSSignature memory SIG_XMSS,
        bytes memory M,
        bytes memory PKseed,
        ADRS memory adrs
    ) internal view returns (bytes memory) {
        console.log("Xmss_pkFromSig");
        // Set address type to WOTS_HASH and set key pair address
        adrs.adrsType = 0; // Assuming 0 is the address type for WOTS_HASH
        // adrs.keyPairAddress = idx;
        adrs.keyPairAddress = bytes4(uint32(idx)); 
        bytes memory sig = SIG_XMSS.wotsSig;
        bytes memory auth = SIG_XMSS.auth;

        // Compute WOTS+ pk from WOTS+ sig
        bytes memory node0 = WOTS_pkFromSig(
            params,
            sig,
            M,
            PKseed,
            adrs
        );
        bytes memory node1;

        // Set address type to TREE and set tree index
        adrs.adrsType = bytes4(uint32(1)); // Assuming 1 is the address type for TREE
        adrs.treeIndex = bytes4(idx);

        console.log("Xmss_pkFromSig:before for loop1");
        // Compute root from WOTS+ pk and AUTH
        for (uint k = 0; k < params.Hprime; k++) {
            // console.log("Xmss_pkFromSig:in for loop2");
            // adrs.treeHeight = k + 1;
            adrs.treeHeight = bytes4(uint32(k + 1));
            if ((idx / (2 ** k)) % 2 == 0) {
                adrs.treeIndex = bytes4(uint32(uint32(adrs.treeIndex) / 2));

                bytes memory bytesToHash = new bytes(params.N + node0.length);

                // Copy AUTH[k*params.N:(k+1)*params.N] to the beginning of bytesToHash
                for (uint i = 0; i < params.N; i++) {
                    bytesToHash[i] = auth[k * params.N + i];
                }

                // Copy node0 to the end of bytesToHash
                for (uint i = 0; i < node0.length; i++) {
                    bytesToHash[params.N + i] = node0[i];
                }

                node1 = ITweakableHashFunction(params.Tweak).H(
                    PKseed,
                    adrs,
                    bytesToHash
                );
            } else {
                adrs.treeIndex = bytes4(uint32((uint32(adrs.treeIndex) - 1) / 2));

                bytes memory bytesToHash = new bytes(params.N + node0.length);

                for (uint i = 0; i < params.N; i++) {
                    bytesToHash[i] = auth[k * params.N + i];
                }

                // Copy node0 to the end of bytesToHash
                for (uint i = 0; i < node0.length; i++) {
                    bytesToHash[params.N + i] = node0[i];
                }

                node1 = ITweakableHashFunction(params.Tweak).H(
                    PKseed,
                    adrs,
                    bytesToHash
                );
            }
            node0 = node1;
        }

        console.log("Xmss_pkFromSig:end loop1");
        return node0;
    }

    function WOTS_pkFromSig(
        SpxParameters.Parameters memory params,
        bytes memory signature,
        bytes memory message,
        bytes memory PKseed,
        ADRS memory adrs
    ) internal view returns (bytes memory) {
        console.log("WOTS_pkFromSig");
        uint256 csum = 0;

        // Make a copy of adrs
        ADRS memory wotspkADRS = adrs;

        // Convert message to base w
        // console.log("WOTS_pkFromSig:before base_w");
        bytes memory _msg = utils.base_w(message, params.W, params.Len1);

        // Compute checksum
        for (uint256 i = 0; i < params.Len1; i++) {
            csum += params.W - 1 - uint8(_msg[i]);
        }

        // console.log("WOTS_pkFromSig:before csum");
        csum <<= (8 - ((params.Len2 * Math.log2(params.W)) % 8));
        uint256 len2_bytes = Math.ceilDiv(params.Len2 * Math.log2(params.W), 8);
        _msg = utils.appendBytes(_msg, utils.base_w(utils.toBytes(csum, len2_bytes), params.W, params.Len2));
        // console.log("WOTS_pkFromSig:after csum");
        bytes memory tmp = new bytes(params.Len * params.N);
        // console.log(tmp.length);
        console.log("WOTS_pkFromSig:before for loop");
        // console.log(params.Len);

        // TODO: remove commnet out
        // for (uint256 i = 0; i < params.Len; i++) {
        //     console.log("WOTS_pkFromSig:in for loop");
        //     adrs.chainAddress = bytes4(uint32(i));
        //     bytes memory result = ITweakableHashFunction(params.Tweak).chain(
        //         params,
        //         utils.slice(signature, i * params.N, params.N),
        //         uint8(_msg[i]),
        //         uint8(params.W - 1 - uint8(_msg[i])),
        //         PKseed,
        //         adrs
        //     );
        //     // console.log("WOTS_pkFromSig:after chain");
        //     // for (uint256 j = 0; j < params.N; j++) {
        //     //     tmp[i * params.N + j] = result[j];
        //     // }
        // }

        console.log("WOTS_pkFromSig:after loo1");

        wotspkADRS.adrsType = bytes4(uint32(2)); // Assuming 2 is the address type for WOTS_PK
        wotspkADRS.keyPairAddress = adrs.keyPairAddress;

        return ITweakableHashFunction(params.Tweak).T_l(PKseed, wotspkADRS, tmp);
    }
}
