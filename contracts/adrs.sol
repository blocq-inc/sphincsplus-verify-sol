// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./util/utils.sol";

contract Address {
    enum AddressType { WOTS_HASH, WOTS_PK, TREE, FORS_TREE, FORS_ROOTS }

    struct ADRS {
        bytes4 LayerAddress;
        bytes12 TreeAddress;
        bytes4 Type;
        bytes4 KeyPairAddress;
        bytes4 TreeHeight;
        bytes4 TreeIndex;
        bytes4 ChainAddress;
        bytes4 HashAddress;
    }

    function copy(ADRS memory adrs) internal pure returns (ADRS memory) {
        return ADRS({
            LayerAddress: adrs.LayerAddress,
            TreeAddress: adrs.TreeAddress,
            Type: adrs.Type,
            KeyPairAddress: adrs.KeyPairAddress,
            TreeHeight: adrs.TreeHeight,
            TreeIndex: adrs.TreeIndex,
            ChainAddress: adrs.ChainAddress,
            HashAddress: adrs.HashAddress
        });
    }

    function getBytes(ADRS memory adrs) internal pure returns (bytes memory) {
        bytes memory ADRSc = new bytes(32);
        uint256 offset = 0;

        for (uint256 i = 0; i < 4; i++) {
            ADRSc[i] = adrs.LayerAddress[i];
        }
        offset += 4;

        for (uint256 i = 0; i < 12; i++) {
            ADRSc[offset + i] = adrs.TreeAddress[i];
        }
        offset += 12;

        for (uint256 i = 0; i < 4; i++) {
            ADRSc[offset + i] = adrs.Type[i];
        }
        offset += 4;

        if (getType(adrs) == AddressType.WOTS_HASH) {
            for (uint256 i = 0; i < 4; i++) {
                ADRSc[offset + i] = adrs.KeyPairAddress[i];
            }
            offset += 4;
            for (uint256 i = 0; i < 4; i++) {
                ADRSc[offset + i] = adrs.ChainAddress[i];
            }
            offset += 4;
            for (uint256 i = 0; i < 4; i++) {
                ADRSc[offset + i] = adrs.HashAddress[i];
            }
        } else if (getType(adrs) == AddressType.WOTS_PK) {
            for (uint256 i = 0; i < 4; i++) {
                ADRSc[offset + i] = adrs.KeyPairAddress[i];
            }
        } else if (getType(adrs) == AddressType.TREE) {
            for (uint256 i = 0; i < 4; i++) {
                ADRSc[offset + i] = adrs.TreeHeight[i];
            }
            offset += 4;
            for (uint256 i = 0; i < 4; i++) {
                ADRSc[offset + i] = adrs.TreeIndex[i];
            }
        } else if (getType(adrs) == AddressType.FORS_TREE) {
            for (uint256 i = 0; i < 4; i++) {
                ADRSc[offset + i] = adrs.KeyPairAddress[i];
            }
            offset += 4;
            for (uint256 i = 0; i < 4; i++) {
                ADRSc[offset + i] = adrs.TreeHeight[i];
            }
            offset += 4;
            for (uint256 i = 0; i < 4; i++) {
                ADRSc[offset + i] = adrs.TreeIndex[i];
            }
        } else if (getType(adrs) == AddressType.FORS_ROOTS) {
            for (uint256 i = 0; i < 4; i++) {
                ADRSc[offset + i] = adrs.KeyPairAddress[i];
            }
        }

        return ADRSc;
    }

    function setLayerAddress(ADRS storage adrs, uint256 a) internal {
        adrs.LayerAddress = bytes4(Util.toBytes(a, 4));
    }

    function setTreeAddress(ADRS storage adrs, uint256 a) internal {
        adrs.TreeAddress = bytes12(Util.toBytes(a, 12));
    }

    function setType(ADRS storage adrs, AddressType a) internal {
        adrs.Type = bytes4(Util.toBytes(uint256(a), 4));
        setKeyPairAddress(adrs, 0);
        setChainAddress(adrs, 0);
        setHashAddress(adrs, 0);
        setTreeHeight(adrs, 0);
        setTreeIndex(adrs, 0);
    }

    function setKeyPairAddress(ADRS storage adrs, uint256 a) internal {
        adrs.KeyPairAddress = bytes4(Util.toBytes(a, 4));
    }

    function setTreeHeight(ADRS storage adrs, uint256 a) internal {
        adrs.TreeHeight = bytes4(Util.toBytes(a, 4));
    }

    function setTreeIndex(ADRS storage adrs, uint256 a) internal {
        adrs.TreeIndex = bytes4(Util.toBytes(a, 4));
    }

    function setChainAddress(ADRS storage adrs, uint256 a) internal {
        adrs.ChainAddress = bytes4(Util.toBytes(a, 4));
    }

    function setHashAddress(ADRS storage adrs, uint256 a) internal {
        adrs.HashAddress = bytes4(Util.toBytes(a, 4));
    }

    function getKeyPairAddress(ADRS memory adrs) internal pure returns (uint256) {
        return uint256(uint32(bytes4(adrs.KeyPairAddress)));
    }

    function getTreeIndex(ADRS memory adrs) internal pure returns (uint256) {
        return uint256(uint32(bytes4(adrs.TreeIndex)));
    }

    function getTreeHeight(ADRS memory adrs) internal pure returns (uint256) {
        return uint256(uint32(bytes4(adrs.TreeHeight)));
    }

    function getType(ADRS memory adrs) internal pure returns (AddressType) {
        return AddressType(uint256(uint32(bytes4(adrs.Type))));
    }

    function getTreeAddress(ADRS memory adrs) internal pure returns (uint256) {
        return uint256(uint96(bytes12(adrs.TreeAddress)));
    }
}