import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "hardhat-contract-sizer";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
      //   contractSizer: {
      //     alphaSort: true,
      //     disambiguatePaths: false,
      //     runOnCompile: true,
      //     strict: true,
      //     only: [":ERC20$"],
      //   },
    },
  },
};

export default config;
