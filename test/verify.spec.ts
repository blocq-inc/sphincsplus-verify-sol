import {
  time,
  loadFixture,
} from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";
import { expect } from "chai";
import hre from "hardhat";

async function deploySPHINCSPlusVerifierFixture() {
  const SPHINCSPlusVerifierFactory = await hre.ethers.getContractFactory(
    "SPHINCSPlusVerifier"
  );
  const verifier = await SPHINCSPlusVerifierFactory.deploy();

  return { verifier };
}

describe("SPHINCSPlusVerifier", function () {
  // We define a fixture to reuse the same setup in every test.
  // We use loadFixture to run this setup once, snapshot that state,
  // and reset Hardhat Network to that snapshot in every test.
  async function deploySPHINCSPlusVerifierFixture() {
    // Contracts are deployed using the first signer/account by default
    const [owner, otherAccount] = await hre.ethers.getSigners();

    const SPHINCSPlusVerifier = await hre.ethers.getContractFactory(
      "SPHINCSPlusVerifier"
    );
    const verifier = await SPHINCSPlusVerifier.deploy();

    return { verifier, owner, otherAccount };
  }

  describe("Deployment", function () {
    it("Should deploy correctly", async function () {
      const { verifier } = await loadFixture(deploySPHINCSPlusVerifierFixture);

      expect(verifier.target).to.be.properAddress;
    });
  });

  describe("Verification", function () {
    it("Should verify a correct signature", async function () {
      const { verifier } = await loadFixture(deploySPHINCSPlusVerifierFixture);

      // Prepare test data
      const message = hre.ethers.toUtf8Bytes("Test message");
      const sig = {
        R: hre.ethers.randomBytes(32),
        SIG_FORS: {
          SK: [hre.ethers.randomBytes(32)],
          AUTH: [hre.ethers.randomBytes(32)],
        },
        SIG_HT: {
          AUTH: [hre.ethers.randomBytes(32)],
        },
      };
      const pk = {
        PKseed: hre.ethers.randomBytes(32),
        PKroot: hre.ethers.randomBytes(32),
      };

      // Execute verification
      const result = await verifier.verify(message, sig, pk);

      // Check the result
      expect(result).to.be.true;
    });

    it("Should reject an invalid signature", async function () {
      const { verifier } = await loadFixture(deploySPHINCSPlusVerifierFixture);

      // Prepare test data (invalid signature)
      const message = hre.ethers.toUtf8Bytes("Test message");
      const sig = {
        R: hre.ethers.randomBytes(32),
        SIG_FORS: {
          SK: [hre.ethers.randomBytes(32)],
          AUTH: [hre.ethers.randomBytes(32)],
        },
        SIG_HT: {
          AUTH: [hre.ethers.randomBytes(32)],
        },
      };
      const pk = {
        PKseed: hre.ethers.randomBytes(32),
        PKroot: hre.ethers.randomBytes(32),
      };

      // Execute verification
      const result = await verifier.verify(message, sig, pk);

      // Check the result
      expect(result).to.be.false;
    });
  });
});
