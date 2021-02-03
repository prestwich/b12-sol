const { assert } = require("chai");
const { ethers } = require("ethers");

const vectors = require("./cip20.json");

describe("CIP20", async () => {
  let cip20;

  before(async () => {
    const Cip20 = await ethers.getContractFactory("Cip20Test");
    cip20 = await Cip20.deploy();
  });

  it("should run hashes", async () => {
    for (vector of vectors) {
      let preimage = `0x${vector.preimage}`;

      assert.include(await cip20.sha2_512(preimage), `0x${vector.sha2_512}`);
      assert.include(await cip20.keccak512(preimage), `0x${vector.keccak512}`);
      assert.include(await cip20.sha3_256(preimage), `0x${vector.sha3_256}`);
      assert.include(await cip20.sha3_512(preimage), `0x${vector.sha3_512}`);
      assert.include(await cip20.blake2s(preimage), `0x${vector.blake2s}`);
    }
  });
});
