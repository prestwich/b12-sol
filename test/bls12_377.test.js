const { assert } = require("chai");

const g1Add = require("./bls12377G1Add_matter.json");

describe("B12", () => {

  let instance;

  before(async () => {
    const Passthrough = await ethers.getContractFactory("Passthrough");
    instance = Passthrough.attach('0x2768df34cD34ecBdad30B6d191DaDfc5ED502eA9');
    // instance = await Passthrough.deploy();
  });

  it("should g1Add", async () => {
    for (const test of g1Add) {
        assert.include(
          await instance.simple(`0x${test.Input}`, 19, 128),
          // await instance.g1Add(`0x${test.Input}`, `0x${test.Expected}`),
          test.Expected,
        );

        // await instance.simpleTx(`0x${test.Input}`, 19, 128);
    }
  });
});