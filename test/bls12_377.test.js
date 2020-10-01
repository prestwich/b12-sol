const { assert } = require("chai");

const g1Add = require("./bls12377G1Add_matter.json");

describe("B12", () => {

  let instance;

  before(async () => {
    const Passthrough = await ethers.getContractFactory("Passthrough");
    instance = await Passthrough.deploy();
  });

  it("should g1Add", async () => {
    for (const test of g1Add) {
        await instance.g1Add.call(`0x${test.Input}`, `0x${test.Expected}`, { gasLimit: 600000 });
    }
  });
});