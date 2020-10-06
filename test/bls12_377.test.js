const { assert } = require("chai");

const g1Add = require("./bls12377G1Add_matter.json");

describe("B12", () => {

  let instance;

  before(async () => {
    const Passthrough = await ethers.getContractFactory("Passthrough");
    instance = Passthrough.attach('0xf26d9780E061D9AED14d8E75aD4b25BCd6470f9e');
    // instance = await Passthrough.deploy();
  });

  it("should g1Add", async () => {
    const promises = [];
    for (const test of g1Add) {
        assert.include(
          await instance.simple(`0x${test.Input}`, 19, 128),
          // await instance.g1Add(`0x${test.Input}`),
          `0x${test.Expected}`,
        );

        // const tx = await instance.g1Add(`0x${test.Input}`);
        // console.log(await tx.wait())

        // promises.push(instance.simpleTx(`0x${test.Input}`, 19, 128));
    }
    // const txns = await Promise.all(promises);
    // txns.forEach((tx) => console.log(tx.hash))
  });
});