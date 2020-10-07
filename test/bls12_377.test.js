const { assert } = require("chai");

const g1Add = require("./bls12377G1Add_matter.json");

describe("BLS12-377", function () {
  let instance;
  this.timeout(40000);
  
  before(async () => {
    const Passthrough = await ethers.getContractFactory("Passthrough");
    instance = Passthrough.attach('0xDC229f666ceF232d6C258eAEb015E17eD2eB366B');
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

        const tx = await instance.g1Add(`0x${test.Input}`);
        console.log(await tx.wait())

        // promises.push(instance.simpleTx(`0x${test.Input}`, 19, 128));
    }
    // const txns = await Promise.all(promises);
    // txns.forEach((tx) => console.log(tx.hash))
  });
  it.skip('should parseG1', async () => {
    for (const test of g1Add) {
      console.log(test.Input);
      let res = await instance.testParseG1(`0x${test.Input}`);
      console.log(res);
    }
  });

  it.skip('should serializeG1', async () => {
    console.log(await instance.testSerializeG1(1, 2, 3, 4));
  });
});