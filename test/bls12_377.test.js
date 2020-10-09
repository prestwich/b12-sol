const { assert } = require("chai");

const g1Add = require("./bls12377G1Add_matter.json");
const g1Mul = require("./bls12377G1Mul_matter.json");
const g1MultiExp = require("./bls12377G1MultiExp_matter.json");
const g2Add = require("./bls12377G2Add_matter.json");
const g2Mul = require("./bls12377G2Mul_matter.json");
const g2MultiExp = require("./bls12377G2MultiExp_matter.json");


describe("BLS12-377", function () {
  let instance;
  this.timeout(60000);
  
  before(async () => {
    const Passthrough = await ethers.getContractFactory("Passthrough");
    // instance = Passthrough.attach('0x5d432D9AA925210DfbCfd967E884C216853dC017');
    instance = await Passthrough.deploy();
  });

  it("should g1Add", async () => {
    for (const test of g1Add) {
        assert.include(
          await instance.g1Add(`0x${test.Input}`),
          `0x${test.Expected}`,
        );
    }
  });

  it('should g1Mul', async () => {
    for (const test of g1Mul) {
      assert.include(
        await instance.g1Mul(`0x${test.Input}`),
        `0x${test.Expected}`
      );
    }
  });

  it('should g1MultiExp', async () => {
    for (const test of g1MultiExp) {
      assert.include(
        await instance.g1MultiExp(`0x${test.Input}`),
        `0x${test.Expected}`
      );
    }
  });

  it("should g2Add", async () => {
    for (const test of g2Add) {
        assert.include(
          await instance.g2Add(`0x${test.Input}`),
          `0x${test.Expected}`,
        );
    }
  });

  it('should g2Mul', async () => {
    for (const test of g2Mul) {
      assert.include(
        await instance.g2Mul(`0x${test.Input}`),
        `0x${test.Expected}`
      );
    }
  });

  it('should g2MultiExp', async () => {
    for (const test of g2MultiExp) {
      assert.include(
        await instance.g2MultiExp(`0x${test.Input}`),
        `0x${test.Expected}`
      );
    }
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

  it.skip('should parseG2', async () => {
    for (const test of g2Add) {
      console.log(test.Input);
      let res = await instance.testParseG2(`0x${test.Input}`);
      console.log(res);
    }
  });

  it.skip('should serializeG2', async () => {
    console.log(await instance.testSerializeG2(1, 2, 3, 4));
  });
});