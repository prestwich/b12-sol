const { assert } = require("chai");
const { tonelli } = require("./tonelli")

function split(n) {
  let str = n.toString(16).padStart(128, '0')
  return ["0x"+str.substr(-128, 64), "0x"+str.substr(-64)]
}

function split2(n) {
  let str = n.toString(16).padStart(96, '0')
  console.log(`B12.Fp(0x${str.substr(0, 32)}, 0x${str.substr(32, 64)})`)
}

function combine(a, b) {
  let aa = a._hex.substr(2).padStart(64, '0')
  let bb = b._hex.substr(2).padStart(64, '0')
  return BigInt("0x"+aa+bb)
}

let base = 0x1ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508c00000000001n
let y1 = 0x001cefdc52b4e1eba6d3b6633bf15a765ca326aa36b6c0b5b1db375b6a5124fa540d200dfb56a6e58785e1aaaa63715bn
let y2 = 0x01914a69c5102eff1f674f5d30afeec4bd7fb348ca3e52d96d182ad44fb82305c2fe3d3634a9591afd82de55559c8ea6n
let x = 0x008848defe740a67c8fc6225bf87ff5485951e2caa9d41bb188282c8bd37cb5cd5481512ffcd394eeab9b16eb21be9efn

function max(a,b) {
  if (a < b) return b
  else return a
}

function min(a,b) {
  if (a > b) return b
  else return a
}

/*
let sq = x**3n + 1n

let [r1, r2, _] = tonelli(sq, base)

console.log(r1, y1, r2, y2)
*/

function findY(x, greatest) {
  let [a, b] = tonelli((x ** 3n + 1n) % base, base)
  return greatest ? max(a,b) : min(a,b)
}

function uncompressSig(comp) {
  let sig = comp.reverse()
  let greatest = (sig[0] & 0x80) != 0
  sig[0] = sig[0] & 0x7f
  let x = BigInt("0x"+Buffer.from(sig).toString("hex"))
  let [a, b] = tonelli((x ** 3n + 1n) % base, base)
  let y = greatest ? max(a,b) : min(a,b)
  console.log(x, a, b, greatest ? max(a,b) : min(a,b), a < b, greatest)
  return `0x${x.toString(16).padStart(128,0)}${y.toString(16).padStart(128,0)}`
}

describe("SnarkEpochDataSlasher", function () {
  let instance;
  this.timeout(60000);
  
  before(async () => {
    const Passthrough = await ethers.getContractFactory("TestSlasher");
    // instance = Passthrough.attach('0x5d432D9AA925210DfbCfd967E884C216853dC017');
    instance = await Passthrough.deploy();
  });

  it.skip('blake2xs hash dual test', async () => {
    let data = "0x1ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508c000000000010"
    let res1 = await instance.testHash4(data)
    let res2 = await instance.testHash5(data)
    console.log(res1, res2)
  });

  it.skip('blake2s hash test', async () => {
    let data = "0x1ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508c000000000010"
    let res = await instance.testHash2(data)
    console.log(res)
  });

  it.skip('blake2xs hash test', async () => {
    let data = "0x1ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508c000000000010"
    let res = await instance.testHash3(data)
    console.log(res)
  });

  it('blake2xs hash works', async () => {
    let data = "0x1ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508c000000000010"
    let res = await instance.testHash(data)
    assert(res == '0x58c64608363b3d7f29e6502799625253ea7ddfafac86701f251215113d5c7c0b8a1907e541658e785a6e892c636193280f703ed74dc10a7d7749385f8be43277')
  });

  it('getting BLS key works', async () => {
    let res = await instance.testBLSPublicKey(123, 0)
    console.log(res)
  })

  it('getting signature', async () => {
    let sig = "81 24 214 139 37 73 112 220 63 194 231 197 173 167 239 46 94 101 107 160 159 115 242 183 252 170 81 250 214 62 27 147 212 97 184 163 59 143 18 100 43 60 116 44 20 245 229 128".split(" ").map(a => parseInt(a,10)).reverse()
    let greatest = (sig[0] & 0x80) != 0
    sig[0] = sig[0] & 0x7f
    let x = BigInt("0x"+Buffer.from(sig).toString("hex"))
    let [a, b] = tonelli((x ** 3n + 1n) % base, base)
    let y = greatest ? max(a,b) : min(a,b)
    console.log(x, a, b, greatest ? max(a,b) : min(a,b), a < b, greatest)
    let data = `0x${x.toString(16).padStart(128,0)}${y.toString(16).padStart(128,0)}`
    let [x1, x2, y1, y2] = await instance.testParseG1(data)
    let rx = combine(x1,x2)
    let ry = combine(y1,y2)
    console.log(rx, ry)
    assert((rx**3n + 1n) % base == (ry**2n) % base)
    assert(x == rx && y == ry)
  })

  it('hash to point', async () => {
    let inner_hash = '0x4acae1bcbedcdc9b9576d482873baba0cf5f6afad7f0431edada90b8d8163fadc32ca426f95cd1f110fe6a3a59060e01'
    let extra_data = '0x01000000000080ca' // counter, max nonsigners, epoch
    let [epoch, res, res2] = await instance.testHashing(extra_data, inner_hash)
    console.log(res2, res)
    let arr = [...Buffer.from(res.substr(2), "hex")]
    console.log(arr.slice(0,48))
    let needed = arr.slice(0,48).reverse()
    // Parse to point
    let greatest = (needed[0] & 0x40) == 0
    needed[0] = (needed[0] & 0x7f) >> 7
    let x = BigInt("0x"+Buffer.from(needed).toString("hex"))
    let y1 = findY(x, greatest)
    let y2 = findY(x, !greatest)
    console.log(x, y1, y2)
    let hints = `0x${y1.toString(16).padStart(128,0)}${y2.toString(16).padStart(128,0)}`
    console.log(hints)
    let point = await instance.testParseToG1Scaled(extra_data, inner_hash, hints)
    console.log(point)
  })

  it('test pairing', async () => {
    let sig = [112, 190, 148, 183, 216, 214, 235, 200, 49, 230, 29, 83, 64, 137, 68, 22, 235, 254, 184, 250, 197, 237, 118, 24, 140, 100, 123, 19, 231, 108, 154, 247, 97, 36, 16, 100, 101, 34, 2, 159, 181, 202, 29, 186, 24, 220, 8, 1]
    let sig_point = uncompressSig(sig)
    let [x1, x2, y1, y2] = await instance.testParseG1(sig_point)
    let rx = combine(x1,x2)
    let ry = combine(y1,y2)
    console.log(rx, ry)
    let inner_hash = '0x4acae1bcbedcdc9b9576d482873baba0cf5f6afad7f0431edada90b8d8163fadc32ca426f95cd1f110fe6a3a59060e01'
    let extra_data = '0x01000000000080ca' // counter, max nonsigners, epoch
    let hint = "0x00000000000000000000000000000000010f1b21a9843f63930f0238e646a0218ed0c9651caa54249a7cd60dd7e23dc3a484cc7188024a07f9e806ccc06aeca400000000000000000000000000000000009f1f246e40d187332c0387865aa9198b52108de44abf6a84768c21e2270a3c728690d2a7fdb5f88b20b9333f95135d"
    let res = await instance.testValid(extra_data, inner_hash, sig_point, hint)
  })

})

