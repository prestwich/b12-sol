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
  return [max(a,b), min(a,b)]
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
    let res = await instance.testBLSPublicKey(1, 0)
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

  it('hash to point 1', async () => {
    let inner_hash = '0x26be7357a1b825b18f823bf3a774714f8e04c25553b5047db1e280e46317b260724026bb187134e35c681c5cbad04300'
    let extra_data = '0x0200000000000080' // counter, max nonsigners, epoch
    let [epoch, res, res2] = await instance.testHashing(extra_data, inner_hash)
    console.log("hash result", res)
    let arr = [...Buffer.from(res.substr(2), "hex")]
    console.log(arr.slice(0,48))
    let needed = arr.slice(0,48).reverse()
    // Parse to point
    needed[0] = needed[0] & 0x01
    let x = BigInt("0x"+Buffer.from(needed).toString("hex"))
    let [y1,y2] = findY(x)
    console.log("x y1 y2", x, y1, y2)
    let parsed_x = await instance.testParseToRandom(extra_data, inner_hash)
    console.log('parsed_x', parsed_x)
    let hints = `0x${y1.toString(16).padStart(128,0)}${y2.toString(16).padStart(128,0)}`
    console.log('hint', hints)
    let point = await instance.testParseToG1Scaled(extra_data, inner_hash, hints)
    console.log('point', point)
  })

  it('hash to point 2', async () => {
    let inner_hash = '0xff0d8dd0bfd78e6465071e4359cf7d9c4252b5206616060b7b97dd92a03f586ed5c975552c6d2eb05b326216d4dff300'
    let extra_data = '0x0200000000000080' // counter, max nonsigners, epoch
    let [epoch, res, res2] = await instance.testHashing(extra_data, inner_hash)
    console.log(res2, res)
    let arr = [...Buffer.from(res.substr(2), "hex")]
    console.log(arr.slice(0,48))
    let needed = arr.slice(0,48).reverse()
    needed[0] = needed[0] & 0x01
    // Parse to point
    let x = BigInt("0x"+Buffer.from(needed).toString("hex"))
    let [y1,y2] = findY(x)
    console.log("x y1 y2", x, y1, y2)
    let hints = `0x${y1.toString(16).padStart(128,0)}${y2.toString(16).padStart(128,0)}`
    console.log('hint', hints)
    let point = await instance.testParseToG1Scaled(extra_data, inner_hash, hints)
    console.log('point', point)
  })

  it('test pairing 1', async () => {
    let sig = [254, 228, 243, 96, 85, 245, 68, 102, 165, 10, 73, 208, 247, 186, 48, 190, 182, 250, 124, 182, 200, 54, 245, 188, 145, 73, 181, 220, 56, 37, 182, 81, 234, 138, 94, 175, 102, 73, 10, 205, 128, 249, 83, 86, 226, 193, 159, 1]
    let sig_point = uncompressSig(sig)
    console.log("sig", sig_point)
    let [x1, x2, y1, y2] = await instance.testParseG1(sig_point)
    let rx = combine(x1,x2)
    let ry = combine(y1,y2)
    console.log(rx, ry)
    let inner_hash = '0x26be7357a1b825b18f823bf3a774714f8e04c25553b5047db1e280e46317b260724026bb187134e35c681c5cbad04300'
    let extra_data = '0x0200000000000080' // counter, max nonsigners, epoch
    // this was calculated in the previous test case
    let hint = "0x000000000000000000000000000000000169655b41d8a50966842c54b2da6db193307de5591ad270fb526422e3e3562e7689dfdf8d14104b009a0a2d4d7c0fc5000000000000000000000000000000000044d4ead5ec6be15fb6d96bb9c6db8986f25c0da7da411e23a0fe0cd625f1d1a0817d64a2ebefb5846eb5d2b283f03c"
    let res = await instance.testValid(extra_data, inner_hash, sig_point, hint)
    console.log(res)
  })

  it('test pairing 2', async () => {
    let sig = [212, 56, 43, 123, 117, 175, 115, 234, 113, 187, 104, 128, 153, 5, 65, 116, 47, 137, 117, 232, 56, 247, 226, 6, 122, 135, 251, 19, 53, 57, 247, 86, 39, 115, 6, 60, 8, 53, 108, 38, 24, 109, 202, 29, 108, 235, 19, 1]
    let sig_point = uncompressSig(sig)
    console.log("sig", sig_point)
    let [x1, x2, y1, y2] = await instance.testParseG1(sig_point)
    let rx = combine(x1,x2)
    let ry = combine(y1,y2)
    console.log(rx, ry)
    let inner_hash = '0xff0d8dd0bfd78e6465071e4359cf7d9c4252b5206616060b7b97dd92a03f586ed5c975552c6d2eb05b326216d4dff300'
    let extra_data = '0x0200000000000080' // counter, max nonsigners, epoch
    // this was calculated in the previous test case
    let hint = "0x00000000000000000000000000000000018f73b0f9f89018577c1967ba35815e988789000c8a6a4693c5701c65d0979a08a3acf13a0b77dde56fab80856375fc00000000000000000000000000000000001ec6951dcc80d26ebeec58b26bc7dc819b50f2f46aa9488b2df2135438b0660e67b052f5f488229f99147f7a9c8a05"
    let res = await instance.testValid(extra_data, inner_hash, sig_point, hint)
    console.log(res)
  })

})

