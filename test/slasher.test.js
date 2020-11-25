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
  let sig = [...comp].reverse()
  let greatest = (sig[0] & 0x80) != 0
  sig[0] = sig[0] & 0x7f
  let x = BigInt("0x"+Buffer.from(sig).toString("hex"))
  let [a, b] = tonelli((x ** 3n + 1n) % base, base)
  let y = greatest ? max(a,b) : min(a,b)
  // console.log(x, a, b, greatest ? max(a,b) : min(a,b), a < b, greatest)
  return `0x${x.toString(16).padStart(128,0)}${y.toString(16).padStart(128,0)}`
}

async function makeHint(instance, { inner, extra }) {
  let inner_hash = inner
  let extra_data = extra // counter, max nonsigners, epoch
  let [epoch, res, res2] = await instance.testHashing(extra_data, inner_hash)
  // console.log("hash result", res)
  let arr = [...Buffer.from(res.substr(2), "hex")]
  console.log(arr.slice(0, 48))
  let needed = arr.slice(0, 48).reverse()
  // Parse to point
  needed[0] = needed[0] & 0x01
  let x = BigInt("0x" + Buffer.from(needed).toString("hex"))
  let [y1, y2] = findY(x)
  console.log("x y1 y2", x.toString(16), y1.toString(16), y2.toString(16))
  let parsed_x = await instance.testParseToRandom(extra_data, inner_hash)
  console.log('parsed_x', parsed_x)
  let hints = `0x${y1.toString(16).padStart(128, 0)}${y2.toString(16).padStart(128, 0)}`
  // console.log('hint', hints)
  let point = await instance.testParseToG1Scaled(extra_data, inner_hash, hints)
  console.log('point', point)
  return hints
}

async function infoToData(instance, info) {
  let hint = await makeHint(instance, info)
  let sig = uncompressSig(info.sig)
  // console.log(sig, info.sig)
  const header = `0x${info.extra.substr(2)}${info.inner.substr(2)}${'1'.padStart(64, '0')}${sig.substr(2)}${hint.substr(2)}`
  return header
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
/*
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
*/
  const info3 = {
    inner: '0x66bf77133dd2f20f56c8260b3700f74e16df62be968466027bd6ec37a8623641b3e903ef5fce6a3b0b0c565b2eebbd00',
    extra: '0x0000000000000078',
    sig: [158, 72, 75, 77, 22, 142, 29, 140, 254, 187, 120, 168, 130, 101, 64, 42, 52, 228, 184, 126, 98, 5, 138, 79, 140, 175, 201, 239, 204, 135, 133, 91, 112, 23, 38, 184, 7, 175, 137, 12, 90, 119, 71, 93, 221, 106, 246, 128]
  }

  const info1 = {
    inner: '0xcd24f5a3be8f5306767c25e2ef565810f76b96887302a246462dfc7575ad4a7d8ea18220a731e942f3b5eaa5b3f47501',
    extra: '0x0100000000000084',
    sig: [255, 16, 101, 16, 206, 86, 53, 253, 109, 149, 69, 64, 239, 73, 187, 11, 70, 172, 157, 120, 9, 158, 73, 47, 177, 127, 203, 96, 139, 125, 177, 170, 114, 179, 194, 243, 184, 237, 86, 255, 171, 74, 145, 90, 162, 213, 140, 129]
  }

  const info2 = {
    inner: '0xe2ff5106f792bb53d97d035a7e9e7b4616acbb06b57a6a13d8cebd974a581e604bfeeb71ae78c46aa32f7fad4a325c00',
    extra: '0x0400000000000084',
    sig: [229, 250, 227, 43, 229, 82, 245, 110, 165, 20, 37, 182, 226, 91, 223, 215, 187, 70, 115, 225, 32, 43, 120, 250, 44, 137, 216, 236, 210, 240, 57, 188, 28, 224, 161, 231, 138, 215, 154, 7, 240, 104, 166, 105, 159, 165, 80, 129]
  }

  const info4 = {
    inner: '0x100da31ae27858efbbca0704c60831f3630d68defc194e26d25189d7097b5f1ea09231d47c3a74eb3f1daaeb27e3e400',
    extra: '0x0000000000000078',
    sig: [245, 247, 108, 37, 25, 163, 158, 240, 233, 83, 140, 198, 51, 22, 28, 56, 80, 16, 154, 12, 124, 84, 128, 131, 42, 234, 125, 138, 195, 252, 138, 116, 194, 102, 180, 206, 106, 86, 25, 66, 101, 132, 233, 210, 225, 7, 14, 0]
  }

  const info5 = {
    inner: '0xdde0fe1df0eaffa6c326a60fd624d3217b506d19fd7f65d7101c1ac2c8cca06b24fe740bab5fd39a610257c60d998c01',
    extra: '0x0100000000008002',
    sig: [245, 29, 224, 84, 151, 73, 123, 172, 29, 168, 222, 245, 199, 229, 235, 216, 53, 0, 59, 28, 192, 12, 142, 216, 224, 93, 93, 79, 62, 94, 70, 246, 234, 29, 127, 157, 146, 69, 52, 19, 102, 210, 223, 52, 201, 240, 43, 128]
  }

  const info6 = {
    inner: '0xb92cad226bbc34cf100a033c6f9ea5d68878762c3a08af22fb889a5c454d5852114ae18abc25c9eae914282c72355c01',
    extra: '0x0300000000008002',
    sig: [11, 0, 154, 125, 65, 178, 12, 115, 45, 250, 147, 247, 49, 196, 67, 212, 108, 253, 142, 34, 223, 161, 146, 137, 107, 57, 97, 87, 133, 211, 125, 25, 192, 255, 122, 239, 162, 160, 232, 187, 17, 125, 51, 161, 142, 145, 27, 0]
  }
/*
  it('hash to point 1', async () => {
    let res = await makeHint(instance, info1)
    console.log("hint", res)
  })

  it('test pairing 1', async () => {
    let sig_point = uncompressSig(info1.sig)
    console.log("sig", sig_point)
    let [x1, x2, y1, y2] = await instance.testParseG1(sig_point)
    let rx = combine(x1,x2)
    let ry = combine(y1,y2)
    // console.log(rx, ry)
    let inner_hash = info1.inner
    let extra_data = info1.extra
    let hint = await makeHint(instance, info1)
    let res = await instance.testValid(extra_data, inner_hash, sig_point, hint)
    console.log(res)
  })

  it('hash to point 2', async () => {
    let res = await makeHint(instance, info2)
    console.log("hint", res)
  })

  it('test pairing 2', async () => {
    let sig_point = uncompressSig(info2.sig)
    console.log("sig", sig_point)
    let [x1, x2, y1, y2] = await instance.testParseG1(sig_point)
    let rx = combine(x1,x2)
    let ry = combine(y1,y2)
    // console.log(rx, ry)
    let inner_hash = info2.inner
    let extra_data = info2.extra
    let hint = await makeHint(instance, info2)
    let res = await instance.testValid(extra_data, inner_hash, sig_point, hint)
    console.log(res)
  })
*/
  it('test decoding', async () => {
    const header = await infoToData(instance, info1)
    const other = await infoToData(instance, info2)
    const header3 = await infoToData(instance, info3)
    const header4 = await infoToData(instance, info4)
    const header5 = await infoToData(instance, info5)
    const header6 = await infoToData(instance, info6)

      console.log(await instance.getEpochFromData(header))
      console.log(await instance.getEpochFromData(other))
      console.log(await instance.testDecode(header))
      console.log(await instance.testDecode(other))
      console.log("header1", await instance.checkSlash(header))
      console.log("header2", await instance.checkSlash(other))

      console.log("header3", await instance.checkSlash(header3))
      console.log("header4", await instance.checkSlash(header4))

      console.log("header5", await instance.checkSlash(header5))
      console.log("header6", await instance.checkSlash(header6))

      console.log("Header 1", header)
      console.log("Header 2", other)

  })

  it('test', async () => {
    let info = info3
    const header = await infoToData(instance, info)
    let hint = await makeHint(instance, info)
    console.log("hint", hint)
    console.log("header", await instance.checkSlash(header))
    console.log("valid", await instance.testValid(info.extra, info.inner, uncompressSig(info.sig), hint))
  })

})

