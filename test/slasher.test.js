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

  it('getting BLS public key', async () => {
    console.log(await instance.validatorBLSPublicKeyFromSet(0, 123))
  })

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

  it('test from RPC', async () => {
    let res = await ethers.provider.send('istanbul_getEpochValidatorSetData', ["0xa"])
    let info = {
      inner: "0x" + Buffer.from(res.bhhash, "base64").toString("hex"),
      extra: "0x" + res.attempts.toString(16).padStart(2, '0') + Buffer.from(res.extraData, "base64").toString("hex"),
      sig: Buffer.from(res.sig, "base64")
    }
    console.log(info)
    let header = await infoToData(instance, info)
    console.log(header)
    console.log(await instance.getEpochFromData(header))
    console.log(await instance.testDecode(header))
    console.log("header", await instance.checkSlash(header))
  })

  function conv(arg) {
    return Buffer.from(arg.split(" ").map(a => parseInt(a,10))).toString("hex")
  }

  function make(a) {
    return uncompressSig([...(Buffer.from(conv(a), 'hex'))])
  }

  it.skip('test aggregation', async () => {

    let sig0 = make("252 197 202 189 148 31 167 22 52 236 212 157 48 200 201 139 184 145 189 221 160 19 14 68 129 239 26 35 91 23 245 115 37 204 103 191 8 139 26 63 93 144 188 10 242 124 98 1")
    let sig1 = make("98 206 56 100 204 210 190 216 160 13 153 63 247 15 29 68 228 253 145 129 97 200 45 168 31 34 56 84 8 216 114 82 76 23 250 235 5 237 139 197 37 19 0 220 10 126 15 1")
    let sig2 = make("231 85 183 177 47 227 32 66 33 106 75 254 114 44 28 211 165 61 238 64 180 21 65 102 0 154 105 158 87 42 104 126 212 22 127 54 218 62 109 50 14 188 196 24 34 25 109 0")
    let sig0a = make("252 197 202 189 148 31 167 22 52 236 212 157 48 200 201 139 184 145 189 221 160 19 14 68 129 239 26 35 91 23 245 115 37 204 103 191 8 139 26 63 93 144 188 10 242 124 98 129")
    let sig1a = make("98 206 56 100 204 210 190 216 160 13 153 63 247 15 29 68 228 253 145 129 97 200 45 168 31 34 56 84 8 216 114 82 76 23 250 235 5 237 139 197 37 19 0 220 10 126 15 129")
    let sig2a = make("231 85 183 177 47 227 32 66 33 106 75 254 114 44 28 211 165 61 238 64 180 21 65 102 0 154 105 158 87 42 104 126 212 22 127 54 218 62 109 50 14 188 196 24 34 25 109 128")

    let res = [
      48, 196,   2, 159, 203,  91,  62,  37, 173,  30,
     141, 251, 141,  50,  33, 186, 192,  50, 157, 144,
     124,   8, 173, 119,  98, 153,  99, 169, 228, 153,
      96, 241, 235,  83, 163, 114,   3,  45,   1, 155,
      62, 189,  75,  48, 103,  86,   9,   0
   ]
    console.log(uncompressSig(res))
    console.log(sig0, sig1, sig2)

    let k0 = "0x4fa3f67fc913878b068d1fa1cdddc54913d3bf988dbe5a36a20fa888f20d4894c408a6773f3d7bde11154f2a3076b700d345a42fd25a0e5e83f4db5586ac7979ac2053cd95d8f2efd3e959571ceccaa743e02cf4be3f5d7aaddb0b06fc9aff0088ca9ae8b27909d810e196f07e21c799c9d70b972d4cb29071b8e40f6e6e37b98779cc221c8f0950d100ba877e4311002457eabb357c025a9175544325925887935edb4180e0eccc7c78d2092abd283a79d74d5b42aca686824f9d554cc09c00"
    let k1 =  "0x362b72c3b63d2980bb2087ec1db8dea03a614fc9db86b0b6fbacd43e530225cff131f6db82356a21f057b365cc0b65010711b131cb84d6a742d06f5000c35069f2cfff04f87f21b3c71aeeefa0f84303dffebefaaa70a327d20d1f6fb5b23401f5f34e3dc7c2b4d8330f227ed394a37df8a5c99d5b97e8c6a0ab7756f81331fc57efc5810e6ea4758cc1fd29c96248000a1f349803a7cc4d3a81510588ee3ed7b4c2d96b19d1682e34e62a1be11d12cd4361c550ce5f928481825c958c628900"
    let k2 = "0x2c8f3e882f730ac7ee1ee827ea15d9e519436ea7f499ea0fbc0ac75f457474befffe76978ee4bff8b8f2a9626cd63f01e058585440fa3016b09bb87450c050ea2f2fb636c19c607593bd2fe9de5d11656a2afca17d1df583de3c405caa78010026318e124849b03a24da37b61c20c1fc56ab4789d412f2f9c59563bf1e4b1d15fbc43a309eb5511b554410b8a7cd2c0147b8bf53160d2981f425c5568dec78e3a0cb072a9d33a3c14f870e70f9b870487f448ebe059eca98a8e49ba12f859800"

    console.log("key", await instance.testKeyAggregation(k0, k1, k2))
    console.log(await instance.testAggregation(sig0, sig1, sig2))
    console.log(await instance.testAggregation(sig0, sig1, sig2a))
    console.log(await instance.testAggregation(sig0, sig1a, sig2))
    console.log(await instance.testAggregation(sig0, sig1a, sig2a))
    console.log(await instance.testAggregation(sig0a, sig1, sig2))
    console.log(await instance.testAggregation(sig0a, sig1, sig2a))
    console.log(await instance.testAggregation(sig0a, sig1a, sig2))
    console.log(await instance.testAggregation(sig0a, sig1a, sig2a))

    let weird = '0x0100000080000044717494530db2abca4866607a1c5a43183f21b7b5b5cdbfe89e64f67551c1eb97c8c63c60568afc58b0cc51998d9d230100000000000000000000000000000000000000000000000000000000000000070000000000000000000000000000000000b4ef893242e667d75205223b3a084ebba8abe416bcab88bd44ac48812e8e8c72f7544a1cd2fce7d62c42cd9964b19a000000000000000000000000000000000054111475eec2a1ad8504fae10119b568ddb543b8a912fd2e97a14409aab253036b1e8998e01141c14d7fdde33f836a00000000000000000000000000000000014cd5a913e7c1df5d5cc6983248ea1bbb25b07708f8da3fbe0bb991df69ceed74a9b4a3c2286f7b7988e009e0ffaf4c000000000000000000000000000000000061649d03dd4f0b68de3f283a585f1f5efd297bf7fc394f60e7a89dda9f7912a261a8a06dd790850b7fdff61f0050b5'

    console.log(await instance.getEpochFromData(weird))
    console.log(await instance.testDecode(weird))
    console.log("header1", await instance.checkSlash(weird))

  })

  it('test decoding', async () => {
    const header = await infoToData(instance, info1)
    const other = await infoToData(instance, info2)
    const header3 = await infoToData(instance, info3)
    const header4 = await infoToData(instance, info4)
    const header5 = await infoToData(instance, info5)
    const header6 = await infoToData(instance, info6)

    
      console.log(await instance.getEpochFromData(header))
      console.log(await instance.getEpochFromData(other))
      console.log(await instance.testDecode(header5))
      console.log(await instance.testDecode(header6))
      console.log("header1", await instance.checkSlash(header))
      console.log("header2", await instance.checkSlash(other))

      console.log("header3", await instance.checkSlash(header3))
      console.log("header4", await instance.checkSlash(header4))

      console.log("header5", await instance.checkSlash(header5))
      console.log("header6", await instance.checkSlash(header6))

      console.log("Header 1", header)
      console.log("Header 2", other)

  })
/*
  it('test', async () => {
    let info = info3
    const header = await infoToData(instance, info)
    let hint = await makeHint(instance, info)
    console.log("hint", hint)
    console.log("header", await instance.checkSlash(header))
    console.log("valid", await instance.testValid(info.extra, info.inner, uncompressSig(info.sig), hint))
  })
*/
})

