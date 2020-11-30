
const fs = require("fs")
const { tonelli } = require("./test/tonelli")
const ethers = require("ethers")

function conv(arg) {
    return Buffer.from(arg.split(" ").map(a => parseInt(a,10))).toString("hex")
}

function max(a,b) {
    if (a < b) return b
    else return a
  }
  
function min(a,b) {
    if (a > b) return b
    else return a
}

let base = 0x1ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508c00000000001n

function uncompressSig(comp) {
    let sig = comp.reverse()
    let greatest = (sig[0] & 0x80) == 0
    sig[0] = sig[0] & 0x7f
    let x = BigInt("0x"+Buffer.from(sig).toString("hex"))
    let [a, b] = tonelli((x ** 3n + 1n) % base, base)
    let y = greatest ? max(a,b) : min(a,b)
    return `0x${x.toString(16).padStart(128,0)}${y.toString(16).padStart(128,0)}`
}
  
async function main() {
    let provider = new ethers.providers.JsonRpcProvider()
    let res = await provider.send('istanbul_getEpochValidatorSetData', ["0x12a2"])
    let info = {
      inner: Buffer.from(res.bhhash, "base64").toString("hex"),
      extra: Buffer.from(res.extraData, "base64").toString("hex"),
      sig: [... (Buffer.from(res.sig, "base64"))]
    }
    // console.log(info)
    // console.log(data)
    console.log(`export SIG=${info.sig}`)
    console.log(`export EXTRA_DATA=${info.extra}`)
    console.log(`export EPOCH_DATA=${Buffer.from(res.message, "base64").toString("hex")}`)
}

main()

