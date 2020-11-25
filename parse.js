
const fs = require("fs")
const { tonelli } = require("./test/tonelli")

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
  
function main() {
    let data = fs.readFileSync(process.argv[2]).toString()
    // console.log(data)
    let sig = data.match(/sig=\"\[([0-9 ]*)/)[1]
    let extra = data.match(/extra=\"\[([ 0-9]*)/)[1]
    let dta = data.match(/data=\"\[([ 0-9]*)/)[1]
    let sig_arr = sig.split(" ").map(a => parseInt(a,10))
    console.log(`export SIG=${sig_arr}`)
    console.log(`export SIGHEX=${conv(sig)}`)
    console.log(`export SIG_UNCOMPRESSED=${uncompressSig(sig_arr)}`)
    console.log(`export EXTRA_DATA=${conv(extra)}`)
    console.log(`export EPOCH_DATA=${conv(dta)}`)
}

main()

