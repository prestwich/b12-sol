
const ethers = require("ethers")
const fs = require("fs")

async function bench(instance, name) {
    let gasLimit = 1000000000
    let t1 = Date.now()
    let left = await instance[name]({gasLimit})
    let t2 = Date.now()
    let used = gasLimit - left.toNumber()
    console.log(`Time ${t2-t1}, gas ${used} => ${used/(t2-t1)/1000} Mgps`)
}

async function main() {
    let provider = new ethers.providers.JsonRpcProvider()
    let {abi, bytecode} = JSON.parse(fs.readFileSync("artifacts/Bench.json"))
    const Bench = new ethers.ContractFactory(abi, bytecode, provider.getSigner())
    let instance = await Bench.deploy()
    let gasLimit = 1000000000
    await instance.baseline({gasLimit})
    await bench(instance, "baseline")
    await bench(instance, "baseline2")
    await bench(instance, "validatorBLS")
}

main()

