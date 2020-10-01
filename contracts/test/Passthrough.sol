//SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.6.8;

import {B12_377Lib} from "../B12Lib.sol";
import "@nomiclabs/buidler/console.sol";

contract Passthrough {
    using B12_377Lib for B12_377Lib.G1Point;
    using B12_377Lib for B12_377Lib.G2Point;
    using B12_377Lib for B12_377Lib.Fp;
    using B12_377Lib for B12_377Lib.Fp2;

    constructor() public {}

    function g1Add(bytes calldata input, bytes calldata output) external view {
        B12_377Lib.G1Point memory a = g1FromBytes(input, 0);
        B12_377Lib.G1Point memory b = g1FromBytes(input, 128);
        B12_377Lib.G1Point memory res = g1FromBytes(output, 0);

        a.g1Add(b);

        require(a.g1Eq(res), "g1Add failed");
    }
}
