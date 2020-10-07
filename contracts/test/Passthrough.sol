//SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.5.10;

import {B12_377Lib} from "../B12Lib.sol";

contract Passthrough {
    using B12_377Lib for B12_377Lib.G1Point;
    using B12_377Lib for B12_377Lib.G2Point;
    using B12_377Lib for B12_377Lib.Fp;
    using B12_377Lib for B12_377Lib.Fp2;
    using B12_377Lib for bytes;

    constructor() public {}

    function dumpMem(uint256 idx) internal {
        uint256 a;
        uint256 b;
        uint256 c;
        uint256 d;

        assembly {
            a := mload(add(idx, 0x00))
            b := mload(add(idx, 0x20))
            c := mload(add(idx, 0x40))
            d := mload(add(idx, 0x60))
        }
    }

    function executePrecompile(
        bytes memory input,
        uint8 addr,
        uint256 output_len
    ) internal view returns (bytes memory output) {
        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                addr,
                add(input, 0x20),   // location
                mload(input),       // length
                add(output, 0x20),  // location
                output_len          // length
            )
            mstore(output, output_len)
        }

        require(success, "failed");
    }

    function simple(
        bytes calldata input,
        uint8 addr,
        uint256 output_len
    ) external view returns (bytes memory) {
        return executePrecompile(input, addr, output_len);
    }

    function simpleTx(
        bytes calldata input,
        uint8 addr,
        uint256 output_len
    ) external returns (bytes memory) {
        return executePrecompile(input, addr, output_len);
    }

    function g1Add(bytes calldata args) external view returns (bytes memory) {
        B12_377Lib.G1Point memory a = args.parseG1(0);
        B12_377Lib.G1Point memory b = args.parseG1(4 * 32);
        return a.g1Add(b).serializeG1();
    }

    function testParseG1(bytes calldata arg)
        external
        pure
        returns (uint256[4] memory ret)
    {
        B12_377Lib.G1Point memory a = arg.parseG1(0);
        ret[0] = a.X.a;
        ret[1] = a.X.b;
        ret[2] = a.Y.a;
        ret[3] = a.Y.b;
    }

    function testSerializeG1(
        uint256 w,
        uint256 x,
        uint256 y,
        uint256 z
    ) external pure returns (bytes memory) {
        B12_377Lib.G1Point memory a;
        a.X.a = w;
        a.X.b = x;
        a.Y.a = y;
        a.Y.b = z;

        return a.serializeG1();
    }
}
