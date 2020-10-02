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

    function executePrecompile(bytes memory input, uint8 addr, uint256 output_len) 
        internal
        view 
        returns (bytes memory output) {
        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                addr,
                add(input, 0x20),
                mload(input),
                add(output, 0x20),
                output_len
            )
            mstore(output, output_len)
        }

        require(success, "failed");
    }

    function simple(bytes calldata input, uint8 addr, uint256 output_len)
        external
        view
        returns (bytes memory output)
    {
        return executePrecompile(input, addr, output_len);
    }

        function simpleTx(bytes calldata input, uint8 addr, uint256 output_len)
        external
        returns (bytes memory output)
    {
        return executePrecompile(input, addr, output_len);
    }

}
