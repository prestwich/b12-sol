//SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.5.10;

import {SnarkEpochDataSlasher} from "../SnarkEpochDataSlasher.sol";

import {CIP20Lib} from "../CIP20Lib.sol";
import {B12} from "../B12.sol";
import {CeloB12_377Lib} from "../B12.sol";

contract Bench is SnarkEpochDataSlasher {

    constructor() public {}

    function baseline() public view returns (uint) {
        uint a = 0;
        for (uint i = 0; i < 1000000; i++) {
            a += 123 * a + (a << 123) % (i*a | 1);
        }
        return gasleft();
    }

    function baseline2() public view returns (uint) {
        bytes memory b = new bytes(1000);
        for (uint i = 0; i < 1000000; i++) {
            b[i%1000] = byte(bytes32(i));
        }
        return gasleft();
    }

    function validatorBLS() public view returns (uint) {
        bytes memory output = new bytes(192);
        bytes memory input = abi.encodePacked(uint256(0), uint256(123));
        bool success;
        for (uint i = 0; i < 300000; i++) {
            assembly {
                success := staticcall(gas(), 235 /* 0xff - 20 */, add(0x20, input), 64, add(0x20, output), 192)
            }
        }
        return gasleft();
    }

}
