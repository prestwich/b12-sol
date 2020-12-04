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
        for (uint i = 0; i < 200000; i++) {
            assembly {
                success := staticcall(gas(), 235 /* 0xff - 20 */, add(0x20, input), 64, add(0x20, output), 192)
            }
        }
        return gasleft();
    }

    function testAggregation() public view returns (uint) {
        bool prev = false;
        bytes memory buffer = new bytes(256);
        B12.G2Point memory public_key = B12.G2Point(B12.Fp2(B12.Fp(0, 0), B12.Fp(0, 0)), B12.Fp2(B12.Fp(0, 0), B12.Fp(0, 0)));
        getBLSPublicKey(123, 0, public_key, buffer);
        B12.G2Point memory agg = B12.G2Point(B12.Fp2(B12.Fp(0, 0), B12.Fp(0, 0)), B12.Fp2(B12.Fp(0, 0), B12.Fp(0, 0)));
        getBLSPublicKey(123, 0, agg, buffer);
        for (uint i = 0; i < 150; i++) {
            getBLSPublicKey(123, 0, public_key, buffer);
            if (!prev) {
                /*
                    agg.X.a.a = public_key.X.a.a;
                    agg.X.b.a = public_key.X.b.a;
                    agg.Y.a.a = public_key.Y.a.a;
                    agg.Y.b.a = public_key.Y.b.a;
                    agg.X.a.b = public_key.X.a.b;
                    agg.X.b.b = public_key.X.b.b;
                    agg.Y.a.b = public_key.Y.a.b;
                    agg.Y.b.b = public_key.Y.b.b;
                */
                agg = public_key;
                prev = true;
            } else {
                agg = CeloB12_377Lib.g2Add(agg, public_key);
            }
        }
        return gasleft();
    }

}
