//SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.5.10;

import {SnarkEpochDataSlasher} from "../SnarkEpochDataSlasher.sol";

import {CIP20Lib} from "../CIP20Lib.sol";

contract TestSlasher is SnarkEpochDataSlasher {

    constructor() public {}

    function testConfig() public pure returns (bytes32) {
        return CIP20Lib.createConfig(32 /* digest size */, 0, 0, 0, 32 /* leaf length */, 0, 64 /* xof digest length*/, 0, 32 /* inner length */, bytes8(0), "ULforxof");
    }

    function testHash(bytes memory data) public view returns (bytes memory) {
        return doHash(data);
    }

    function testHash2(bytes memory data) public view returns (bytes memory) {
        // return CIP20Lib.blake2Xs(data, 64);
        // return CIP20Lib.blake2s(data);
        bytes32 config = CIP20Lib.createConfig(32 /* digest size */, 0, 0, 0, 32 /* leaf length */, 0, 32 /* xof digest length*/, 0, 32 /* inner length */, bytes8(0), bytes8(0));
        return CIP20Lib.blake2sWithConfig(config, "", data);
    }

    function testHash4(bytes memory data) public view returns (bytes memory) {
        // return CIP20Lib.blake2Xs(data, 64);
        // return CIP20Lib.blake2s(data);
        bytes32 config = CIP20Lib.createConfig(32 /* digest size */, 0, 0, 0, 32 /* leaf length */, 0, 64 /* xof digest length*/, 0, 32 /* inner length */, bytes8(0), bytes8(0));
        return CIP20Lib.blake2sWithConfig(config, "", data);
    }

    function testHash5(bytes memory data) public view returns (bytes memory) {
        // return CIP20Lib.blake2Xs(data, 64);
        // return CIP20Lib.blake2s(data);
        bytes32 config1 = CIP20Lib.createConfig(32 /* digest size */, 0, 0, 0, 32 /* leaf length */, 0 /* node offset */, 64 /* xof digest length*/, 0, 32 /* inner length */, bytes8(0), bytes8(0));
        bytes32 config2 = CIP20Lib.createConfig(32 /* digest size */, 0, 0, 0, 32 /* leaf length */, 1, 64 /* xof digest length*/, 0, 32 /* inner length */, bytes8(0), bytes8(0));
        return abi.encodePacked(CIP20Lib.blake2sWithConfig(config1, "", data), CIP20Lib.blake2sWithConfig(config2, "", data));
    }

    function testHash3(bytes memory data) public view returns (bytes memory) {
        // return CIP20Lib.blake2Xs(data, 64);
        // return CIP20Lib.blake2s(data);
        bytes32 config = CIP20Lib.createConfig(32 /* digest size */, 0, 0, 0, 32 /* leaf length */, 0, 32 /* xof digest length*/, 0, 32 /* inner length */, bytes8(0), bytes8(0));
        return CIP20Lib.blake2XsWithConfig(config, "", data, 32);
    }

}
