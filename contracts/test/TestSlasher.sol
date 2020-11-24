//SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.5.10;

import {SnarkEpochDataSlasher} from "../SnarkEpochDataSlasher.sol";

import {CIP20Lib} from "../CIP20Lib.sol";
import {B12} from "../B12.sol";
import {CeloB12_377Lib} from "../B12.sol";

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

    function testBLSPublicKey(uint16 epoch, uint i) public view returns (uint256, uint256, uint256, uint256, uint256, uint256, uint256, uint256) {
        B12.G2Point memory p = getBLSPublicKey(epoch, i);
        return (p.X.a.a, p.X.a.b, p.X.b.a, p.X.b.b, p.Y.a.a, p.Y.a.b, p.Y.b.a, p.Y.b.b);
    }

    function testParseG1(bytes memory data) public pure returns (uint256, uint256, uint256, uint256) {
        B12.G1Point memory p = B12.parseG1(data, 0);
        return (p.X.a, p.X.b, p.Y.a, p.Y.b);
    }

    function testHashing(bytes memory extra, bytes memory message) public view returns (uint16, bytes memory, bytes memory) {
        return (epochFromExtraData(extra), doHash(abi.encodePacked(extra, message)), abi.encodePacked(extra, message));
    }

    function testParseToG1Scaled(bytes memory extra, bytes memory message, bytes memory hints) public view returns (uint256, uint256, uint256, uint256) {
        B12.G1Point memory p = parseToG1Scaled(doHash(abi.encodePacked(extra, message)), hints);
        return (p.X.a, p.X.b, p.Y.a, p.Y.b);
    }

    function testParseToRandom(bytes memory extra, bytes memory message) public view returns (uint256, uint256) {
        bool greatest;
        B12.Fp memory x;
        (x, greatest) = B12.parseRandomPoint(doHash(abi.encodePacked(extra, message)));
        return (x.a, x.b);
    }

    function testValid(bytes memory extra, bytes memory message, bytes memory sig, bytes memory hints) public view returns (bool) {
        B12.G1Point memory p = parseToG1Scaled(doHash(abi.encodePacked(extra, message)), hints);
        B12.G2Point memory public_key = getBLSPublicKey(100, 0);
        B12.G1Point memory sig_point = B12.parseG1(sig, 0);
        B12.PairingArg[] memory args = new B12.PairingArg[](2);
        args[0] = B12.PairingArg(sig_point, negativeP2());
        args[1] = B12.PairingArg(p, public_key);
        return CeloB12_377Lib.pairing(args);
    }


}
