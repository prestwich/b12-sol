//SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.5.10;

import {TypedMemView} from "@summa-tx/memview.sol/contracts/TypedMemView.sol";

import {CIP20Lib} from "./CIP20Lib.sol";
import {CeloB12_377Lib} from "./B12.sol";
import {B12} from "./B12.sol";

contract SnarkEpochDataSlasher {

    using TypedMemView for bytes;
    using TypedMemView for bytes29;

    function slash(uint16 epoch, uint8 counter1, uint32 maximum_non_signers1, bytes memory bhhash1, uint256 bitmap1, bytes memory sig1, bytes memory hint1,
         uint8 counter2, uint32 maximum_non_signers2, bytes memory bhhash2, uint256 bitmap2, bytes memory sig2, bytes memory hint2) public view {
        bytes memory data1 = abi.encodePacked(counter1, epoch, maximum_non_signers1, bhhash1);
        bytes memory data2 = abi.encodePacked(counter2, epoch, maximum_non_signers2, bhhash2);
        slash2(epoch, data1, bitmap1, sig1, hint1, data2, bitmap2, sig2, hint2);
    }

    // look this up
    function negativeP2() internal pure returns (B12.G2Point memory p) {
    }

    function mapToG1(B12.Fp memory x, B12.Fp memory hint1, B12.Fp memory hint2, bool greatest)
        internal
        view
        returns (B12.G1Point memory) {
        B12.Fp memory base = B12.Fp(0x1ae3a4617c510eac63b05c06ca1493b, 0x1a22d9f300f5138f1ef3622fba094800170b5d44300000008508c00000000001);
        B12.Fp memory res = B12.fpAdd(B12.fpModExp(x, 3, base), B12.Fp(0,1));
        B12.Fp memory sqhint1 = B12.fpModExp(hint1, 2, base);
        B12.Fp memory sqhint2 = B12.fpModExp(hint2, 2, base);
        require(B12.FpEq(sqhint1, res));
        require(B12.FpEq(sqhint2, res));
        require(B12.fpGt(sqhint1, sqhint2));
        B12.G1Point memory p = B12.G1Point(x, greatest ? hint1 : hint2);
        B12.G1Point memory q = CeloB12_377Lib.g1Mul(p, 30631250834960419227450344600217059328);
        return q;
    }

    function parsePoint(bytes memory h) internal pure returns (B12.Fp memory, bool) {
        bytes29 ref1 = h.ref(0).postfix(h.length, 0);
        uint256 a1 = ref1.indexUint(0, 32);
        uint256 b1 = ref1.indexUint(32, 32);
        // 512 - 377 = 135
        return (B12.Fp(a1 >> 135, (a1 << 135) | (b1 >> 135)), (b1 >> 134) & 1 == 0);
    }

    function slash2(uint16 epoch, bytes memory data1, uint256 bitmap1, bytes memory sig1, bytes memory hint1,
                                  bytes memory data2, uint256 bitmap2, bytes memory sig2, bytes memory hint2) internal view returns (bool) {
        require(isValid(epoch, data1, bitmap1, sig1, hint1));
        require(isValid(epoch, data2, bitmap2, sig2, hint2));
    }

    function getBLSPublicKey(uint16 epoch, uint i) internal view returns (bytes memory) {

    }

    function isValid(uint16 epoch, bytes memory data, uint256 bitmap, bytes memory sig, bytes memory hints) internal view returns (bool) {
        bytes32 config = CIP20Lib.createConfig(32, 0, 0, 0, 32, 0, 64 /* xof digest length*/, 0, 32 /* inner length */, bytes8(0), "ULforxof");
        bytes memory h = CIP20Lib.blake2XsWithConfig(config, new bytes(0), data, 32);
        bool greatest;
        B12.Fp memory x;
        (x, greatest) = parsePoint(h);
        B12.G1Point memory p = mapToG1(x, B12.parseFp(hints, 0), B12.parseFp(hints, 64), greatest);
        bool prev = false;
        B12.G2Point memory agg = B12.G2Point(B12.Fp2(B12.Fp(0, 0), B12.Fp(0, 0)), B12.Fp2(B12.Fp(0, 0), B12.Fp(0, 0)));
        uint num = 0;
        for (uint i = 0; i < 150; i++) {
            if (bitmap & 1 == 1) {
                num++;
                bytes memory public_key_data = getBLSPublicKey(epoch, i);
                B12.G2Point memory public_key = B12.parseG2(public_key_data, 0);
                if (!prev) {
                    agg = public_key;
                } else {
                    agg = CeloB12_377Lib.g2Add(agg, public_key);
                }
            }
            bitmap = bitmap >> 1;
        }
        // TODO: check that there were enough signatures
        B12.G1Point memory sig_point = B12.parseG1(sig, 0);
        B12.PairingArg[] memory args = new B12.PairingArg[](2);
        args[0] = B12.PairingArg(sig_point, negativeP2());
        args[1] = B12.PairingArg(p, agg);
        return CeloB12_377Lib.pairing(args);
    }

}
