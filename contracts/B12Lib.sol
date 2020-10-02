//SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.6.8;
pragma experimental ABIEncoderV2;

// largely based on 
// https://github.com/ralexstokes/deposit-verifier/blob/master/deposit_verifier.sol

library B12_381Lib {
    uint8 constant G1_ADD = 10;
    uint8 constant G1_MUL = 11;
    uint8 constant G1_MULTI_EXP = 12;
    uint8 constant G2_ADD = 13;
    uint8 constant G2_MUL = 14;
    uint8 constant G2_MULTI_EXP = 15;
    uint8 constant PAIRING = 16;
    uint8 constant MAP_TO_G1 = 17;
    uint8 constant MAP_TO_G2 = 18;

    // Fp is a field element with the high-order part stored in `a`.
    struct Fp {
        uint256 a;
        uint256 b;
    }

    // Fp2 is an extension field element with the coefficient of the
    // quadratic non-residue stored in `b`, i.e. p = a + i * b
    struct Fp2 {
        Fp a;
        Fp b;
    }

    // G1Point represents a point on BLS12-377 over Fp with coordinates (X,Y);
    struct G1Point {
        Fp X;
        Fp Y;
    }

    // G2Point represents a point on BLS12-377 over Fp2 with coordinates (X,Y);
    struct G2Point {
        Fp2 X;
        Fp2 Y;
    }

    struct G1MultiExpArg {
        G1Point X;
        uint256 scalar;
    }

    struct G2MultiExpArg {
        G2Point X;
        uint256 scalar;
    }

    struct PairingArg {
        G1Point X;
        G2Point Y;
    }

        function FpEq(B12_377Lib.Fp memory a, B12_377Lib.Fp memory b)
        internal
        pure
        returns (bool)
    {
        return (a.a == b.a && a.b == b.b);
    }

    function Fp2Eq(B12_377Lib.Fp2 memory a, B12_377Lib.Fp2 memory b)
        internal
        pure
        returns (bool)
    {
        return FpEq(a.a, b.a) && FpEq(a.b, b.b);
    }

    function g1Eq(B12_377Lib.G1Point memory a, B12_377Lib.G1Point memory b)
        internal
        pure
        returns (bool)
    {
        return FpEq(a.X, b.X) && FpEq(a.Y, b.Y);
    }

    function g1Eq(B12_377Lib.G2Point memory a, B12_377Lib.G2Point memory b)
        internal
        pure
        returns (bool)
    {
        return (Fp2Eq(a.X, b.X) && Fp2Eq(a.Y, b.Y));
    }

    function g1FromBytes(bytes memory input, uint256 offset)
        internal
        pure
        returns (B12_377Lib.G1Point memory ret)
    {
        require(input.length >= offset + 128, "overrun");
        uint256 ptr;
        assembly {
            ptr := add(add(input, 0x20), offset) // ((input + 20) + offset)
            mstore(add(ret, 0x00), mload(add(ptr, 0x00))) // ret.X.a
            mstore(add(ret, 0x20), mload(add(ptr, 0x20))) // ret.X.b
            mstore(add(ret, 0x40), mload(add(ptr, 0x40))) // ret.Y.a
            mstore(add(ret, 0x60), mload(add(ptr, 0x60))) // ret.Y.b
        }
    }

    function g2FromBytes(bytes memory input, uint256 offset)
        internal
        pure
        returns (B12_377Lib.G2Point memory ret)
    {
        require(input.length >= offset + 256, "overrun");
        uint256 ptr;
        assembly {
            ptr := add(add(input, 0x20), offset)
            mstore(add(ret, 0x00), mload(add(ptr, 0x00))) // ret.X.a.a
            mstore(add(ret, 0x20), mload(add(ptr, 0x20))) // ret.X.a.b
            mstore(add(ret, 0x40), mload(add(ptr, 0x40))) // ret.X.b.a
            mstore(add(ret, 0x60), mload(add(ptr, 0x60))) // ret.X.b.b
            mstore(add(ret, 0x80), mload(add(ptr, 0x80))) // ret.Y.a.a
            mstore(add(ret, 0xa0), mload(add(ptr, 0xa0))) // ret.Y.a.b
            mstore(add(ret, 0xc0), mload(add(ptr, 0xc0))) // ret.Y.b.a
            mstore(add(ret, 0xe0), mload(add(ptr, 0xe0))) // ret.Y.b.b
        }
    }

    // Overwrites A
    function g1Add(G1Point memory a, G1Point memory b) internal view {
        uint256[8] memory input;
        input[0] = a.X.a;
        input[1] = a.X.b;
        input[2] = a.Y.a;
        input[3] = a.Y.b;

        input[4] = b.X.a;
        input[5] = b.X.b;
        input[6] = b.Y.a;
        input[7] = b.Y.b;

        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                G1_ADD,
                input,
                256,
                a, // reuse the memory to avoid growing
                128
            )
            // deallocate the input, leaving dirty memory
            mstore(0x40, input)
        }
        require(success, "g1 add precompile failed");
    }

    // Overwrites A
    function g1Mul(G1Point memory a, uint256 scalar) internal view {
        uint256[5] memory input;
        input[0] = a.X.a;
        input[1] = a.X.b;
        input[2] = a.Y.a;
        input[3] = a.Y.b;

        input[4] = scalar;

        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                G1_MUL,
                input,
                160,
                a, // reuse the memory to avoid growing
                128
            )
            // deallocate the input, leaving dirty memory
            mstore(0x40, input)
        }
        require(success, "g1 mul precompile failed");
    }

    function g1MultiExp(G1MultiExpArg[] memory argVec)
        internal
        view
        returns (G1Point memory c)
    {
        uint256 len = argVec.length;
        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                G1_MULTI_EXP,
                add(argVec, 0x20), // the body of the array
                mul(160, len), // 160 bytes per arg
                c, // write directly to the already allocated result
                128
            )
            // deallocate the input, leaving dirty memory
        }
        require(success, "g1 multiExp precompile failed");
    }

    // Overwrites A
    function g2Add(G2Point memory a, G2Point memory b) internal view {
        uint256[16] memory input;
        input[0] = a.X.a.a;
        input[1] = a.X.a.b;
        input[2] = a.X.b.a;
        input[3] = a.X.b.b;

        input[4] = a.Y.a.a;
        input[5] = a.Y.a.b;
        input[6] = a.Y.b.a;
        input[7] = a.Y.b.b;

        input[8] = b.X.a.a;
        input[9] = b.X.a.b;
        input[10] = b.X.b.a;
        input[11] = b.X.b.b;

        input[12] = b.Y.a.a;
        input[13] = b.Y.a.b;
        input[14] = b.Y.b.a;
        input[15] = b.Y.b.b;

        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                G2_ADD,
                input,
                512,
                a, // reuse the memory to avoid growing
                256
            )
            // deallocate the input, leaving dirty memory
            mstore(0x40, input)
        }
        require(success, "g2 add precompile failed");
    }

    // Overwrites A
    function g2Mul(G2Point memory a, uint256 scalar) internal view {
        uint256[9] memory input;

        input[0] = a.X.a.a;
        input[1] = a.X.a.b;
        input[2] = a.X.b.a;
        input[3] = a.X.b.b;

        input[4] = a.Y.a.a;
        input[5] = a.Y.a.b;
        input[6] = a.Y.b.a;
        input[7] = a.Y.b.b;

        input[8] = scalar;

        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                G2_MUL,
                input,
                288,
                a, // reuse the memory to avoid growing
                256
            )
            // deallocate the input, leaving dirty memory
            mstore(0x40, input)
        }
        require(success, "g2 mul precompile failed");
    }

    function g2MultiExp(G2MultiExpArg[] memory argVec)
        internal
        view
        returns (G1Point memory c)
    {
        uint256 len = argVec.length;
        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                G2_MULTI_EXP,
                add(argVec, 0x20), // the body of the array
                mul(288, len), // 288 bytes per arg
                c, // write directly to the already allocated result
                256
            )
            // deallocate the input, leaving dirty memory
        }
        require(success, "g2 multiExp precompile failed");
    }

    function pairing(PairingArg[] memory argVec)
        internal
        view
        returns (bool result)
    {
        uint256 len = argVec.length;
        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                PAIRING,
                add(argVec, 0x20), // the body of the array
                mul(384, len), // 384 bytes per arg
                mload(0x40), // write to earliest freemem
                32
            )
            result := mload(mload(0x40)) // load what we just wrote
        }
        require(success, "pairing precompile failed");
    }

    function mapToG1(Fp memory a) internal view returns (G1Point memory b) {
        uint256[2] memory input;
        input[0] = a.a;
        input[1] = a.b;

        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                MAP_TO_G1,
                input, // the body of the array
                64,
                b, // write directly to pre-allocated result
                128
            )
            // deallocate the input, leaving dirty memory
            mstore(0x40, input)
        }
    }

    function mapToG2(Fp2 memory a) internal view returns (G2Point memory b) {
        uint256[4] memory input;
        input[0] = a.a.a;
        input[1] = a.a.b;
        input[2] = a.b.a;
        input[3] = a.b.b;

        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                MAP_TO_G2,
                input, // the body of the array
                128,
                b, // write directly to pre-allocated result
                256
            )
            // deallocate the input, leaving dirty memory
            mstore(0x40, input)
        }
    }
}

library B12_377Lib {
    uint8 constant G1_ADD = 19;
    uint8 constant G1_MUL = 20;
    uint8 constant G1_MULTI_EXP = 21;
    uint8 constant G2_ADD = 22;
    uint8 constant G2_MUL = 23;
    uint8 constant G2_MULTI_EXP = 24;
    uint8 constant PAIRING = 25;

    // Fp is a field element with the high-order part stored in `a`.
    struct Fp {
        uint256 a;
        uint256 b;
    }

    // Fp2 is an extension field element with the coefficient of the
    // quadratic non-residue stored in `b`, i.e. p = a + i * b
    struct Fp2 {
        Fp a;
        Fp b;
    }

    // G1Point represents a point on BLS12-377 over Fp with coordinates (X,Y);
    struct G1Point {
        Fp X;
        Fp Y;
    }

    // G2Point represents a point on BLS12-377 over Fp2 with coordinates (X,Y);
    struct G2Point {
        Fp2 X;
        Fp2 Y;
    }

    struct G1MultiExpArg {
        G1Point X;
        uint256 scalar;
    }

    struct G2MultiExpArg {
        G2Point X;
        uint256 scalar;
    }

    struct PairingArg {
        G1Point X;
        G2Point Y;
    }

        function FpEq(B12_377Lib.Fp memory a, B12_377Lib.Fp memory b)
        internal
        pure
        returns (bool)
    {
        return (a.a == b.a && a.b == b.b);
    }

    function Fp2Eq(B12_377Lib.Fp2 memory a, B12_377Lib.Fp2 memory b)
        internal
        pure
        returns (bool)
    {
        return FpEq(a.a, b.a) && FpEq(a.b, b.b);
    }

    function g1Eq(B12_377Lib.G1Point memory a, B12_377Lib.G1Point memory b)
        internal
        pure
        returns (bool)
    {
        return FpEq(a.X, b.X) && FpEq(a.Y, b.Y);
    }

    function g1Eq(B12_377Lib.G2Point memory a, B12_377Lib.G2Point memory b)
        internal
        pure
        returns (bool)
    {
        return (Fp2Eq(a.X, b.X) && Fp2Eq(a.Y, b.Y));
    }

    function g1FromBytes(bytes memory input, uint256 offset)
        internal
        pure
        returns (B12_377Lib.G1Point memory ret)
    {
        require(input.length >= offset + 128, "overrun");
        uint256 ptr;
        assembly {
            ptr := add(add(input, 0x20), offset) // ((input + 20) + offset)
            mstore(add(ret, 0x00), mload(add(ptr, 0x00))) // ret.X.a
            mstore(add(ret, 0x20), mload(add(ptr, 0x20))) // ret.X.b
            mstore(add(ret, 0x40), mload(add(ptr, 0x40))) // ret.Y.a
            mstore(add(ret, 0x60), mload(add(ptr, 0x60))) // ret.Y.b
        }
    }

    function g2FromBytes(bytes memory input, uint256 offset)
        internal
        pure
        returns (B12_377Lib.G2Point memory ret)
    {
        require(input.length >= offset + 256, "overrun");
        uint256 ptr;
        assembly {
            ptr := add(add(input, 0x20), offset)
            mstore(add(ret, 0x00), mload(add(ptr, 0x00))) // ret.X.a.a
            mstore(add(ret, 0x20), mload(add(ptr, 0x20))) // ret.X.a.b
            mstore(add(ret, 0x40), mload(add(ptr, 0x40))) // ret.X.b.a
            mstore(add(ret, 0x60), mload(add(ptr, 0x60))) // ret.X.b.b
            mstore(add(ret, 0x80), mload(add(ptr, 0x80))) // ret.Y.a.a
            mstore(add(ret, 0xa0), mload(add(ptr, 0xa0))) // ret.Y.a.b
            mstore(add(ret, 0xc0), mload(add(ptr, 0xc0))) // ret.Y.b.a
            mstore(add(ret, 0xe0), mload(add(ptr, 0xe0))) // ret.Y.b.b
        }
    }

    // Overwrites A
    function g1Add(G1Point memory a, G1Point memory b) internal view {
        uint256[8] memory input;
        input[0] = a.X.a;
        input[1] = a.X.b;
        input[2] = a.Y.a;
        input[3] = a.Y.b;

        input[4] = b.X.a;
        input[5] = b.X.b;
        input[6] = b.Y.a;
        input[7] = b.Y.b;

        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                G1_ADD,
                input,
                256,
                a, // reuse the memory to avoid growing
                128
            )
            // deallocate the input, leaving dirty memory
            mstore(0x40, input)
        }
        require(success, "g1 add precompile failed");
    }

    // Overwrites A
    function g1Mul(G1Point memory a, uint256 scalar) internal view {
        uint256[5] memory input;
        input[0] = a.X.a;
        input[1] = a.X.b;
        input[2] = a.Y.a;
        input[3] = a.Y.b;

        input[4] = scalar;

        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                G1_MUL,
                input,
                160,
                a, // reuse the memory to avoid growing
                128
            )
            // deallocate the input, leaving dirty memory
            mstore(0x40, input)
        }
        require(success, "g1 mul precompile failed");
    }

    function g1MultiExp(G1MultiExpArg[] memory argVec)
        internal
        view
        returns (G1Point memory c)
    {
        uint256 len = argVec.length;
        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                G1_MULTI_EXP,
                add(argVec, 0x20), // the body of the array
                mul(160, len), // 160 bytes per arg
                c, // write directly to the already allocated result
                128
            )
            // deallocate the input, leaving dirty memory
        }
        require(success, "g1 multiExp precompile failed");
    }

    // Overwrites A
    function g2Add(G2Point memory a, G2Point memory b) internal view {
        uint256[16] memory input;
        input[0] = a.X.a.a;
        input[1] = a.X.a.b;
        input[2] = a.X.b.a;
        input[3] = a.X.b.b;

        input[4] = a.Y.a.a;
        input[5] = a.Y.a.b;
        input[6] = a.Y.b.a;
        input[7] = a.Y.b.b;

        input[8] = b.X.a.a;
        input[9] = b.X.a.b;
        input[10] = b.X.b.a;
        input[11] = b.X.b.b;

        input[12] = b.Y.a.a;
        input[13] = b.Y.a.b;
        input[14] = b.Y.b.a;
        input[15] = b.Y.b.b;

        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                G2_ADD,
                input,
                512,
                a, // reuse the memory to avoid growing
                256
            )
            // deallocate the input, leaving dirty memory
            mstore(0x40, input)
        }
        require(success, "g2 add precompile failed");
    }

    // Overwrites A
    function g2Mul(G2Point memory a, uint256 scalar) internal view {
        uint256[9] memory input;

        input[0] = a.X.a.a;
        input[1] = a.X.a.b;
        input[2] = a.X.b.a;
        input[3] = a.X.b.b;

        input[4] = a.Y.a.a;
        input[5] = a.Y.a.b;
        input[6] = a.Y.b.a;
        input[7] = a.Y.b.b;

        input[8] = scalar;

        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                G2_MUL,
                input,
                288,
                a, // reuse the memory to avoid growing
                256
            )
            // deallocate the input, leaving dirty memory
            mstore(0x40, input)
        }
        require(success, "g2 mul precompile failed");
    }

    function g2MultiExp(G2MultiExpArg[] memory argVec)
        internal
        view
        returns (G1Point memory c)
    {
        uint256 len = argVec.length;
        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                G2_MULTI_EXP,
                add(argVec, 0x20), // the body of the array
                mul(288, len), // 288 bytes per arg
                c, // write directly to the already allocated result
                256
            )
            // deallocate the input, leaving dirty memory
        }
        require(success, "g2 multiExp precompile failed");
    }

    function pairing(PairingArg[] memory argVec)
        internal
        view
        returns (bool result)
    {
        uint256 len = argVec.length;
        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                PAIRING,
                add(argVec, 0x20), // the body of the array
                mul(384, len), // 384 bytes per arg
                mload(0x40), // write to earliest freemem
                32
            )
            result := mload(mload(0x40)) // load what we just wrote
        }
        require(success, "pairing precompile failed");
    }
}
