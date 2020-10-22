// SPDX-License-Identifier: The Unlicense
// Based on work here:
// https://github.com/ralexstokes/deposit-verifier

pragma solidity ^0.6.8;

import {B12_381Lib} from "./B12Lib.sol";
import {IDepositContract} from "./IDepositContract.sol";
import {TypedMemView} from "@summa-tx/memview.sol/contracts/TypedMemView.sol";
import {SafeMath} from "@summa-tx/memview.sol/contracts/SafeMath.sol";

contract DepositVerifier {
    using SafeMath for uint256;
    using TypedMemView for bytes;
    using TypedMemView for bytes29;
    using B12_381Lib for bytes;
    using B12_381Lib for B12_381Lib.Fp;
    using B12_381Lib for B12_381Lib.Fp2;
    using B12_381Lib for B12_381Lib.G1Point;
    using B12_381Lib for B12_381Lib.G2Point;

    uint256 constant PUBLIC_KEY_LENGTH = 48;
    uint256 constant SIGNATURE_LENGTH = 96;
    uint256 constant WITHDRAWAL_CREDENTIALS_LENGTH = 32;
    uint256 constant WEI_PER_GWEI = 1e9;

    string constant BLS_SIG_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_+";
    bytes1 constant BLS_BYTE_WITHOUT_FLAGS_MASK = bytes1(0x1f);

    uint8 constant MOD_EXP_PRECOMPILE_ADDRESS = 0x5;

    IDepositContract immutable depositContract;
    // Constant related to versioning serializations of deposits on eth2
    bytes32 immutable DEPOSIT_DOMAIN;

    constructor(address depositContractAddress, bytes32 deposit_domain) public {
        depositContract = IDepositContract(depositContractAddress);
        DEPOSIT_DOMAIN = deposit_domain;
    }

    // Return a `wei` value in units of Gwei and serialize as a (LE) `bytes8`.
    function serializeAmount(uint256 amount)
        private
        pure
        returns (bytes memory)
    {
        uint256 depositAmount = amount / WEI_PER_GWEI;

        bytes memory encodedAmount = new bytes(8);

        for (uint256 i = 0; i < 8; i++) {
            encodedAmount[i] = bytes1(uint8(depositAmount / (2**(8 * i))));
        }

        return encodedAmount;
    }

    // Compute the "signing root" from the deposit message. This root is the Merkle root
    // of a specific tree specified by SSZ serialization that takes as leaves chunks of 32 bytes.
    // NOTE: This computation is done manually in ``computeSigningRoot``.
    // NOTE: function is exposed for testing...
    function computeSigningRoot(
        bytes memory publicKey,
        bytes memory withdrawalCredentials,
        uint256 amount
    ) public view returns (bytes32) {
        bytes memory serializedPublicKey = new bytes(64);
        for (uint256 i = 0; i < PUBLIC_KEY_LENGTH; i++) {
            serializedPublicKey[i] = publicKey[i];
        }

        bytes32 publicKeyRoot = sha256(serializedPublicKey);
        bytes32 firstNode = sha256(
            abi.encodePacked(publicKeyRoot, withdrawalCredentials)
        );

        bytes memory amountRoot = new bytes(64);
        bytes memory serializedAmount = serializeAmount(amount);
        for (uint256 i = 0; i < 8; i++) {
            amountRoot[i] = serializedAmount[i];
        }
        bytes32 secondNode = sha256(amountRoot);

        bytes32 depositMessageRoot = sha256(
            abi.encodePacked(firstNode, secondNode)
        );
        return sha256(abi.encodePacked(depositMessageRoot, DEPOSIT_DOMAIN));
    }

    // NOTE: function exposed for testing...
    function expandMessage(bytes32 message) public pure returns (bytes memory) {
        bytes memory b0Input = new bytes(143);
        for (uint256 i = 0; i < 32; i++) {
            b0Input[i + 64] = message[i];
        }
        b0Input[96] = 0x01;
        for (uint256 i = 0; i < 44; i++) {
            b0Input[i + 99] = bytes(BLS_SIG_DST)[i];
        }

        bytes32 b0 = sha256(abi.encodePacked(b0Input));

        bytes memory output = new bytes(256);
        bytes32 chunk = sha256(
            abi.encodePacked(b0, bytes1(0x01), bytes(BLS_SIG_DST))
        );
        assembly {
            mstore(add(output, 0x20), chunk)
        }
        for (uint256 i = 2; i < 9; i++) {
            bytes32 input;
            assembly {
                input := xor(
                    b0,
                    mload(add(output, add(0x20, mul(0x20, sub(i, 2)))))
                )
            }
            chunk = sha256(
                abi.encodePacked(input, bytes1(uint8(i)), bytes(BLS_SIG_DST))
            );
            assembly {
                mstore(add(output, add(0x20, mul(0x20, sub(i, 1)))), chunk)
            }
        }

        return output;
    }

    // Reduce the number encoded as the big-endian slice of data[start:end] modulo the BLS12-381 field modulus.
    // Copying of the base is cribbed from the following:
    // https://github.com/ethereum/solidity-examples/blob/f44fe3b3b4cca94afe9c2a2d5b7840ff0fafb72e/src/unsafe/Memory.sol#L57-L74
    function reduceModulo(
        bytes memory data,
        uint256 start,
        uint256 end
    ) private view returns (bytes memory) {
        uint256 length = end - start;
        assert(length >= 0);
        assert(length <= data.length);

        bytes memory result = new bytes(48);

        bool success;
        assembly {
            let p := mload(0x40)
            // length of base
            mstore(p, length)
            // length of exponent
            mstore(add(p, 0x20), 0x20)
            // length of modulus
            mstore(add(p, 0x40), 48)
            // base
            // first, copy slice by chunks of EVM words
            let ctr := length
            let src := add(add(data, 0x20), start)
            let dst := add(p, 0x60)
            for {

            } or(gt(ctr, 0x20), eq(ctr, 0x20)) {
                ctr := sub(ctr, 0x20)
            } {
                mstore(dst, mload(src))
                dst := add(dst, 0x20)
                src := add(src, 0x20)
            }
            // next, copy remaining bytes in last partial word
            let mask := sub(exp(256, sub(0x20, ctr)), 1)
            let srcpart := and(mload(src), not(mask))
            let destpart := and(mload(dst), mask)
            mstore(dst, or(destpart, srcpart))
            // exponent
            mstore(add(p, add(0x60, length)), 1)
            // modulus
            let modulusAddr := add(p, add(0x60, add(0x10, length)))
            mstore(
                modulusAddr,
                or(mload(modulusAddr), 0x1a0111ea397fe69a4b1ba7b6434bacd7)
            ) // pt 1
            mstore(
                add(p, add(0x90, length)),
                0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
            ) // pt 2
            success := staticcall(
                sub(gas(), 2000),
                MOD_EXP_PRECOMPILE_ADDRESS,
                p,
                add(0xB0, length),
                add(result, 0x20),
                48
            )
            // Use "invalid" to make gas estimation work
            switch success
                case 0 {
                    invalid()
                }
        }
        require(success, "call to modular exponentiation precompile failed");
        return result;
    }

    function hashToField(bytes32 message)
        internal
        pure
        returns (B12_381Lib.Fp2[2] memory result)
    {
        bytes memory some_bytes = expandMessage(message);
        result[0] = some_bytes.parseFp2(0);
        result[1] = some_bytes.parseFp2(128);
    }

    function hashToCurve(bytes32 message)
        internal
        view
        returns (B12_381Lib.G2Point memory)
    {
        B12_381Lib.Fp2[2] memory elements = hashToField(message);
        B12_381Lib.G2Point memory firstPoint = elements[0].mapToG2();
        B12_381Lib.G2Point memory secondPoint = elements[1].mapToG2();
        return firstPoint.g2Add(secondPoint);
    }

    function decodeG1Point(bytes memory encodedX, B12_381Lib.Fp memory Y)
        private
        pure
        returns (B12_381Lib.G1Point memory)
    {
        encodedX[0] = encodedX[0] & BLS_BYTE_WITHOUT_FLAGS_MASK;
        B12_381Lib.Fp memory X = encodedX.parseCompactFp(0);
        return B12_381Lib.G1Point(X, Y);
    }

    function decodeG2Point(bytes memory encodedX, B12_381Lib.Fp2 memory Y)
        private
        pure
        returns (B12_381Lib.G2Point memory)
    {
        encodedX[0] = encodedX[0] & BLS_BYTE_WITHOUT_FLAGS_MASK;
        B12_381Lib.Fp2 memory X = encodedX.parseCompactFp2(0);
        return B12_381Lib.G2Point(X, Y);
    }

    function blsSignatureIsValid(
        bytes32 message,
        bytes memory encodedPublicKey,
        bytes memory encodedSignature,
        bytes memory publicKeyYCoordinateBytes,
        bytes memory signatureYCoordinateBytes
    ) internal view returns (bool) {
        B12_381Lib.Fp memory publicKeyYCoordinate = publicKeyYCoordinateBytes
            .parseFp(0);
        B12_381Lib.Fp2 memory signatureYCoordinate = signatureYCoordinateBytes
            .parseFp2(0);

        B12_381Lib.PairingArg[] memory args = new B12_381Lib.PairingArg[](2);

        args[0].g1 = decodeG1Point(encodedPublicKey, publicKeyYCoordinate);
        args[0].g2 = decodeG2Point(encodedSignature, signatureYCoordinate);

        args[1].g1 = B12_381Lib.negativeP1();
        args[1].g2 = hashToCurve(message);

        return B12_381Lib.pairing(args);
    }

    function verifyAndDeposit(
        bytes calldata publicKey,
        bytes calldata withdrawalCredentials,
        bytes calldata signature,
        bytes32 depositDataRoot,
        bytes calldata publicKeyYCoordinate,
        bytes calldata signatureYCoordinate
    ) external payable {
        require(
            publicKey.length == PUBLIC_KEY_LENGTH,
            "incorrectly sized public key"
        );
        require(
            withdrawalCredentials.length == WITHDRAWAL_CREDENTIALS_LENGTH,
            "incorrectly sized withdrawal credentials"
        );
        require(
            signature.length == SIGNATURE_LENGTH,
            "incorrectly sized signature"
        );
        require(
            publicKeyYCoordinate.length == 64,
            "incorrectly sized signatureYCoordinate"
        );
        require(
            signatureYCoordinate.length == 128,
            "incorrectly sized signatureYCoordinate"
        );
        bytes32 signingRoot = computeSigningRoot(
            publicKey,
            withdrawalCredentials,
            msg.value
        );

        require(
            blsSignatureIsValid(
                signingRoot,
                publicKey,
                signature,
                publicKeyYCoordinate,
                signatureYCoordinate
            ),
            "BLS signature verification failed"
        );

        depositContract.deposit{value: msg.value}(
            publicKey,
            withdrawalCredentials,
            signature,
            depositDataRoot
        );
    }
}
