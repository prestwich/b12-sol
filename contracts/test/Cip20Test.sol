//SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.5.10;

import "../Cip20Lib.sol";

contract Cip20Test {

    using Cip20Lib for bytes;

    function sha3_256(bytes memory input) external view returns (bytes memory) {
        return input.sha3_256();
    }

    function sha3_512(bytes memory input) external view returns (bytes memory) {
        return input.sha3_512();
    }

    function keccak512(bytes memory input)
        external
        view
        returns (bytes memory)
    {
        return input.keccak512();
    }

    function sha2_512(bytes memory input)
        external
        view
        returns (bytes memory)
    {
        return input.sha2_512();
    }

    function blake2sWithConfig(
        bytes32 config,
        bytes memory key,
        bytes memory preimage
    ) external view returns (bytes memory) {
        return Cip20Lib.blake2sWithConfig(config, key, preimage);
    }


    // default settings, no key
    function blake2s(bytes memory preimage)
        external
        view
        returns (bytes memory)
    {
        return preimage.blake2s();
    }
}