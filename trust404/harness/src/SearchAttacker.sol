// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Generic persistent caller used by the Track 04 search runtime.
/// It deliberately knows nothing about target names, vulnerabilities, or ABIs.
contract SearchAttacker {
    error SearchCallFailed(bytes revertData);

    function execute(address target, uint256 value, bytes calldata data)
        external
        payable
        returns (bytes memory result)
    {
        (bool ok, bytes memory returned) = target.call{value: value}(data);
        if (!ok) revert SearchCallFailed(returned);
        return returned;
    }

    receive() external payable {}
}
