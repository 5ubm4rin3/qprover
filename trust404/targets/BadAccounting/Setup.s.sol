// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {BadAccounting} from "./src/BadAccounting.sol";

/// @dev Minimal cheatcode surface, referenced by the fixed Foundry VM
/// address so this file needs no forge-std import to stay self-contained.
interface IVm {
    function deal(address who, uint256 amount) external;
}

/// @notice Deterministic deployment for the harness's `deploy.setup` path.
contract Setup {
    IVm constant vm = IVm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    uint256 constant SEED = 10 ether;

    function run() external returns (address target) {
        vm.deal(address(this), SEED);
        target = address(new BadAccounting{value: SEED}());
    }
}
