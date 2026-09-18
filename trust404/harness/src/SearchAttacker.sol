// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Generic persistent caller used by the Track 04 search runtime.
/// It deliberately knows nothing about target names, vulnerabilities, or ABIs.
contract SearchAttacker {
    error SearchCallFailed(bytes revertData);
    error InvalidCallbackProgram();

    address[] private _callbackTargets;
    uint256[] private _callbackValues;
    bytes[] private _callbackData;
    uint256 private _callbackCursor;
    uint256 private _callbackBudget;

    function execute(address target, uint256 value, bytes calldata data)
        external
        payable
        returns (bytes memory result)
    {
        (bool ok, bytes memory returned) = target.call{value: value}(data);
        if (!ok) revert SearchCallFailed(returned);
        return returned;
    }

    function configureCallback(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata data,
        uint256 depthBudget
    ) external {
        if (targets.length != values.length || targets.length != data.length) {
            revert InvalidCallbackProgram();
        }
        delete _callbackTargets;
        delete _callbackValues;
        delete _callbackData;
        for (uint256 i = 0; i < targets.length; ++i) {
            _callbackTargets.push(targets[i]);
            _callbackValues.push(values[i]);
            _callbackData.push(data[i]);
        }
        _callbackCursor = 0;
        _callbackBudget = depthBudget;
    }

    function clearCallback() external {
        delete _callbackTargets;
        delete _callbackValues;
        delete _callbackData;
        _callbackCursor = 0;
        _callbackBudget = 0;
    }

    function _dispatchCallback() internal {
        if (_callbackBudget == 0 || _callbackCursor >= _callbackTargets.length) return;
        uint256 cursor = _callbackCursor;
        _callbackCursor = cursor + 1;
        _callbackBudget -= 1;
        (bool ok, bytes memory returned) = _callbackTargets[cursor].call{
            value: _callbackValues[cursor]
        }(_callbackData[cursor]);
        if (!ok) revert SearchCallFailed(returned);
    }

    receive() external payable {
        _dispatchCallback();
    }

    fallback() external payable {
        _dispatchCallback();
    }
}
