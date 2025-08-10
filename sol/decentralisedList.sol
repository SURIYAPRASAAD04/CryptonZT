// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title EscrowWithArbiter
/// @notice Simple escrow: depositor locks funds, beneficiary can claim with depositor approval or arbiter resolution.
contract EscrowWithArbiter {
    address public depositor;
    address public beneficiary;
    address public arbiter;
    uint256 public depositAmount;
    bool public deposited;
    bool public released;
    bool public disputed;

    event Deposited(address indexed from, uint256 amount);
    event Released(address indexed to, uint256 amount);
    event Disputed(address indexed by);
    event Resolved(address indexed to, uint256 amount, string reason);

    modifier onlyDepositor() {
        require(msg.sender == depositor, "only depositor");
        _;
    }
    modifier onlyArbiter() {
        require(msg.sender == arbiter, "only arbiter");
        _;
    }

    constructor(address _beneficiary, address _arbiter) payable {
        depositor = msg.sender;
        beneficiary = _beneficiary;
        arbiter = _arbiter;
        deposited = false;
        released = false;
        disputed = false;
    }

    // Depositor funds the escrow (single deposit)
    function deposit() external payable onlyDepositor {
        require(!deposited, "already deposited");
        require(msg.value > 0, "zero value");
        depositAmount = msg.value;
        deposited = true;
        emit Deposited(msg.sender, msg.value);
    }

    // Depositor can release funds directly to beneficiary if no dispute
    function release() external onlyDepositor {
        require(deposited, "no deposit");
        require(!released, "already released");
        require(!disputed, "in dispute");
        released = true;
        (bool ok, ) = beneficiary.call{value: depositAmount}("");
        require(ok, "transfer failed");
        emit Released(beneficiary, depositAmount);
    }

    // Beneficiary can signal dispute (e.g., if depositor won't release)
    function raiseDispute() external {
        require(msg.sender == beneficiary, "only beneficiary");
        require(deposited && !released, "no active deposit");
        disputed = true;
        emit Disputed(msg.sender);
    }

    // Arbiter resolves dispute and chooses recipient with optional reason
    function resolveDispute(address payable recipient, uint256 amount, string calldata reason) external onlyArbiter {
        require(disputed, "no dispute");
        require(!released, "already released");
        require(amount <= depositAmount, "amount exceed");
        released = true;
        // send requested amount to recipient
        (bool ok, ) = recipient.call{value: amount}("");
        require(ok, "transfer failed");
        // if leftover, return to depositor
        uint256 leftover = depositAmount - amount;
        if (leftover > 0) {
            (bool ok2, ) = payable(depositor).call{value: leftover}("");
            require(ok2, "refund failed");
        }
        emit Resolved(recipient, amount, reason);
    }

    // Emergency: depositor can cancel if not disputed and not released
    function cancel() external onlyDepositor {
        require(deposited, "no deposit");
        require(!released, "already released");
        require(!disputed, "in dispute");
        released = true;
        (bool ok, ) = payable(depositor).call{value: depositAmount}("");
        require(ok, "refund failed");
    }

    // View helpers
    function status() external view returns (string memory) {
        if (!deposited) return "No deposit";
        if (released) return "Released";
        if (disputed) return "In Dispute";
        return "Locked";
    }

    receive() external payable {
        revert("send via deposit()");
    }
}
