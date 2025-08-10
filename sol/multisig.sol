// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title MultiSigWallet
/// @notice Simple multisig: owners propose transactions, require confirmations to execute.
contract MultiSigWallet {
    address[] public owners;
    mapping(address => bool) public isOwner;
    uint public required;

    struct Txn {
        address to;
        uint value;
        bytes data;
        bool executed;
        uint numConfirmations;
    }

    Txn[] public transactions;
    mapping(uint => mapping(address => bool)) public confirmed;

    event SubmitTx(uint indexed txIndex, address indexed proposer, address to, uint value);
    event ConfirmTx(uint indexed txIndex, address indexed owner);
    event ExecuteTx(uint indexed txIndex, address indexed executor);

    modifier onlyOwner() {
        require(isOwner[msg.sender], "not owner");
        _;
    }

    constructor(address[] memory _owners, uint _required) {
        require(_owners.length > 0, "owners required");
        require(_required > 0 && _required <= _owners.length, "invalid required count");
        for (uint i=0; i<_owners.length; i++) {
            address o = _owners[i];
            require(o != address(0) && !isOwner[o], "invalid owner");
            isOwner[o] = true;
            owners.push(o);
        }
        required = _required;
    }

    function submitTransaction(address to, uint value, bytes calldata data) external onlyOwner returns (uint) {
        uint txIndex = transactions.length;
        transactions.push(Txn({to: to, value: value, data: data, executed: false, numConfirmations: 0}));
        emit SubmitTx(txIndex, msg.sender, to, value);
        return txIndex;
    }

    function confirmTransaction(uint txIndex) external onlyOwner {
        require(txIndex < transactions.length, "tx not found");
        require(!confirmed[txIndex][msg.sender], "already confirmed");
        Txn storage txn = transactions[txIndex];
        require(!txn.executed, "already executed");

        confirmed[txIndex][msg.sender] = true;
        txn.numConfirmations += 1;
        emit ConfirmTx(txIndex, msg.sender);
    }

    function executeTransaction(uint txIndex) external onlyOwner {
        require(txIndex < transactions.length, "tx not found");
        Txn storage txn = transactions[txIndex];
        require(!txn.executed, "already executed");
        require(txn.numConfirmations >= required, "insufficient confirmations");

        txn.executed = true;
        (bool success, ) = txn.to.call{value: txn.value}(txn.data);
        require(success, "tx failed");
        emit ExecuteTx(txIndex, msg.sender);
    }

    function revokeConfirmation(uint txIndex) external onlyOwner {
        require(txIndex < transactions.length, "tx not found");
        require(confirmed[txIndex][msg.sender], "not confirmed");
        Txn storage txn = transactions[txIndex];
        require(!txn.executed, "already executed");

        confirmed[txIndex][msg.sender] = false;
        txn.numConfirmations -= 1;
    }

    // helpers
    function getOwners() external view returns (address[] memory) {
        return owners;
    }

    function getTxnCount() external view returns (uint) {
        return transactions.length;
    }

    receive() external payable {}
}
