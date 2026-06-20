// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OwnableVault {
    address public owner;
    uint256 public balance;

    constructor() {
        owner = msg.sender;
    }

    function deposit(uint256 amount) external {
        balance += amount;
    }

    function withdraw(uint256 amount) external {
        require(msg.sender == owner, "only owner");
        balance -= amount;
    }
}
