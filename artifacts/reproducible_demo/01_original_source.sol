pragma solidity ^0.8.20;

contract VulnerableVault {
    address public owner;
    int256 public balance;

    function drain() public {
        require(msg.sender != owner, "only non-owner can trigger the vulnerable path");
        balance = balance - 15;
    }
}
