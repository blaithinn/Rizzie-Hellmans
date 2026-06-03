// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MessageHash {
    struct HashRecord {
        bytes32 hash;
        uint256 timestamp;
    }

    HashRecord[] public records;

    event HashStored(address indexed sender, bytes32 hash, uint256 timestamp);

    function storeHash(bytes32 hash) public {
        records.push(HashRecord(hash, block.timestamp));
        emit HashStored(msg.sender, hash, block.timestamp);
    }

    function getHash(uint256 index) public view returns (bytes32, uint256) {
        require(index < records.length, "Index out of range");
        HashRecord memory r = records[index];
        return (r.hash, r.timestamp);
    }

    function getRecordCount() public view returns (uint256) {
        return records.length;
    }
}