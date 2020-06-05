pragma solidity ^0.5.8;

/** @title  A contract for generating unique identifiers
  *
  * @notice  A contract that provides an identifier generation scheme,
  * guaranteeing uniqueness across all contracts that inherit from it,
  * as well as the unpredictability of future identifiers.
  *
  * @dev  This contract is intended to be inherited by any contract that
  * implements the callback software pattern for cooperative custodianship.
  *
*/
contract LockRequestable {

    // MEMBERS
    /// @notice  the count of all invocations of `generateLockId`.
    uint256 public lockRequestCount;

    // CONSTRUCTOR
    constructor() public {
        lockRequestCount = 0;
    }

    // FUNCTIONS
    /** @notice  Returns a fresh unique identifier.
      *
      * @dev the generation scheme uses three components.
      * First, the blockhash of the previous block.
      * Second, the deployed address.
      * Third, the next value of the counter.
      * This ensures that identifiers are unique across all contracts
      * following this scheme, and that future identifiers are
      * unpredictable.
      *
      * @return a 32-byte unique identifier.
    */
    function generateLockId() internal returns (bytes32 lockId) {
        return keccak256(abi.encodePacked(blockhash(block.number - 1), address(this), ++lockRequestCount));
    }
}