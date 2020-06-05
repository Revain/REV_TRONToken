pragma solidity ^0.5.8;

/**
  * @title contract for generating HEX pointer
  * for functions.
  *
  * @dev this contract is a tool meant to be used
  * on local JavaScript VM.
  *
  */
contract callbackSelector {

    address _null;

    constructor() public {
      _null = address(0);
    }

    /**
      * @notice function which returns function HEX pointer (callbackSelector)
      *
      * @param _function function name with parameter types. Case and whitespace sensitive.
      *
      * @dev example: `function get(string memory _function)`
      *    _function: `get(string)`
      *       result: `0x693ec85e`
      */
    function get(string memory _function) public pure returns (bytes4) {
        return bytes4(keccak256(abi.encodePacked(_function)));
    }

    function recover(bytes32 _requestMsgHash, uint8 _recoveryByte1, bytes32 _ecdsaR1, bytes32 _ecdsaS1) public returns (address) {
      address _address = ecrecover(
            keccak256(abi.encodePacked("\x19TRON Signed Message:\n32", _requestMsgHash)),
            _recoveryByte1,
            _ecdsaR1,
            _ecdsaS1
        );
        emit recovered(_address);
        return _address;
    }

    event recovered(address _address);
}