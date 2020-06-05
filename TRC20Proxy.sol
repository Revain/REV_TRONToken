pragma solidity ^0.5.8;

import "./TRC20Impl.sol";
import "./TRC20Interface.sol";
import "./TRC20ImplUpgradeable.sol";

/** @title  Public interface to TRC20 compliant token.
  *
  * @notice  This contract is a permanent entry point to an TRC20 compliant
  * system of contracts.
  *
  * @dev  This contract contains no business logic and instead
  * delegates to an instance of TRC20Impl. This contract also has no storage
  * that constitutes the operational state of the token. This contract is
  * upgradeable in the sense that the `custodian` can update the
  * `TRC20Impl` address, thus redirecting the delegation of business logic.
  * The `custodian` is also authorized to pass custodianship.
  *
*/
contract TRC20Proxy is TRC20Interface, TRC20ImplUpgradeable {

    // MEMBERS
    /// @notice  Returns the name of the token.
    string public name;

    /// @notice  Returns the symbol of the token.
    string public symbol;

    /// @notice  Returns the number of decimals the token uses.
    uint8 public decimals;

    // CONSTRUCTOR
    constructor(
        string memory _name,
        string memory _symbol,
        uint8 _decimals,
        address _custodian
    )
        TRC20ImplUpgradeable(_custodian)
        public
    {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
    }

    // PUBLIC FUNCTIONS
    // (TRC20Interface)
    /** @notice  Returns the total token supply.
      *
      * @return  the total token supply.
      */
    function totalSupply() public view returns (uint256) {
        return trc20Impl.totalSupply();
    }

    /** @notice  Returns the account balance of another account with an address
      * `_owner`.
      *
      * @return  balance  the balance of account with address `_owner`.
      */
    function balanceOf(address tokenOwner) public view returns (uint256 balance) {
        return trc20Impl.balanceOf(tokenOwner);
    }

    /** @dev Internal use only.
      */
    function emitTransfer(address _from, address _to, uint256 _value) public onlyImpl {
        emit Transfer(_from, _to, _value);
    }

    /** @notice  Transfers `_value` amount of tokens to address `_to`.
      *
      * @dev Will fire the `Transfer` event. Will revert if the `_from`
      * account balance does not have enough tokens to spend.
      *
      * @return  success  true if transfer completes.
      */
    function transfer(address to, uint256 tokens) public returns (bool success) {
        return trc20Impl.transferWithSender(msg.sender, to, tokens);
    }

    /** @notice  Transfers `_value` amount of tokens from address `_from`
      * to address `_to`.
      *
      * @dev  Will fire the `Transfer` event. Will revert unless the `_from`
      * account has deliberately authorized the sender of the message
      * via some mechanism.
      *
      * @return  success  true if transfer completes.
      */
    function transferFrom(address from, address to, uint256 tokens) public returns (bool success) {
        return trc20Impl.transferFromWithSender(msg.sender, from, to, tokens);
    }

    /** @dev Internal use only.
      */
    function emitApproval(address _owner, address _spender, uint256 _value) public onlyImpl {
        emit Approval(_owner, _spender, _value);
    }

    /** @notice  Allows `_spender` to withdraw from your account multiple times,
      * up to the `_value` amount. If this function is called again it
      * overwrites the current allowance with _value.
      *
      * @dev  Will fire the `Approval` event.
      *
      * @return  success  true if approval completes.
      */
    function approve(address spender, uint256 tokens) public returns (bool success) {
        return trc20Impl.approveWithSender(msg.sender, spender, tokens);
    }

    /** @notice Increases the amount `_spender` is allowed to withdraw from
      * your account.
      * This function is implemented to avoid the race condition in standard
      * TRC20 contracts surrounding the `approve` method.
      *
      * @dev  Will fire the `Approval` event. This function should be used instead of
      * `approve`.
      *
      * @return  success  true if approval completes.
      */
    function increaseApproval(address _spender, uint256 _addedValue) public returns (bool success) {
        return trc20Impl.increaseApprovalWithSender(msg.sender, _spender, _addedValue);
    }

    /** @notice  Decreases the amount `_spender` is allowed to withdraw from
      * your account. This function is implemented to avoid the race
      * condition in standard TRC20 contracts surrounding the `approve` method.
      *
      * @dev  Will fire the `Approval` event. This function should be used
      * instead of `approve`.
      *
      * @return  success  true if approval completes.
      */
    function decreaseApproval(address _spender, uint256 _subtractedValue) public returns (bool success) {
        return trc20Impl.decreaseApprovalWithSender(msg.sender, _spender, _subtractedValue);
    }

    /** @notice  Returns how much `_spender` is currently allowed to spend from
      * `_owner`'s balance.
      *
      * @return  remaining  the remaining allowance.
      */
    function allowance(address tokenOwner, address spender) public view returns (uint256 remaining) {
        return trc20Impl.allowance(tokenOwner, spender);
    }
}
