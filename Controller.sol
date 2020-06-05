pragma solidity ^0.5.8;

import "./LockRequestable.sol";
import "./TRC20Impl.sol";
import "./Custodian.sol";

/** @title  A contact to govern hybrid control over increases to the token supply and managing accounts.
  *
  * @notice  A contract that acts as a custodian of the active token
  * implementation, and an intermediary between it and the ‘true’ custodian.
  * It preserves the functionality of direct custodianship as well as granting
  * limited control of token supply increases to an additional key.
  *
  * @dev  This contract is a layer of indirection between an instance of
  * TRC20Impl and a custodian. The functionality of the custodianship over
  * the token implementation is preserved (printing and custodian changes),
  * but this contract adds the ability for an additional key
  * (the 'controller') to increase the token supply up to a ceiling,
  * and this supply ceiling can only be raised by the custodian.
  *
  */
contract Controller is LockRequestable {

    // TYPES
    /// @dev The struct type for pending ceiling raises.
    struct PendingCeilingRaise {
        uint256 raiseBy;
    }

    /// @dev The struct type for pending wipes.
    struct wipeAddress {
        uint256 value;
        address from;
    }

    /// @dev The struct type for pending force transfer requests.
    struct forceTransferRequest {
        uint256 value;
        address from;
        address to;
    }

    // MEMBERS
    /// @dev  The reference to the active token implementation.
    TRC20Impl public trc20Impl;

    /// @dev  The address of the account or contract that acts as the custodian.
    Custodian public custodian;

    /** @dev  The sole authorized caller of limited printing.
      * This account is also authorized to lower the supply ceiling and
      * wiping suspected accounts or force transferring funds from them.
      */
    address public controller;

    /** @dev  The maximum that the token supply can be increased to
      * through the use of the limited printing feature.
      * The difference between the current total supply and the supply
      * ceiling is what is available to the 'controller' account.
      * The value of the ceiling can only be increased by the custodian.
      */
    uint256 public totalSupplyCeiling;

    /// @dev  The map of lock ids to pending ceiling raises.
    mapping (bytes32 => PendingCeilingRaise) public pendingRaiseMap;

    /// @dev  The map of lock ids to pending wipes.
    mapping (bytes32 => wipeAddress[]) public pendingWipeMap;

    /// @dev  The map of lock ids to pending force transfer requests.
    mapping (bytes32 => forceTransferRequest) public pendingForceTransferRequestMap;

    // CONSTRUCTOR
    constructor(
        address _TRC20Impl,
        address _custodian,
        address _controller,
        uint256 _initialCeiling
    )
        public
    {
        trc20Impl = TRC20Impl(_TRC20Impl);
        custodian = Custodian(_custodian);
        controller = _controller;
        totalSupplyCeiling = _initialCeiling;
    }

    // MODIFIERS
    modifier onlyCustodian {
        require(msg.sender == address(custodian), "only custodian");
        _;
    }
    modifier onlyController {
        require(msg.sender == controller, "only controller");
        _;
    }

    modifier onlySigner {
        require(custodian.signerSet(msg.sender) == true, "only signer");
        _;
    }

    /** @notice  Increases the token supply, with the newly created tokens
      * being added to the balance of the specified account.
      *
      * @dev  The function checks that the value to print does not
      * exceed the supply ceiling when added to the current total supply.
      * NOTE: printing to the zero address is disallowed.
      *
      * @param  _receiver  The receiving address of the print.
      * @param  _value  The number of tokens to add to the total supply and the
      * balance of the receiving address.
      */
    function limitedPrint(address _receiver, uint256 _value) public onlyController {
        uint256 totalSupply = trc20Impl.totalSupply();
        uint256 newTotalSupply = totalSupply + _value;

        require(newTotalSupply >= totalSupply, "new total supply overflow");
        require(newTotalSupply <= totalSupplyCeiling, "total supply ceiling overflow");
        trc20Impl.confirmPrint(trc20Impl.requestPrint(_receiver, _value));
    }

    /** @notice  Requests wipe of suspected accounts.
      *
      * @dev  Returns a unique lock id associated with the request.
      * Only controller can call this function, and only the custodian
      * can confirm the request.
      *
      * @param  _froms  The array of suspected accounts.
      *
      * @param  _values  array of amounts by which suspected accounts will be wiped.
      *
      * @return  lockId  A unique identifier for this request.
      */
    function requestWipe(address[] memory _froms, uint256[] memory _values) public onlyController returns (bytes32 lockId) {
        require(_froms.length == _values.length, "_froms[] and _values[] must be same length");
        lockId = generateLockId();
        uint256 amount = _froms.length;

        for(uint256 i = 0; i < amount; i++) {
            address from = _froms[i];
            uint256 value = _values[i];
            pendingWipeMap[lockId].push(wipeAddress(value, from));
        }

        emit WipeRequested(lockId);

        return lockId;
    }

    /** @notice  Confirms a pending wipe of suspected accounts.
      *
      * @dev  When called by the custodian with a lock id associated with a
      * pending wipe, the amount requested is burned from the suspected accounts.
      *
      * @param  _lockId  The identifier of a pending wipe request.
      */
    function confirmWipe(bytes32 _lockId) public onlyCustodian {
        uint256 amount = pendingWipeMap[_lockId].length;
        for(uint256 i = 0; i < amount; i++) {
            wipeAddress memory addr = pendingWipeMap[_lockId][i];
            address from = addr.from;
            uint256 value = addr.value;
            trc20Impl.burn(from, value);
        }

        delete pendingWipeMap[_lockId];

        emit WipeCompleted(_lockId);
    }

    /** @notice  Requests force transfer from the suspected account.
      *
      * @dev  Returns a unique lock id associated with the request.
      * Only controller can call this function, and only the custodian
      * can confirm the request.
      *
      * @param  _from  address of suspected account.
      *
      * @param  _to  address of reciever.
      *
      * @param  _value  amount which will be transferred.
      *
      * @return  lockId  A unique identifier for this request.
      */
    function requestForceTransfer(address _from, address _to, uint256 _value) public onlyController returns (bytes32 lockId) {
        lockId = generateLockId();
        require (_value != 0, "no zero value transfers");
        pendingForceTransferRequestMap[lockId] = forceTransferRequest(_value, _from, _to);

        emit ForceTransferRequested(lockId, _from, _to, _value);

        return lockId;
    }

    /** @notice  Confirms a pending force transfer request.
      *
      * @dev  When called by the custodian with a lock id associated with a
      * pending transfer request, the amount requested is transferred from the suspected account.
      *
      * @param  _lockId  The identifier of a pending transfer request.
      */
    function confirmForceTransfer(bytes32 _lockId) public onlyCustodian {
        address from = pendingForceTransferRequestMap[_lockId].from;
        address to = pendingForceTransferRequestMap[_lockId].to;
        uint256 value = pendingForceTransferRequestMap[_lockId].value;

        delete pendingForceTransferRequestMap[_lockId];

        trc20Impl.forceTransfer(from, to, value);

        emit ForceTransfTRCompleted(_lockId, from, to, value);
    }

    /** @notice  Requests an increase to the supply ceiling.
      *
      * @dev  Returns a unique lock id associated with the request.
      * Anyone can call this function, but confirming the request is authorized
      * by the custodian.
      *
      * @param  _raiseBy  The amount by which to raise the ceiling.
      *
      * @return  lockId  A unique identifier for this request.
      */
    function requestCeilingRaise(uint256 _raiseBy) public returns (bytes32 lockId) {
        require(_raiseBy != 0, "no zero ceiling raise");

        lockId = generateLockId();

        pendingRaiseMap[lockId] = PendingCeilingRaise({
            raiseBy: _raiseBy
        });

        emit CeilingRaiseLocked(lockId, _raiseBy);
    }

    /** @notice  Confirms a pending increase in the token supply.
      *
      * @dev  When called by the custodian with a lock id associated with a
      * pending ceiling increase, the amount requested is added to the
      * current supply ceiling.
      * NOTE: this function will not execute any raise that would overflow the
      * supply ceiling, but it will not revert either.
      *
      * @param  _lockId  The identifier of a pending ceiling raise request.
      */
    function confirmCeilingRaise(bytes32 _lockId) public onlyCustodian {
        PendingCeilingRaise storage pendingRaise = pendingRaiseMap[_lockId];

        // copy locals of references to struct members
        uint256 raiseBy = pendingRaise.raiseBy;
        // accounts for a gibberish _lockId
        require(raiseBy != 0, "no gibberish _lockId");

        delete pendingRaiseMap[_lockId];

        uint256 newCeiling = totalSupplyCeiling + raiseBy;
        // overflow check
        if (newCeiling >= totalSupplyCeiling) {
            totalSupplyCeiling = newCeiling;

            emit CeilingRaiseConfirmed(_lockId, raiseBy, newCeiling);
        }
    }

    /** @notice  Lowers the supply ceiling, further constraining the bound of
      * what can be printed by the controller.
      *
      * @dev  The controller is the sole authorized caller of this function,
      * so it is the only account that can elect to lower its limit to increase
      * the token supply.
      *
      * @param  _lowerBy  The amount by which to lower the supply ceiling.
      */
    function lowerCeiling(uint256 _lowerBy) public onlyController {
        uint256 newCeiling = totalSupplyCeiling - _lowerBy;
        // overflow check
        require(newCeiling <= totalSupplyCeiling, "totalSupplyCeiling overflow");
        totalSupplyCeiling = newCeiling;

        emit CeilingLowered(_lowerBy, newCeiling);
    }

    /** @notice  Pass-through control of print confirmation, allowing this
      * contract's custodian to act as the custodian of the associated
      * active token implementation.
      *
      * @dev  This contract is the direct custodian of the active token
      * implementation, but this function allows this contract's custodian
      * to act as though it were the direct custodian of the active
      * token implementation. Therefore the custodian retains control of
      * unlimited printing.
      *
      * @param  _lockId  The identifier of a pending print request in
      * the associated active token implementation.
      */
    function confirmPrintProxy(bytes32 _lockId) public onlyCustodian {
        trc20Impl.confirmPrint(_lockId);
    }

    /** @notice  Pass-through control of custodian change confirmation,
      * allowing this contract's custodian to act as the custodian of
      * the associated active token implementation.
      *
      * @dev  This contract is the direct custodian of the active token
      * implementation, but this function allows this contract's custodian
      * to act as though it were the direct custodian of the active
      * token implementation. Therefore the custodian retains control of
      * custodian changes.
      *
      * @param  _lockId  The identifier of a pending custodian change request
      * in the associated active token implementation.
      */
    function confirmCustodianChangeProxy(bytes32 _lockId) public onlyCustodian {
        trc20Impl.confirmCustodianChange(_lockId);
    }

    /** @notice  Blocks all transactions with a wallet.
      *
      * @dev Only signers from custodian are authorized to call this function
      *
      * @param  wallet account which will be blocked.
      */
    function blockWallet(address wallet) public onlySigner {
        trc20Impl.blockWallet(wallet);
        emit Blocked(wallet);
    }

    /** @notice Unblocks all transactions with a wallet.
      *
      * @dev Only signers from custodian are authorized to call this function
      *
      * @param  wallet account which will be unblocked.
      */
    function unblockWallet(address wallet) public onlySigner {
        trc20Impl.unblockWallet(wallet);
        emit Unblocked(wallet);
    }

    // EVENTS
    /// @dev  Emitted by successful `requestCeilingRaise` calls.
    event CeilingRaiseLocked(bytes32 _lockId, uint256 _raiseBy);

    /// @dev  Emitted by successful `confirmCeilingRaise` calls.
    event CeilingRaiseConfirmed(bytes32 _lockId, uint256 _raiseBy, uint256 _newCeiling);

    /// @dev  Emitted by successful `lowTRCeiling` calls.
    event CeilingLowered(uint256 _lowerBy, uint256 _newCeiling);

    /// @dev  Emitted by successful `blockWallet` calls.
    event Blocked(address _wallet);

    /// @dev  Emitted by successful `unblockWallet` calls.
    event Unblocked(address _wallet);

     /// @dev  Emitted by successful `requestForceTransfer` calls.
    event ForceTransferRequested(bytes32 _lockId, address _from, address _to, uint256 _value);

    /// @dev  Emitted by successful `confirmForceTransfer` calls.
    event ForceTransfTRCompleted(bytes32 _lockId, address _from, address _to, uint256 _value);

    /// @dev  Emitted by successful `requestWipe` calls.
    event WipeRequested(bytes32 _lockId);

    /// @dev  Emitted by successful `confirmWipe` calls.
    event WipeCompleted(bytes32 _lockId);
}