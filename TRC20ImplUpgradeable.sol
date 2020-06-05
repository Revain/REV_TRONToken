pragma solidity ^0.5.8;

import "./CustodianUpgradeable.sol";
import "./TRC20Impl.sol";

/** @title  A contract to inherit upgradeable token implementations.
  *
  * @notice  A contract that provides re-usable code for upgradeable
  * token implementations. It itself inherits from `CustodianUpgradable`
  * as the upgrade process is controlled by the custodian.
  *
  * @dev  This contract is intended to be inherited by any contract
  * requiring a reference to the active token implementation, either
  * to delegate calls to it, or authorize calls from it. This contract
  * provides the mechanism for that implementation to be replaced,
  * which constitutes an implementation upgrade.
  *
  */
contract TRC20ImplUpgradeable is CustodianUpgradeable  {

    // TYPES
    /// @dev  The struct type for pending implementation changes.
    struct ImplChangeRequest {
        address proposedNew;
    }

    // MEMBERS
    // @dev  The reference to the active token implementation.
    TRC20Impl public trc20Impl;

    /// @dev  The map of lock ids to pending implementation changes.
    mapping (bytes32 => ImplChangeRequest) public implChangeReqs;

    // CONSTRUCTOR
    constructor(address _custodian) CustodianUpgradeable(_custodian) public {
        trc20Impl = TRC20Impl(0x0);
    }

    // MODIFIERS
    modifier onlyImpl {
        require(msg.sender == address(trc20Impl), "only TRC20Impl");
        _;
    }

    // PUBLIC FUNCTIONS
    // (UPGRADE)
    /** @notice  Requests a change of the active implementation associated
      * with this contract.
      *
      * @dev  Returns a unique lock id associated with the request.
      * Anyone can call this function, but confirming the request is authorized
      * by the custodian.
      *
      * @param  _proposedImpl  The address of the new active implementation.
      * @return  lockId  A unique identifier for this request.
      */
    function requestImplChange(address _proposedImpl) public returns (bytes32 lockId) {
        require(_proposedImpl != address(0), "no null value for `_proposedImpl`");

        lockId = generateLockId();

        implChangeReqs[lockId] = ImplChangeRequest({
            proposedNew: _proposedImpl
        });

        emit ImplChangeRequested(lockId, msg.sender, _proposedImpl);
    }

    /** @notice  Confirms a pending change of the active implementation
      * associated with this contract.
      *
      * @dev  When called by the custodian with a lock id associated with a
      * pending change, the `TRC20Impl TRC20Impl` member will be updated
      * with the requested address.
      *
      * @param  _lockId  The identifier of a pending change request.
      */
    function confirmImplChange(bytes32 _lockId) public onlyCustodian {
        trc20Impl = getImplChangeReq(_lockId);

        delete implChangeReqs[_lockId];

        emit ImplChangeConfirmed(_lockId, address(trc20Impl));
    }

    // PRIVATE FUNCTIONS
    function getImplChangeReq(bytes32 _lockId) private view returns (TRC20Impl _proposedNew) {
        ImplChangeRequest storage changeRequest = implChangeReqs[_lockId];

        // reject ‘null’ results from the map lookup
        // this can only be the case if an unknown `_lockId` is received
        require(changeRequest.proposedNew != address(0), "reject ‘null’ results from the map lookup");

        return TRC20Impl(changeRequest.proposedNew);
    }

    //EVENTS
    /// @dev  Emitted by successful `requestImplChange` calls.
    event ImplChangeRequested(
        bytes32 _lockId,
        address _msgSender,
        address _proposedImpl
    );

    /// @dev Emitted by successful `confirmImplChange` calls.
    event ImplChangeConfirmed(bytes32 _lockId, address _newImpl);
}