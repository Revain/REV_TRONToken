pragma solidity ^0.5.8;

import "./CustodianUpgradeable.sol";
import "./TRC20Proxy.sol";
import "./TRC20Store.sol";

/** @title  TRC20 compliant token intermediary contract holding core logic.
  *
  * @notice  This contract serves as an intermediary between the exposed TRC20
  * interface in TRC20Proxy and the store of balances in TRC20Store. This
  * contract contains core logic that the proxy can delegate to
  * and that the store is called by.
  *
  * @dev  This contract contains the core logic to implement the
  * TRC20 specification as well as several extensions.
  * 1. Changes to the token supply.
  * 2. Batched transfers.
  * 3. Relative changes to spending approvals.
  * 4. Delegated transfer control ('sweeping').
  *
  */
contract TRC20Impl is CustodianUpgradeable {

    // TYPES
    /// @dev  The struct type for pending increases to the token supply (print).
    struct PendingPrint {
        address receiver;
        uint256 value;
    }

    // MEMBERS
    /// @dev  The reference to the proxy.
    TRC20Proxy public trc20Proxy;

    /// @dev  The reference to the store.
    TRC20Store public trc20Store;

    /// @dev  The sole authorized caller of delegated transfer control ('sweeping').
    address public sweeper;

    /** @dev  The static message to be signed by an external account that
      * signifies their permission to forward their balance to any arbitrary
      * address. This is used to consolidate the control of all accounts
      * backed by a shared keychain into the control of a single key.
      * Initialized as the concatenation of the address of this contract
      * and the word "sweep". This concatenation is done to prevent a replay
      * attack in a subsequent contract, where the sweeping message could
      * potentially be replayed to re-enable sweeping ability.
      */
    bytes32 public sweepMsg;

    /** @dev  The mapping that stores whether the address in question has
      * enabled sweeping its contents to another account or not.
      * If an address maps to "true", it has already enabled sweeping,
      * and thus does not need to re-sign the `sweepMsg` to enact the sweep.
      */
    mapping (address => bool) public sweptSet;

    /// @dev  The map of lock ids to pending token increases.
    mapping (bytes32 => PendingPrint) public pendingPrintMap;

    /// @dev The map of blocked addresses.
    mapping (address => bool) public blocked;

    // CONSTRUCTOR
    constructor(
          address _TRC20Proxy,
          address _TRC20Store,
          address _custodian,
          address _sweeper
    )
        CustodianUpgradeable(_custodian)
        public
    {
        require(_sweeper != address(0), "no null value for `_sweeper`");
        trc20Proxy = TRC20Proxy(_TRC20Proxy);
        trc20Store = TRC20Store(_TRC20Store);

        sweeper = _sweeper;
        sweepMsg = keccak256(abi.encodePacked(address(this), "sweep"));
    }

    // MODIFIERS
    modifier onlyProxy {
        require(msg.sender == address(trc20Proxy), "only TRC20Proxy");
        _;
    }
    modifier onlySweeper {
        require(msg.sender == sweeper, "only sweeper");
        _;
    }


    /** @notice  Core logic of the TRC20 `approve` function.
      *
      * @dev  This function can only be called by the referenced proxy,
      * which has an `approve` function.
      * Every argument passed to that function as well as the original
      * `msg.sender` gets passed to this function.
      * NOTE: approvals for the zero address (unspendable) are disallowed.
      *
      * @param  _sender  The address initiating the approval in a proxy.
      */
    function approveWithSender(
        address _sender,
        address _spender,
        uint256 _value
    )
        public
        onlyProxy
        returns (bool success)
    {
        require(_spender != address(0), "no null value for `_spender`");
        require(blocked[_sender] != true, "_sender must not be blocked");
        require(blocked[_spender] != true, "_spender must not be blocked");
        trc20Store.setAllowance(_sender, _spender, _value);
        trc20Proxy.emitApproval(_sender, _spender, _value);
        return true;
    }

    /** @notice  Core logic of the `increaseApproval` function.
      *
      * @dev  This function can only be called by the referenced proxy,
      * which has an `increaseApproval` function.
      * Every argument passed to that function as well as the original
      * `msg.sender` gets passed to this function.
      * NOTE: approvals for the zero address (unspendable) are disallowed.
      *
      * @param  _sender  The address initiating the approval.
      */
    function increaseApprovalWithSender(
        address _sender,
        address _spender,
        uint256 _addedValue
    )
        public
        onlyProxy
        returns (bool success)
    {
        require(_spender != address(0),"no null value for_spender");
        require(blocked[_sender] != true, "_sender must not be blocked");
        require(blocked[_spender] != true, "_spender must not be blocked");
        uint256 currentAllowance = trc20Store.allowed(_sender, _spender);
        uint256 newAllowance = currentAllowance + _addedValue;

        require(newAllowance >= currentAllowance, "new allowance must not be smaller than previous");

        trc20Store.setAllowance(_sender, _spender, newAllowance);
        trc20Proxy.emitApproval(_sender, _spender, newAllowance);
        return true;
    }

    /** @notice  Core logic of the `decreaseApproval` function.
      *
      * @dev  This function can only be called by the referenced proxy,
      * which has a `decreaseApproval` function.
      * Every argument passed to that function as well as the original
      * `msg.sender` gets passed to this function.
      * NOTE: approvals for the zero address (unspendable) are disallowed.
      *
      * @param  _sender  The address initiating the approval.
      */
    function decreaseApprovalWithSender(
        address _sender,
        address _spender,
        uint256 _subtractedValue
    )
        public
        onlyProxy
        returns (bool success)
    {
        require(_spender != address(0), "no unspendable approvals"); // disallow unspendable approvals
        require(blocked[_sender] != true, "_sender must not be blocked");
        require(blocked[_spender] != true, "_spender must not be blocked");
        uint256 currentAllowance = trc20Store.allowed(_sender, _spender);
        uint256 newAllowance = currentAllowance - _subtractedValue;

        require(newAllowance <= currentAllowance, "new allowance must not be smaller than previous");

        trc20Store.setAllowance(_sender, _spender, newAllowance);
        trc20Proxy.emitApproval(_sender, _spender, newAllowance);
        return true;
    }

    /** @notice  Requests an increase in the token supply, with the newly created
      * tokens to be added to the balance of the specified account.
      *
      * @dev  Returns a unique lock id associated with the request.
      * Anyone can call this function, but confirming the request is authorized
      * by the custodian.
      * NOTE: printing to the zero address is disallowed.
      *
      * @param  _receiver  The receiving address of the print, if confirmed.
      * @param  _value  The number of tokens to add to the total supply and the
      * balance of the receiving address, if confirmed.
      *
      * @return  lockId  A unique identifier for this request.
      */
    function requestPrint(address _receiver, uint256 _value) public returns (bytes32 lockId) {
        require(_receiver != address(0), "no null value for `_receiver`");
        require(blocked[msg.sender] != true, "account blocked");
        require(blocked[_receiver] != true, "_receiver must not be blocked");
        lockId = generateLockId();

        pendingPrintMap[lockId] = PendingPrint({
            receiver: _receiver,
            value: _value
        });

        emit PrintingLocked(lockId, _receiver, _value);
    }

    /** @notice  Confirms a pending increase in the token supply.
      *
      * @dev  When called by the custodian with a lock id associated with a
      * pending increase, the amount requested to be printed in the print request
      * is printed to the receiving address specified in that same request.
      * NOTE: this function will not execute any print that would overflow the
      * total supply, but it will not revert either.
      *
      * @param  _lockId  The identifier of a pending print request.
      */
    function confirmPrint(bytes32 _lockId) public onlyCustodian {
        PendingPrint storage print = pendingPrintMap[_lockId];

        // reject ‘null’ results from the map lookup
        // this can only be the case if an unknown `_lockId` is received
        address receiver = print.receiver;
        require (receiver != address(0), "unknown `_lockId`");
        uint256 value = print.value;

        delete pendingPrintMap[_lockId];

        uint256 supply = trc20Store.totalSupply();
        uint256 newSupply = supply + value;
        if (newSupply >= supply) {
          trc20Store.setTotalSupply(newSupply);
          trc20Store.addBalance(receiver, value);

          emit PrintingConfirmed(_lockId, receiver, value);
          trc20Proxy.emitTransfer(address(0), receiver, value);
        }
    }

    /** @notice  Burns the specified value from the sender's balance.
      *
      * @dev  Sender's balanced is subtracted by the amount they wish to burn.
      *
      * @param  _value  The amount to burn.
      *
      * @return success true if the burn succeeded.
      */
    function burn(uint256 _value) public returns (bool success) {
        require(blocked[msg.sender] != true, "account blocked");
        uint256 balanceOfSender = trc20Store.balances(msg.sender);
        require(_value <= balanceOfSender, "disallow burning more, than amount of the balance");

        trc20Store.setBalance(msg.sender, balanceOfSender - _value);
        trc20Store.setTotalSupply(trc20Store.totalSupply() - _value);

        trc20Proxy.emitTransfer(msg.sender, address(0), _value);

        return true;
    }

     /** @notice  Burns the specified value from the balance in question.
      *
      * @dev  Suspected balance is subtracted by the amount which will be burnt.
      *
      * @dev If the suspected balance has less than the amount requested, it will be set to 0.
      *
      * @param  _from  The address of suspected balance.
      *
      * @param  _value  The amount to burn.
      *
      * @return success true if the burn succeeded.
      */
    function burn(address _from, uint256 _value) public onlyCustodian returns (bool success) {
        uint256 balance = trc20Store.balances(_from);
        if(_value <= balance){
            trc20Store.setBalance(_from, balance - _value);
            trc20Store.setTotalSupply(trc20Store.totalSupply() - _value);
            trc20Proxy.emitTransfer(_from, address(0), _value);
            emit Wiped(_from, _value, _value, balance - _value);
        }
        else {
            trc20Store.setBalance(_from,0);
            trc20Store.setTotalSupply(trc20Store.totalSupply() - balance);
            trc20Proxy.emitTransfer(_from, address(0), balance);
            emit Wiped(_from, _value, balance, 0);
        }
        return true;
    }

    /** @notice  A function for a sender to issue multiple transfers to multiple
      * different addresses at once. This function is implemented for gas
      * considerations when someone wishes to transfer, as one transaction is
      * cheaper than issuing several distinct individual `transfer` transactions.
      *
      * @dev  By specifying a set of destination addresses and values, the
      * sender can issue one transaction to transfer multiple amounts to
      * distinct addresses, rather than issuing each as a separate
      * transaction. The `_tos` and `_values` arrays must be equal length, and
      * an index in one array corresponds to the same index in the other array
      * (e.g. `_tos[0]` will receive `_values[0]`, `_tos[1]` will receive
      * `_values[1]`, and so on.)
      * NOTE: transfers to the zero address are disallowed.
      *
      * @param  _tos  The destination addresses to receive the transfers.
      * @param  _values  The values for each destination address.
      * @return  success  If transfers succeeded.
      */
    function batchTransfer(address[] memory _tos, uint256[] memory _values) public returns (bool success) {
        require(_tos.length == _values.length, "_tos and _values must be the same length");
        require(blocked[msg.sender] != true, "account blocked");
        uint256 numTransfers = _tos.length;
        uint256 senderBalance = trc20Store.balances(msg.sender);

        for (uint256 i = 0; i < numTransfers; i++) {
          address to = _tos[i];
          require(to != address(0), "no null values for _tos");
          require(blocked[to] != true, "_tos must not be blocked");
          uint256 v = _values[i];
          require(senderBalance >= v, "insufficient funds");

          if (msg.sender != to) {
            senderBalance -= v;
            trc20Store.addBalance(to, v);
          }
          trc20Proxy.emitTransfer(msg.sender, to, v);
        }

        trc20Store.setBalance(msg.sender, senderBalance);

        return true;
    }

    /** @notice  Enables the delegation of transfer control for many
      * accounts to the sweeper account, transferring any balances
      * as well to the given destination.
      *
      * @dev  An account delegates transfer control by signing the
      * value of `sweepMsg`. The sweeper account is the only authorized
      * caller of this function, so it must relay signatures on behalf
      * of accounts that delegate transfer control to it. Enabling
      * delegation is idempotent and permanent. If the account has a
      * balance at the time of enabling delegation, its balance is
      * also transferred to the given destination account `_to`.
      * NOTE: transfers to the zero address are disallowed.
      *
      * @param  _vs  The array of recovery byte components of the ECDSA signatures.
      * @param  _rs  The array of 'R' components of the ECDSA signatures.
      * @param  _ss  The array of 'S' components of the ECDSA signatures.
      * @param  _to  The destination for swept balances.
      */
    function enableSweep(uint8[] memory _vs, bytes32[] memory _rs, bytes32[] memory _ss, address _to) public onlySweeper {
        require(_to != address(0), "no null value for `_to`");
        require(blocked[_to] != true, "_to must not be blocked");
        require((_vs.length == _rs.length) && (_vs.length == _ss.length), "_vs[], _rs[], _ss lengths are different");

        uint256 numSignatures = _vs.length;
        uint256 sweptBalance = 0;

        for (uint256 i = 0; i < numSignatures; ++i) {
            address from = ecrecover(keccak256(abi.encodePacked("\x19TRON Signed Message:\n32",sweepMsg)), _vs[i], _rs[i], _ss[i]);
            require(blocked[from] != true, "_froms must not be blocked");
            // ecrecover returns 0 on malformed input
            if (from != address(0)) {
                sweptSet[from] = true;

                uint256 fromBalance = trc20Store.balances(from);

                if (fromBalance > 0) {
                    sweptBalance += fromBalance;

                    trc20Store.setBalance(from, 0);

                    trc20Proxy.emitTransfer(from, _to, fromBalance);
                }
            }
        }

        if (sweptBalance > 0) {
          trc20Store.addBalance(_to, sweptBalance);
        }
    }

    /** @notice  For accounts that have delegated, transfer control
      * to the sweeper, this function transfers their balances to the given
      * destination.
      *
      * @dev The sweeper account is the only authorized caller of
      * this function. This function accepts an array of addresses to have their
      * balances transferred for gas efficiency purposes.
      * NOTE: any address for an account that has not been previously enabled
      * will be ignored.
      * NOTE: transfers to the zero address are disallowed.
      *
      * @param  _froms  The addresses to have their balances swept.
      * @param  _to  The destination address of all these transfers.
      */
    function replaySweep(address[] memory _froms, address _to) public onlySweeper {
        require(_to != address(0), "no null value for `_to`");
        require(blocked[_to] != true, "_to must not be blocked");
        uint256 lenFroms = _froms.length;
        uint256 sweptBalance = 0;

        for (uint256 i = 0; i < lenFroms; ++i) {
            address from = _froms[i];
            require(blocked[from] != true, "_froms must not be blocked");
            if (sweptSet[from]) {
                uint256 fromBalance = trc20Store.balances(from);

                if (fromBalance > 0) {
                    sweptBalance += fromBalance;

                    trc20Store.setBalance(from, 0);

                    trc20Proxy.emitTransfer(from, _to, fromBalance);
                }
            }
        }

        if (sweptBalance > 0) {
            trc20Store.addBalance(_to, sweptBalance);
        }
    }

    /** @notice  Core logic of the TRC20 `transferFrom` function.
      *
      * @dev  This function can only be called by the referenced proxy,
      * which has a `transferFrom` function.
      * Every argument passed to that function as well as the original
      * `msg.sender` gets passed to this function.
      * NOTE: transfers to the zero address are disallowed.
      *
      * @param  _sender  The address initiating the transfer in a proxy.
      */
    function transferFromWithSender(
        address _sender,
        address _from,
        address _to,
        uint256 _value
    )
        public
        onlyProxy
        returns (bool success)
    {
        require(_to != address(0), "no null values for `_to`");
        require(blocked[_sender] != true, "_sender must not be blocked");
        require(blocked[_from] != true, "_from must not be blocked");
        require(blocked[_to] != true, "_to must not be blocked");

        uint256 balanceOfFrom = trc20Store.balances(_from);
        require(_value <= balanceOfFrom, "insufficient funds on `_from` balance");

        uint256 senderAllowance = trc20Store.allowed(_from, _sender);
        require(_value <= senderAllowance, "insufficient allowance amount");

        trc20Store.setBalance(_from, balanceOfFrom - _value);
        trc20Store.addBalance(_to, _value);

        trc20Store.setAllowance(_from, _sender, senderAllowance - _value);

        trc20Proxy.emitTransfer(_from, _to, _value);

        return true;
    }

    /** @notice  Core logic of the TRC20 `transfer` function.
      *
      * @dev  This function can only be called by the referenced proxy,
      * which has a `transfer` function.
      * Every argument passed to that function as well as the original
      * `msg.sender` gets passed to this function.
      * NOTE: transfers to the zero address are disallowed.
      *
      * @param  _sender  The address initiating the transfer in a proxy.
      */
    function transferWithSender(
        address _sender,
        address _to,
        uint256 _value
    )
        public
        onlyProxy
        returns (bool success)
    {
        require(_to != address(0), "no null value for `_to`");
        require(blocked[_sender] != true, "_sender must not be blocked");
        require(blocked[_to] != true, "_to must not be blocked");

        uint256 balanceOfSender = trc20Store.balances(_sender);
        require(_value <= balanceOfSender, "insufficient funds");

        trc20Store.setBalance(_sender, balanceOfSender - _value);
        trc20Store.addBalance(_to, _value);

        trc20Proxy.emitTransfer(_sender, _to, _value);

        return true;
    }

    /** @notice  Transfers the specified value from the balance in question.
      *
      * @dev  Suspected balance is subtracted by the amount which will be transferred.
      *
      * @dev If the suspected balance has less than the amount requested, it will be set to 0.
      *
      * @param  _from  The address of suspected balance.
      *
      * @param  _value  The amount to transfer.
      *
      * @return success true if the transfer succeeded.
      */
    function forceTransfer(
        address _from,
        address _to,
        uint256 _value
    )
        public
        onlyCustodian
        returns (bool success)
    {
        require(_to != address(0), "no null value for `_to`");
        uint256 balanceOfSender = trc20Store.balances(_from);
        if(_value <= balanceOfSender) {
            trc20Store.setBalance(_from, balanceOfSender - _value);
            trc20Store.addBalance(_to, _value);

            trc20Proxy.emitTransfer(_from, _to, _value);
        } else {
            trc20Store.setBalance(_from, 0);
            trc20Store.addBalance(_to, balanceOfSender);

            trc20Proxy.emitTransfer(_from, _to, balanceOfSender);
        }

        return true;
    }

    // METHODS (TRC20 sub interface impl.)
    /// @notice  Core logic of the TRC20 `totalSupply` function.
    function totalSupply() public view returns (uint256) {
        return trc20Store.totalSupply();
    }

    /// @notice  Core logic of the TRC20 `balanceOf` function.
    function balanceOf(address _owner) public view returns (uint256 balance) {
        return trc20Store.balances(_owner);
    }

    /// @notice  Core logic of the TRC20 `allowance` function.
    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return trc20Store.allowed(_owner, _spender);
    }

    /// @dev internal use only.
    function blockWallet(address wallet) public onlyCustodian returns (bool success) {
        blocked[wallet] = true;
        return true;
    }

    /// @dev internal use only.
    function unblockWallet(address wallet) public onlyCustodian returns (bool success) {
        blocked[wallet] = false;
        return true;
    }

    // EVENTS
    /// @dev  Emitted by successful `requestPrint` calls.
    event PrintingLocked(bytes32 _lockId, address _receiver, uint256 _value);

    /// @dev Emitted by successful `confirmPrint` calls.
    event PrintingConfirmed(bytes32 _lockId, address _receiver, uint256 _value);

    /** @dev Emitted by successful `confirmWipe` calls.
      *
      * @param _value Amount requested to be burned.
      *
      * @param _burned Amount which was burned.
      *
      * @param _balance Amount left on account after burn.
      *
      * @param _from Account which balance was burned.
      */
     event Wiped(address _from, uint256 _value, uint256 _burned, uint _balance);
}
