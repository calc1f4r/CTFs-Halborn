# Critical Risk

# [C-01] Chain can be halted by 0 token redeems

## Severity

Critical Risk

## Description

The `RedeemCollateral(...)` function allows users to burn HAL and create a delayed `RedeemRequest` that will later be processed in
`EndRedeeming(...)`, where collateral is sent from the redeem pool module account to the user.

However, the collateral amount is computed by dividing the HAL amount by the exchange rate and truncating to an integer. If the
user redeems **1 HAL**, the computed collateral becomes **0** (integer truncation). The module still stores a redeem request with
`Collateral.Amount == 0`.

When the request matures, `EndRedeeming(...)` attempts to send `sdk.NewCoins(req.Collateral)` to the user. In Cosmos SDK,
`sdk.NewCoins(...)` sanitizes its input by removing zero-amount coins, so a `0` coin becomes an **empty** `sdk.Coins{}`. The bank
keeper treats sending an empty coin set as a no-op and returns success, so the user's balance does not increase. The module then
hits a `panic(...)` that asserts the user's balance increased, halting the chain during `EndBlock`.

## Location of Affected Code

```go
File: x/hal/keeper/msg_server_redeem_collateral.go

48:  redeemedCollateralAmount := halAmount.Quo(exchangeRate).TruncateInt()
54:  redeemedCollateralCoin := sdk.NewCoin(collateralDenom, redeemedCollateralAmount)
68:  redeemRequest := types.RedeemRequest{ Account: accAddr.String(), Collateral: redeemedCollateralCoin, Completiontime: completionTime }
74:  k.SetRedeemRequest(ctx, redeemRequest)
```

```go
File: x/hal/keeper/keeper.go

145: if err := k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.RedeemPoolName, accAddr, sdk.NewCoins(req.Collateral)); err != nil {
...
154: if !balanceAfter.Amount.GT(balanceBefore.Amount) {
155:     panic(fmt.Sprintf("User balance did not increase after the transfer..."))
156: }
```

## Impact

Any user who can obtain and redeem **1 HAL** can cause a deterministic panic in `EndBlock`, halting the chain (denial of service).

## Proof of Concept

1.  Ensure you hold at least `1` HAL.
2.  Call `MsgRedeemCollateral` with `HalAmount = 1 HAL`.
3.  The module burns `1 HAL` and creates a redeem request where `Collateral.Amount == 0` due to truncation.
4.  After the redeem duration elapses, `EndRedeeming(...)` processes the request in `EndBlock`.
5.  The bank send is called with `sdk.NewCoins(0<collateralDenom>)`, which is sanitized to an empty `sdk.Coins{}` and succeeds as
    a no-op.
6.  The user's balance remains unchanged, so `EndRedeeming(...)` panics, and all validators halt.

## Recommendation

- Reject redeems that would result in zero collateral (e.g., enforce `HalAmount >= exchangeRate` or `redeemedCollateralAmount > 0`
  before creating/storing the request).
- As a defense-in-depth measure, do not `panic` in `EndRedeeming(...)` for balance assertions; instead handle unexpected outcomes
  safely (e.g., return/log and delete or quarantine malformed requests).

## Team Response

N/A

---

[C-02] Chain can be halted by donations

## Severity

Critical Risk

## Description

The `InvariantCheck` function in `x/hal/keeper/keeper.go` enforces that the total supply of HAL tokens is at least double the collateral balance in the pools (`CollateralPoolName` and `RedeemPoolName`). It calculates the required HAL supply based on the current balance of these pools using `k.bankKeeper.GetBalance(...)`.

However, the module accounts for `CollateralPoolName` (`halborn_collateral_pool`) and `RedeemPoolName` (`halborn_redeem_pool`) are not added to the blocked list in `app/app_config.go`. This allows any user to send collateral tokens directly to these module accounts using `MsgSend`.

If a user sends collateral tokens to the pool without minting HAL tokens (a "donation"), the collateral balance increases, but the HAL supply remains the same. This causes the invariant condition `halSupply < collateral * 2` to trigger. Since `InvariantCheck` is called in `BeginBlock`, the panic will occur at the start of the next block, causing the chain to halt permanently.

## Location of Affected Code

```go
File: x/hal/keeper/keeper.go

163: func (k Keeper) InvariantCheck(ctx sdk.Context) error {
...
178: 	collateralPoolBalance := k.bankKeeper.GetBalance(ctx, k.accountKeeper.GetModuleAddress(types.CollateralPoolName), collateralDenom)
...
199: 	result := halSupply.Amount.Sub(mintableHalAmountDec.TruncateInt())
200: 
201: 	// Check if the result is greater than or equal to zero
202: 	if result.IsNegative() {
203: 		panic("invariant check failed: total HAL supply is less than the calculated amount from collateral")
204:  }
205: 
206: 	return nil
207: }
```

## Impact

Any user can permanently halt the chain by sending a small amount of collateral tokens to the `halborn_collateral_pool` or `halborn_redeem_pool` module account. This is a severe denial-of-service vulnerability.

## Proof of Concept

1.  A malicious user acquires `1` unit of collateral token (e.g., `uatom` or whatever the collateral denom is).
2.  The user sends `1` unit of collateral to the `halborn_collateral_pool` address using `MsgSend`.
3.  The transaction is included in a block.
4.  In the `BeginBlock` of the **next** block (or same block if Invariant is checked after txs, but here it is BeginBlock), the `InvariantCheck` runs.
5.  `collateralPoolBalance` has increased, so `mintableHalAmountDec` (collateral * 2) increases.
6.  `halSupply` has not increased.
7.  `halSupply < mintableHalAmountDec` becomes true.
8.  The node panics with "invariant check failed...".
9.  All validators panic, and the chain halts.

## Recommendation

1.  **Block Module Accounts**: Add `halmoduletypes.CollateralPoolName` and `halmoduletypes.RedeemPoolName` to the `blockedAccAddrs` list in `app/app_config.go` to prevent direct transfers.

```go
// app/app_config.go
blockAccAddrs = []string{
    // ...
    halmoduletypes.CollateralPoolName,
    halmoduletypes.RedeemPoolName,
    // ...
}
```
2. use the state checks for this.

## Team Response

N/A

---


# High Risk

# [High-01] Unchecked Return Value in `MintHal` Allows Free Token Minting

## Severity

High Risk

## Description

The `MintHal` function in `x/hal/keeper/msg_server_mint_hal.go` is responsible for minting HAL tokens in exchange for collateral tokens. It first mints the HAL tokens and sends them to the user, and then attempts to transfer the collateral from the user to the module.

The function fails to check the error returned by `SendCoinsFromAccountToModule` when transferring the collateral from the user to the module account.

## Location of Affected Code

```go
File: x/hal/keeper/msg_server_mint_hal.go

71: 	k.bankKeeper.SendCoinsFromAccountToModule(ctx, accAddr, types.CollateralPoolName, sdk.NewCoins(msg.CollateralAmount))
```

## Impact

An attacker can mint an unlimited amount of HAL tokens without providing any collateral. This would lead to hyperinflation of the HAL token and complete insolvency of the protocol.

## Proof of Concept

1.  Create an account with `0` collateral tokens.
2.  Call `MintHal` requesting to mint `100` HAL tokens (which requires `50` collateral).
3.  The `MintHal` function mints `100` HAL and sends them to the attacker (Lines 58-64).
4.  The function attempts to pull `50` collateral from the attacker (Line 71). This fails because the attacker has `0` balance, returning an error.
5.  The error is ignored.
6.  The function returns success (Line 73).
7.  **Result:** Attacker has `100` HAL and paid `0` collateral.

## Recommendation

Ensure that the error returned by `SendCoinsFromAccountToModule` is checked and returned if it is not nil. Additionally, consider following the Checks-Effects-Interactions pattern by transferring the collateral *before* minting the new tokens.

```go
	// Transfer the collateral amount from the creator account to the module account.
	if err := k.bankKeeper.SendCoinsFromAccountToModule(ctx, accAddr, types.CollateralPoolName, sdk.NewCoins(msg.CollateralAmount)); err != nil {
		return nil, errorsmod.Wrap(err, "failed to send collateral amount")
	}

	// Mint the HAL tokens to the module account
	if err := k.bankKeeper.MintCoins(ctx, types.CollateralPoolName, sdk.NewCoins(mintedHalCoin)); err != nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInsufficientFunds, "failed to mint HAL coins")
	}
```

## Team Response

N/A

---

# [High-02] Non-deterministic Execution due to `time.Now()` Usage

## Severity

High Risk

## Description

**Context:**
The `RedeemCollateral` function in `x/hal/keeper/msg_server_redeem_collateral.go` calculates a `completionTime` for when the collateral redemption will be finalized.

**Problem:**
The function uses the standard Go library's `time.Now()` function to determine the current time.

**Impact:**
In a decentralized network, `time.Now()` returns the local system time of the machine executing the code. Since different validators will execute the transaction at slightly different wall-clock times (and may have clock skews), they will calculate different `completionTime` values. This results in a non-deterministic state transition, causing an AppHash mismatch between validators. This will inevitably lead to a consensus failure and chain halt.

## Location of Affected Code

```go
File: x/hal/keeper/msg_server_redeem_collateral.go

63: 	completionTime := time.Now().Add(redeemDur)
```

## Impact

The use of non-deterministic code in the state machine breaks the consensus mechanism of the CometBFT (Tendermint) engine. This will cause the chain to halt as validators cannot agree on the next block state.

## Proof of Concept

1.  Validator A processes the block at `T` time. `completionTime` = `T + duration`.
2.  Validator B processes the same block at `T + 100ms` time. `completionTime` = `T + 100ms + duration`.
3.  The resulting `RedeemRequest` object stored in the state differs between Validator A and Validator B.
4.  The Merkle root of the application state (AppHash) differs.
5.  Consensus fails.

## Recommendation

Use the block time provided by the context `ctx.BlockTime()` instead of the system time `time.Now()`. `ctx.BlockTime()` is consistent across all validators for a given block.

```go
	// Use BlockTime for deterministic behavior
	completionTime := ctx.BlockTime().Add(redeemDur)
```

## Team Response

N/A

---

[M-01] Treasury account for ticket fees is not configured

## Severity

Medium Risk

## Description

The `CreateTicket(...)` function charges users HAL tokens to open a ticket (the context). However, it sends those tokens to `types.TreasuryKey`, which is not configured as a module account in `app/app_config.go` (the problem).

This means ticket creation can fail at runtime, or funds could later be sent to an unintended module account if one is created with that name, breaking the intended fee collection flow (the impact).

## Location of Affected Code

```go
// x/hal/keeper/msg_server_create_ticket.go
if err := k.bankKeeper.SendCoinsFromAccountToModule(ctx, accAddr, types.TreasuryKey, sdk.NewCoins(halCoin)); err != nil {
	return nil, err
}
```

```go
// app/app_config.go
// moduleAccPerms includes hal, halborn_collateral_pool, halborn_redeem_pool
// but does not include "treasury_key"
```

## Impact

- Ticket creation may be broken on-chain when the treasury module account does not exist.
- Fee collection can be misdirected or mis-accounted depending on future module account configuration.



## Recommendation

- Use an existing, configured module account name for treasury (or add `treasury_key` as a proper module account with explicit permissions and blocked-address decisions) in `moduleAccPerms` in `app/app_config.go`.
- If the intent is to send to the `x/hal` module account, use `types.ModuleName` instead of `types.TreasuryKey`.

## Team Response

N/A

---

[M-02] Redeem requests can be overwritten due to per-account keying

## Severity

Medium Risk

## Description

**Context:**
The `RedeemCollateral` flow is intended to be asynchronous: a user burns HAL and a `RedeemRequest` is stored, then later (once
the redeem duration has elapsed) the request is processed in `EndRedeeming(...)` and collateral is sent from the redeem pool to
the user.

**Problem:**
Redeem requests are stored under a KV key derived only from the account (`RedeemRequestKeyPrefix + request.Account`). This means
there is effectively only **one redeem-request slot per account**. If the same user submits another `MsgRedeemCollateral` before
the earlier request is executed, the new request overwrites the old one in state.

## Location of Affected Code

```go
File: x/hal/keeper/keeper.go

71: func (k Keeper) SetRedeemRequest(ctx sdk.Context, request types.RedeemRequest) {
...
77:     key := []byte(types.RedeemRequestKeyPrefix + request.Account)
...
81:     store.Set(key, bz)
82: }
```

```go
File: x/hal/keeper/msg_server_redeem_collateral.go

67:  // Store the redeem request details to process at EndBlock
68:  redeemRequest := types.RedeemRequest{ Account: accAddr.String(), Collateral: redeemedCollateralCoin, Completiontime: completionTime }
74:  k.SetRedeemRequest(ctx, redeemRequest)
```

## Impact

If a user submits multiple redeems while an earlier redeem is still pending, only the latest request remains recorded. Since
collateral is moved into the redeem pool at request creation time, any overwritten portion of the earlier pending request may
become unclaimable (stuck in the redeem pool), leading to loss of user funds and broken UX/accounting.

## Proof of Concept

1.  User has sufficient HAL balance and calls `MsgRedeemCollateral` for amount `A`.
2.  Before the redeem duration elapses, the same user calls `MsgRedeemCollateral` again for amount `B`.
3.  The second call writes to the same key (`RedeemRequestKeyPrefix + account`) and overwrites the first request.
4.  When `EndRedeeming(...)` executes after the redeem duration, only request `B` is processed and deleted; request `A` is no
    longer present in state, while the collateral corresponding to `A` was already moved into the redeem pool.

## Recommendation

- Store redeem requests under a unique per-request key, for example `(account, sequence)` and maintain a per-account sequence
  counter.
- Enforce `MaxRedeemEntries` by tracking multiple pending requests per account and rejecting new requests once the limit is hit.
- If the intended design is "only one pending request per account", explicitly reject a new redeem when a request already exists
  for that account (instead of silently overwriting it).

## Team Response

N/A

---

[M-03] No Validation on Ticket Issue Length Allows Spam

## Severity

Medium Risk

## Description

The `CreateTicket` function in `x/hal/keeper/msg_server_create_ticket.go` allows users to create tickets with an arbitrary length `Issue` string. There are no checks for a minimum length (allowing empty issues) or a maximum length (allowing excessively large issues).

If the `Issue` length is 0, the cost calculated is 0 HAL tokens. This allows users to create tickets for free (excluding gas fees), spamming the state with empty tickets. Conversely, users can create tickets with extremely large payloads, potentially causing state bloat.

## Location of Affected Code

```go
File: x/hal/keeper/msg_server_create_ticket.go

32: 	issueLength := len(msg.Issue)
33: 	halCost := math.NewUint(uint64(issueLength))
```

## Impact

1.  **Free Spam:** Users can create an unlimited number of empty tickets without paying any HAL tokens, cluttering the state.


## Proof of Concept

**Case 1: Empty Issue (Free Spam)**
1.  Submit a `MsgCreateTicket` with `Issue = ""`.
2.  `issueLength` is 0. `halCost` is 0.
3.  The transaction succeeds, and a new ticket is appended to the store with 0 HAL cost.

**Case 2: Huge Issue**
1.  Submit a `MsgCreateTicket` with `Issue` containing 1MB of text.
2.  If the user pays the required HAL, the 1MB string is stored in the application state.

## Recommendation

Enforce minimum and maximum length constraints on the `Issue` field.

```go
	// Define constants or params for limits
	const MinIssueLength = 1
	const MaxIssueLength = 1000 // Example limit

	issueLength := len(msg.Issue)
	if issueLength < MinIssueLength {
		return nil, errorsmod.Wrap(types.ErrInvalidIssue, "issue cannot be empty")
	}
	if issueLength > MaxIssueLength {
		return nil, errorsmod.Wrap(types.ErrInvalidIssue, "issue is too long")
	}
```

## Team Response

N/A

---

[M-04] KV Store Write and Delete Operations Ignore Errors

## Severity

Medium Risk

## Description

The module performs critical state persistence operations through KV store writes and deletes (the context). However, multiple functions ignore errors returned by `store.Set(...)` and `store.Delete(...)` operations (the problem).

This means that storage failures (I/O errors, disk full conditions, store service failures) can silently fail, causing state inconsistencies where transactions succeed but data is not persisted or deleted. This leads to inconsistent application state, potential loss of user funds, and makes debugging operational incidents significantly harder (the impact).

## Location of Affected Code

```go
File: x/hal/keeper/keeper.go

81: 	store.Set(key, bz)  // error ignored
```

```go
File: x/hal/keeper/keeper.go

124: 	store.Delete(key)  // error ignored
```

```go
File: x/hal/keeper/ticket.go

36: 	store.Set(bz, appendedValue)  // error ignored
```

```go
File: x/hal/keeper/ticket.go

59: 	store.Set(byteKey, bz)  // error ignored
```

```go
File: x/hal/keeper/params.go

30: 	store.Set(types.ParamsKey, bz)  // error ignored, even though function returns error
```

## Impact

- **State Inconsistency**: Redeem requests, tickets, and parameters may not be persisted despite successful transaction execution, leading to inconsistent state between expected and actual storage.
- **Fund Loss**: If a redeem request write fails silently, users may lose access to their collateral as the request won't be processed in `EndBlock`.
- **Operational Issues**: Silent failures make debugging production incidents extremely difficult, as transactions appear successful but state changes are not reflected.
- **Data Corruption**: Failed deletes can leave stale data in the store, causing incorrect state reads and potential double-processing of requests.

## Proof of Concept

1. **Redeem Request Write Failure:**
   - A user calls `MsgRedeemCollateral` to redeem HAL tokens.
   - The transaction succeeds and HAL is burned.
   - `SetRedeemRequest` is called, but `store.Set(...)` fails due to disk I/O error.
   - The error is ignored, transaction returns success.
   - In `EndBlock`, `EndRedeeming` cannot find the request (it was never written).
   - User's collateral remains stuck in the redeem pool, and HAL is already burned.

2. **Redeem Request Delete Failure:**
   - A redeem request matures and `EndRedeeming` processes it.
   - Collateral is sent to the user successfully.
   - `DeleteRedeemRequest` is called, but `store.Delete(...)` fails silently.
   - The request remains in storage.
   - On the next block, `EndRedeeming` processes the same request again, potentially sending collateral twice.

3. **Ticket Creation Failure:**
   - User pays HAL tokens to create a ticket.
   - `AppendTicket` is called, but `store.Set(...)` fails.
   - Error is ignored, transaction succeeds.
   - User paid fees but ticket was not created.

## Recommendation

Check and handle errors from all KV store operations:

```go
// x/hal/keeper/keeper.go
func (k Keeper) SetRedeemRequest(ctx sdk.Context, request types.RedeemRequest) error {
	store := k.storeService.OpenKVStore(ctx)
	key := []byte(types.RedeemRequestKeyPrefix + request.Account)
	bz := k.cdc.MustMarshal(&request)
	
	if err := store.Set(key, bz); err != nil {
		return errorsmod.Wrap(err, "failed to store redeem request")
	}
	return nil
}

func (k Keeper) DeleteRedeemRequest(ctx sdk.Context, account string) error {
	store := k.storeService.OpenKVStore(ctx)
	key := []byte(types.RedeemRequestKeyPrefix + account)
	
	if err := store.Delete(key); err != nil {
		return errorsmod.Wrap(err, "failed to delete redeem request")
	}
	return nil
}
```

```go
// x/hal/keeper/ticket.go
func (k Keeper) AppendTicket(ctx sdk.Context, post types.Ticket) (uint64, error) {
	// ...
	if err := store.Set(bz, appendedValue); err != nil {
		return 0, errorsmod.Wrap(err, "failed to store ticket")
	}
	// ...
}

func (k Keeper) SetTicketCounter(ctx sdk.Context, count uint64) error {
	// ...
	if err := store.Set(byteKey, bz); err != nil {
		return errorsmod.Wrap(err, "failed to update ticket counter")
	}
	return nil
}
```

```go
// x/hal/keeper/params.go
func (k Keeper) SetParams(ctx context.Context, params types.Params) error {
	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	bz, err := k.cdc.Marshal(&params)
	if err != nil {
		return err
	}
	if err := store.Set(types.ParamsKey, bz); err != nil {
		return errorsmod.Wrap(err, "failed to store params")
	}
	return nil
}
```

## Team Response

N/A

---

[M-05] Missing Validation for MaxRedeemEntries

## Severity

Medium Risk

## Description

The `MaxRedeemEntries` parameter is defined in the `Params` of the module, intending to limit the number of concurrent redeem operations per account. However, this parameter is completely unused in the `RedeemCollateral` function.

While the current implementation suffers from an overwrite issue (discussed in M-02) that limits requests to 1 per account, fixing that issue without implementing `MaxRedeemEntries` enforcement would open the door to unbounded state growth. A user could submit an unlimited number of redeem requests, which are all iterated over in `EndRedeeming` at the end of every block.

## Location of Affected Code

```go
File: x/hal/keeper/msg_server_redeem_collateral.go

// No check for MaxRedeemEntries exists in this function
func (k msgServer) RedeemCollateral(goCtx context.Context, msg *types.MsgRedeemCollateral) (*types.MsgRedeemCollateralResponse, error) {
    ...
    // Request is created and stored without checking the count
    k.SetRedeemRequest(ctx, redeemRequest)
    ...
}
```

## Impact

If the overwrite issue is resolved (to allow multiple requests), the lack of `MaxRedeemEntries` enforcement allows a malicious user to spam the chain with thousands of small redeem requests.

Since `EndRedeeming` iterates over **all** redeem requests in `EndBlock`, a large number of pending requests would cause the `EndBlock` execution to consume excessive gas, potentially exceeding the block gas limit. This would lead to a chain halt or inability to process legitimate transactions (Denial of Service).

## Proof of Concept

1.  Assume the overwrite issue is fixed (requests are unique).
2.  Attacker submits 10,000 `MsgRedeemCollateral` transactions with small amounts.
3.  All 10,000 requests are stored in the state.
4.  In `EndBlock`, the `EndRedeeming` function iterates through all 10,000 requests to check if `ctx.BlockTime().After(req.Completiontime)`.
5.  This heavy iteration consumes massive computation and gas, potentially causing the block to timeout or fail, halting the chain.

## Recommendation

Enforce the `MaxRedeemEntries` limit in `RedeemCollateral`.

```go
    // Get params
    params := k.GetParams(ctx)
    maxEntries := params.MaxRedeemEntries

    // Get current number of pending requests for this account
    // Note: You will need to implement a way to count requests per account, 
    // potentially by using a prefix iterator or a separate counter.
    currentRequests := k.GetRedeemRequestCount(ctx, accAddr)

    if currentRequests >= maxEntries {
        return nil, errorsmod.Wrap(types.ErrMaxRedeemEntries, "max redeem entries reached")
    }
```

## Team Response

N/A
