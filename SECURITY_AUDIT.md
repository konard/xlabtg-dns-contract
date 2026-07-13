# Security Audit — TON DNS Smart Contracts (`.ton` zone)

**Audit request:** [xlabtg/dns-contract#1](https://github.com/xlabtg/dns-contract/issues/1)
**Scope reference:** [TON Bug Bounty Program](https://github.com/xlabtg/bug-bounty)
**Contracts audited (FunC):**

| File | Role | Lines |
|------|------|-------|
| `func/root-dns.fc` | Root DNS resolver (masterchain): `.ton`, `.t.me`, `www.ton` alias | 79 |
| `func/nft-collection.fc` | `.ton` DNS resolver + domain minter (NFT collection) | 139 |
| `func/nft-item.fc` | Domain (editable NFT item) with built-in auction | 318 |
| `func/dns-utils.fc` | Domain string parsing/validation, pricing | 109 |
| `func/params.fc`, `func/op-codes.fc` | Constants, workchain helpers, op codes | 17 |

**Source revision audited:** last functional change `fef4183` (2022‑10‑30). `func/stdlib.fc` is the standard library and is out of audit scope except where it affects the contracts above.

---

## 1. Executive summary

The three contracts implement the production `.ton` naming system: a masterchain
root resolver, a basechain collection that mints domains and starts auctions,
and per‑domain NFT items that carry ownership, editable on‑chain DNS records,
and a self‑contained ascending auction.

**No Critical, High, or Medium severity vulnerabilities were found.** Every
privileged action is gated by an explicit sender/authorization check, arithmetic
uses TON `coins`/256‑bit integers with guarded subtractions, and all
cross‑contract value flows are conservative (they never send more than the
contract can spare above `min_tons_for_storage`). A small number of
**Informational / Low** observations (code quality, documentation) are listed in
§6; none are exploitable.

This report follows the methodology and attack‑vector checklist from the audit
request. Findings are backed by direct code references and by executable tests
run against the real TON `func`/`fift` toolchain (§7). Per the request's
guidance ("No false positives — only report what you can prove with PoC"), no
speculative issues are reported as vulnerabilities.

---

## 2. Architecture & message flow

```
                masterchain                         basechain
        ┌───────────────────────┐        ┌───────────────────────────┐
resolve │  root-dns.fc          │  next  │  nft-collection.fc        │
──────► │  dnsresolve()         ├───────►│  (".ton" resolver+minter) │
        │  ".ton"/".t.me"/www   │        │  dnsresolve()             │
        └───────────────────────┘        │  op=0 deploy domain       │
                                         └───────────┬───────────────┘
                                                     │ deploy (mode 64)
                                                     ▼
                                         ┌───────────────────────────┐
                                         │  nft-item.fc (one domain) │
                                         │  auction + ownership +    │
                                         │  editable DNS records     │
                                         └───────────────────────────┘
```

* **`root-dns.fc`** is a pure resolver. `recv_internal` is an empty function —
  the contract holds no funds logic and cannot be mutated by messages; its
  storage (three resolver addresses) is only settable by a code/data upgrade
  outside message flow. `dnsresolve` returns a `dns_next_resolver` record
  pointing at the appropriate basechain resolver.
* **`nft-collection.fc`** validates a requested domain name, enforces minimum
  price and the network blacklist, and deploys the deterministic per‑name item
  (`item_index = slice_hash(domain)`), forwarding the buyer's payment with send
  mode `64` (carry remaining value).
* **`nft-item.fc`** runs the auction, then holds ownership and DNS records. The
  winning bid is forwarded to the collection; the item retains only
  `min_tons_for_storage` (1 TON).

### Trust boundaries

| Party | Trusted for | Enforcement |
|-------|-------------|-------------|
| Collection contract | initializing an item, receiving auction proceeds | `equal_slices(collection_address, sender_address)` (item.fc:127, 145) |
| Domain owner | transfer, edit content, change DNS records | `equal_slices(sender_address, owner_address)` (item.fc:195, 200, 205) |
| Network config (validators / governance) | seize/destroy a domain | data read from `config_param(dns_config_id)` (item.fc:228, collection.fc:80) |
| Anyone (untrusted) | placing bids, buying names, triggering time‑based expiry | economic + temporal guards only |

---

## 3. Threat model

Assets: (a) domain ownership (the NFT), (b) TON held by an item during/after an
auction, (c) DNS resolution integrity. Attacker capabilities: send arbitrary
internal messages with attacker‑chosen `op`, `query_id`, body, sender, and value
(subject to paying for it). The attacker cannot forge `sender_address`, cannot
write network config, and cannot make `now()` move backwards.

The remainder of this report walks the request's checklist and states, for each
item, the concrete code guard and whether an attack is possible.

---

## 4. Attack‑vector checklist results

### 4.1 Message handling
* **Incoming message validation / `op` handling** — `nft-item.fc` dispatches on a
  32‑bit `op` and rejects anything unrecognized with `throw(0xffff)`
  (item.fc:263). `op == 0` is treated as a bid/fill‑up (not a fall‑through).
  `nft-collection.fc` bounces empty bodies (`throw(0xffff)`, collection.fc:52)
  and rejects unknown ops (collection.fc:99). ✅ *Verified by test
  `security-item-access-control.js` (unknown op → 65535).*
* **Sender authentication** — see §2 trust‑boundary table; every privileged
  branch checks `sender_address`. ✅
* **Replay protection** — not applicable in the wallet sense: these are
  internal‑message‑driven contracts with no signatures/seqno. Each internal
  message is delivered once by the network; there is no signed payload that
  could be replayed. State transitions are idempotent w.r.t. authorization
  (e.g., re‑sending a deploy for an already‑initialized item just refunds the
  sender, item.fc:145‑149). ✅
* **Bounced messages** — both `recv_internal`s ignore bounced messages early
  (`flags & 1` → `return ()`, item.fc:114, collection.fc:57). Outgoing messages
  use non‑bounceable flag `0x10` deliberately (item.fc:66). ✅

### 4.2 Signature verification
Not applicable. Neither contract verifies off‑chain signatures; authorization is
by on‑chain `sender_address` and network config. There is therefore **no
signature bypass / malleability surface**. ✅

### 4.3 State management
* **Initialization** — `load_data` distinguishes an uninitialized item
  (only `index + collection_address` stored) from an initialized one by checking
  residual `slice_bits` (item.fc:43‑47). Only the collection can initialize
  (`throw_unless(405, ...)`, item.fc:127). Re‑initialization is impossible: once
  initialized, a further collection deploy hits the refund branch
  (item.fc:145). ✅
* **Consistency / atomicity** — TON executes one message per transaction with an
  atomic `set_data`; there is no synchronous re‑entrancy. The item estimates its
  post‑send balance locally (`my_balance -= amount_to_send`, item.fc:187) purely
  to size the next transfer conservatively; the authoritative balance change
  happens in the action phase. ✅
* **State exposure** — get‑methods expose only public NFT data (owner, content,
  domain, auction, index). No secrets are stored on‑chain. ✅

### 4.4 Fund management
* **Balance checks before transfers** — every outgoing value is bounded by
  `my_balance - min_tons_for_storage()`:
  outbid refund (item.fc:164), auction settlement to collection (item.fc:184),
  ownership‑transfer excess (`throw_unless(402, rest_amount >= 0)`, item.fc:96),
  and balance‑release payout (item.fc:247). The contract can never be drained
  below its storage reserve by these paths. ✅
* **Integer overflow/underflow** — amounts are TON `coins` (≤ 2^120) and the 5%
  bid increment uses `muldiv(max_bid_amount, 105, 100)` with a 256‑bit
  intermediate (item.fc:163) — no overflow. All subtractions that could go
  negative are either guarded (`throw_unless(402, ...)`) or gated behind
  `amount_to_send > 0` (item.fc:165, 185, 248). ✅
* **Dust / underpayment** — buying a name requires `msg_value >= min_price`
  (collection.fc:76); out‑bidding requires ≥105% of the previous bid
  (item.fc:163); balance‑release requires `msg_value >= min_price`
  (item.fc:245). ✅ *Verified by `test/collection.js` (204) and
  `test/item-bid.js` (407).*

### 4.5 TVM‑specific
* **Gas / DoS** — the only unbounded loops are domain parsing
  (`read_domain_from_comment`, `get_top_domain_bits`, `check_domain_string`),
  all bounded by the message the sender pays for; running out of gas aborts the
  sender's own transaction with no state change. There is no path where a third
  party can force the contract itself to run out of gas at a critical moment. ✅
* **Cell/slice handling** — length pre‑checks guard every `preload_bits`/
  `load_*` in the resolvers (e.g. `subdomain_len >= 8*8` before
  `preload_bits(8*8)`, root-dns.fc:33). Domain length is bounded to
  4..126 bytes on mint (collection.fc:70‑73). ✅

### 4.6 DNS‑specific
* **Ownership checks** — record edits (`op::change_dns_record`,
  `op::edit_content`) require `sender == owner` (item.fc:200, 205). ✅
  *Verified by `security-item-access-control.js` (410/411) and
  `test/item-edit-record.js` (411).*
* **Resolution logic** — `dnsresolve` in all three contracts enforces
  byte‑aligned input (`mod(bits,8)==0`), requires the leading `\0`, and returns
  correctly‑sized `next_resolver` records. The root correctly resolves `.ton`,
  `.t.me` and the `www.ton → foundation.ton` alias, with the alias checked
  before the generic `.ton` branch (root-dns.fc:33‑74). ✅ *Verified by
  `test/root.js`.*

### 4.7 Governance / expiry (DNS‑specific privileged paths)
* **`op::process_governance_decision`** (item.fc:226) is permissionless to
  *trigger* but fully driven by `config_param(dns_config_id)` (network config
  #80). The op reads the decision (transfer target or destroy) keyed by the
  item's own `index`; it throws `415` if the index is absent and `413` if an
  auction is live. An attacker who is not the validator set cannot place an
  entry in the network config, so triggering the op for a non‑listed domain is a
  no‑op that only costs the attacker gas. ✅ *Verified by
  `security-item-access-control.js` (415) and `security-item-governance.js`
  (413).*
* **`op::dns_balance_release`** (item.fc:242) — permissionless re‑auction that is
  only allowed once a domain has not been refreshed for `one_year`
  (`throw_unless(414, now() - last_fill_up_time > one_year & auction is null)`),
  and requires the caller to pay `>= min_price`. `last_fill_up_time` is refreshed
  by every owner action (transfer/edit/record‑change/owner fill‑up), so an active
  owner is never exposed. This is the **intended domain‑expiry mechanism**, not a
  vulnerability. ✅ *Verified by `security-item-access-control.js` (414 while
  fresh) and `test/item-loss.js` (release after a year).*

---

## 5. Access‑control matrix (nft-item.fc)

| Operation | Op code | Allowed sender | Guard (exit code on violation) |
|-----------|---------|----------------|--------------------------------|
| Initialize item | (implicit, from collection) | collection | `405` |
| Refund on re‑deploy | (implicit) | collection | n/a (refund) |
| Bid / owner fill‑up | `0` | anyone (bid) / owner after auction | `407` (bid < 105%), `406` (post‑auction fill by non‑owner) |
| Transfer | `0x5fcc3d14` | owner | `401` |
| Edit content | `0x1a0b9d51` | owner | `410` |
| Change DNS record | `0x4eb1f0f9` | owner | `411` |
| Governance decision | `0x44beae41` | anyone (data from config) | `413` (auction live), `415` (not listed), `416` (bad op) |
| Balance release / re‑auction | `0x4ed14b65` | anyone (after 1y) | `414` (too fresh), `407` (underpaid) |
| Get static data | `0x2fcb26a2` | anyone | — (read‑only reply) |
| Unknown | — | — | `0xffff` |

---

## 6. Informational / Low‑severity observations

None of the following are exploitable; they are code‑quality / documentation
notes for maintainers.

* **I‑1 (Info, dead parameter).** `transfer_ownership` (item.fc:80) receives a
  `sender_address` argument that is never used inside the function — the new
  owner is read from `in_msg_body`/`config_value`. Harmless; removing it would
  slightly reduce gas and improve clarity. *(CWE‑1164: Irrelevant Code.)*
* **I‑2 (Info, duplicated error code).** Exit code `407` is reused for two
  distinct underpayment conditions — "bid below 105%" (item.fc:163) and
  "balance‑release below min price" (item.fc:245). Not a bug, but distinct codes
  would make off‑chain diagnostics unambiguous.
* **I‑3 (Info, behavioral note).** The `www.ton → foundation.ton` alias in
  `root-dns.fc` shadows any literal second‑level domain named `www`; such a name
  can never be resolved through the root. This is the documented intent of the
  alias, noted here for completeness.
* **I‑4 (Info, by‑design UX risk).** A domain is permanently lost to a new
  auction if the owner does not perform any state‑changing action for one year
  (§4.7). This is the intended economic model but is a foot‑gun for holders who
  assume ownership is perpetual; wallets integrating this contract should surface
  the `get_last_fill_up_time` deadline.
* **I‑5 (Info, non‑bounceable payouts).** All outgoing value messages use the
  non‑bounceable prefix `0x10` (item.fc:66). Refunds/payouts to a
  not‑yet‑initialized account therefore create it rather than bouncing back.
  Intended for user‑facing payouts; no fund‑loss because destinations are
  owner/bidder/collection addresses derived from prior interaction.

---

## 7. Reproduction / how findings were verified

The audit was validated with the upstream TON compiler and Fift VM (not on
mainnet/testnet, per the request's safety requirement):

```sh
# func + fift toolchain on PATH, FIFTPATH pointing at the fift library
bash test.sh          # runs the full suite, prints "OK" on success
```

New adversarial regression tests added by this audit:

* `test/security-item-access-control.js` — proves that a non‑owner cannot
  transfer (`401`), edit content (`410`), or change a DNS record (`411`); that
  an unknown op is rejected (`0xffff`); that `dns_balance_release` fails while
  the domain is fresh (`414`); and that a governance decision for a non‑listed
  domain is rejected (`415`).
* `test/security-item-governance.js` — proves a governance decision is rejected
  while an auction is live (`413`).

Both are wired into `test.sh` and pass deterministically alongside the 16
pre‑existing tests (18 scenarios total).

---

## 8. Conclusion

The audited `.ton` DNS contracts enforce authorization on every privileged
operation, keep all value transfers within safe balance bounds, and contain no
signature, replay, overflow, access‑control, or fund‑theft vulnerability within
the Bug Bounty scope. The permissionless governance‑ and expiry‑trigger paths
are safe because they are constrained by network config and time, respectively.
Recommendations are limited to the Informational items in §6.
