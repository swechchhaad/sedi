# SEDI-CRY-01: offline authenticity verification (ProVerif)

**Tool:** ProVerif 2.05, with correspondence, reachability and secrecy queries.
**Model generator and runner:** [`scripts/cry01_proverif.py`](../scripts/cry01_proverif.py)
**Generated models:** [`proverif/cry01/`](../proverif/cry01/)
**Raw output, with traces:** `results/cry01/`
**Tamarin counterpart:** [`tamarin/cry01_offline_verification.spthy`](../tamarin/cry01_offline_verification.spthy). This ProVerif model is the primary result for now. The Tamarin theory is to be re-run as a cross-check (see §7).

```
python3 scripts/cry01_proverif.py           # 10 configurations x 8 properties (~2 s)
```

**Result:** all 80 results match the expected outcome. None are inconclusive. Every `false` result comes with a reconstructed trace.

## 1. What CRY-01 requires
1. Authenticity and integrity can be verified using **only the Department's published verification key and the credential**.
2. There is **no real-time communication** with the Department or any third party for authenticity.
3. Status may be checked externally, but **separately** from authenticity.
4. There is **no shared-secret** authentication.

## 2. KERI's KEL is not "the Department's published verification key"
In variant A the verifier's trust anchor is a **static key** `pk(skD)`, loaded once out of band. In KERI/ACDC (variants B and C) the trust anchor is the issuer **AID** `h(pk(k0), h(pk(k1)), witness key)`. This is a self-certifying digest of the inception key, the pre-rotation commitment and the witness configuration. The AID alone is not enough to check a credential:

- **The ACDC carries no signature of its own.** It is *anchored* by an interaction event (`ixn`) in the issuer's KEL, signed with the key that was current when it was issued.
- **After a rotation**, the verifier must know the issuer's *current* key state. Otherwise a retired key can still be used to sign.

How the verifier obtains that KEL state is what separates the variants:

| Config | KEL state is... | Real-time communication during the check? |
|---|---|---|
| A (static key) | not applicable; the static key is published once | no |
| B_carried | **carried by the holder** as a proof: inception [+ rotation] | no |
| B_carried_receipts | **carried**, plus the **witness receipt** for the anchoring event | no |
| B_cached | **cached locally**, copied from the witnessed KEL *before* the check (online, at sync time) | no, but the cache was filled online earlier |
| C_online_kel | **retrieved online** from witnesses *during* the check | **yes** |
| C_keripy_online_kel_tel | retrieved online, plus TEL state from the registry, before acceptance | **yes** |

"Included in the credential" is not a KERI option: the ACDC contains its issuer AID but no KEL.

## 3. Model
**Attacker:** a Dolev-Yao network. The Department, its witnesses and its status registry are honest unless a compromise flag reveals a key.

**KERI timeline (phases):**
- **phase 0:** inception, then credentials anchored under `k0`.
- **phase 1:** rotation to the pre-committed `k1`, then credentials anchored under `k1`. Key compromise happens here: the *retired* `k0` or the *current* `k1`.
- **phase 2 / 3:** verification (or a cache sync in phase 2, then verification from the cache in phase 3).

**Witnesses (AS-WIT):** they receipt an anchoring event only if it is signed by the key that is current *in that phase*.

**Status:** a separate `Status` process runs **after** authenticity is accepted. It queries the registry and records `StatusGood` or `StatusFail`.

**Verification sessions:** every session has a fresh `sid`, so "no query *during* the check" is a statement about that session.

**Assumptions:**
- **AS-PUB (A):** `pk(skD)` is obtained once, out of band.
- **AS-PUB-AID (B, C):** the issuer AID is pinned once, out of band.
- **AS-WIT:** honest witnesses, as above.
- **AS-STAT:** the status registry signs its answers.

## 4. Lemmas

| ID | Statement | ProVerif query |
|---|---|---|
| sanity | an honestly issued credential is accepted | `AuthAccept(sid,s,a) ∧ Issued(s)` reachable |
| L1 strict | accepted ⇒ issued | `AuthAccept(sid,s,a) ==> Issued(s)` |
| **L1** | **accepted ⇒ issued, unless an issuer signing key was revealed** | `... ==> Issued(s) ∨ Compromised(a)` |
| L1b | accepted ⇒ issued, unless the **current** key was revealed (a retired key must not suffice) | `... ==> Issued(s) ∨ CompromisedCurrent(a)` |
| **L2** | **no Department/third-party query during an accepted check** | `AuthAccept(sid,..) ∧ OnlineQuery(sid,..) ==> false` |
| **L3a** | **acceptance does not require a status query** | `AuthAccept(sid,..) ==> StatusQuery(sid)` is *false* |
| **L3b** | **status failure is distinguishable from authenticity failure**: authenticity never fails because status is unavailable | `AuthReject(sid, s, nostatus)` unreachable |
| **L4** | **no shared-secret path**: the verifier's pinned verification material is publicly derivable | `attacker(pk(skD))` / `attacker(AID)` reachable. The shared MAC key `kDV` is not derivable. |

## 5. Results

| Config | sanity | L1 strict | **L1** | L1b post-rotation | **L2 offline** | **L3a** status-free | **L3b** distinct | **L4** no secret |
|---|---|---|---|---|---|---|---|---|
| A_static_key | holds | holds | holds | holds | holds | holds | holds | holds |
| A_static_key_revealed | holds | **FAILS** | holds | holds | holds | holds | holds | holds |
| A_shared_secret_NEG | holds | holds | holds | holds | holds | holds | holds | **FAILS** |
| B_carried | holds | holds | holds | holds | holds | holds | holds | holds |
| B_carried_retired_key_revealed | holds | **FAILS** | holds | **FAILS** | holds | holds | holds | holds |
| B_carried_receipts_retired_key_revealed | holds | holds | holds | holds | holds | holds | holds | holds |
| B_cached_retired_key_revealed | holds | holds | holds | holds | holds | holds | holds | holds |
| B_cached_current_key_revealed | holds | **FAILS** | holds | holds | holds | holds | holds | holds |
| C_online_kel | holds | holds | holds | holds | **FAILS** | holds | holds | holds |
| C_keripy_online_kel_tel | holds | holds | holds | holds | **FAILS** | **FAILS** | **FAILS** | holds |

### Counterexample traces
1. **B_carried: post-rotation forgery (L1 strict, L1b).**
   1. The issuer rotates from `k0` to `k1`.
   2. The *retired* key `sk0` is revealed.
   3. The attacker signs `(ixn, aid, s')` with `sk0` for a SAID `s'` that was never issued.
   4. It presents that anchor with **only the inception event**, leaving out the rotation.
   5. The verifier checks the inception against the pinned AID, verifies the anchor under `k0`, and accepts.

   The carried KEL **cannot prove it is the latest KEL**. KERI's claim that a compromised retired key is harmless therefore needs fresh key state. The same attack **fails** when the holder also carries the **witness receipt** for the anchor (B_carried_receipts): witnesses only receipt events signed by the current key. It also fails when the verifier checks against a **cached witnessed KEL** (B_cached).
2. **A_static_key_revealed and B_cached_current_key_revealed (L1 strict).** Once the *current* signing key leaks, forgeries are accepted. L1 still holds, because the exception applies. The difference: under A the forgery works **forever**, since a static key has no rotation. Under KERI it works until the issuer rotates to its pre-committed key.
3. **A_shared_secret_NEG (L4).** The negative control. The verifier authenticates with a MAC key `kDV` it shares with the Department. ProVerif proves `kDV` is not derivable from public information, so the acceptance path depends on a shared secret. This shows L4 actually distinguishes the cases.
4. **C_online_kel (L2).** The verifier issues `OnlineQuery(sid, witness)` before `AuthAccept(sid, ...)`.
5. **C_keripy_online_kel_tel (L2, L3a, L3b).** This models keripy's verifier ([`src/keri/vdr/verifying.py:126-143`](../src/keripy/src/keri/vdr/verifying.py#L126-L143)). It will not accept a credential until TEL state for it is known: it escrows the credential and queues a `telquery`. That gives three failures:
   - `StatusQuery(sid)` happens before every `AuthAccept(sid, ...)` (L3a);
   - both an online query to the registry and one to the witnesses happen during the check (L2);
   - if the status answer is missing or invalid, the credential is rejected *as an authenticity failure*: `AuthReject(sid, s, nostatus)` (L3b).

## 6. Conclusion: KERI/ACDC satisfies CRY-01 only conditionally
- **Variant A** satisfies CRY-01 exactly as worded. The cost is that a key compromise is permanent.
- **KERI/ACDC with carried *and receipted* KEL evidence, or a KEL cache filled before the check,** satisfies CRY-01. Authenticity is checked offline, separately from status, without shared secrets. It is also robust to compromise of a *retired* key, which variant A cannot offer. The conditions:
  - the verifier has pinned the issuer AID;
  - it trusts the witness configuration committed in that AID (AS-WIT);
  - for the cache variant, the cache was filled online *before* the check and is recent enough to include the credential's anchor. That is an explicit freshness assumption.
- **KERI/ACDC with carried KEL but no witness receipts** satisfies the offline requirement. It is **not** robust after rotation: a retired key can forge credentials against a verifier that only sees the carried events.
- **KERI/ACDC as keripy's verifier implements it (C_keripy)** does **not** satisfy CRY-01:
  - it needs real-time contact with witnesses/registry during verification (clause 2);
  - it makes authenticity acceptance depend on a status lookup (clause 3);
  - it reports unavailable status as an authenticity failure (clause 3).

  Offline operation needs the credential's TEL state carried or cached, which is PRV-03 variants C/D.

## 7. Scope, limitations and the Tamarin cross-check
- **One rotation, one witness key.** Witness thresholds (KAWA), witness duplicity and delegation are not modeled. AS-WIT is an assumption.
- **Phases stand in for key-state epochs.** Witnesses accept events signed by the key current *in that phase*, which avoids ProVerif's over-approximation of "latest KEL entry" lookups (see `docs/cry02.md` §7).
- **Status:** revocation itself is not modeled. Status failure means the answer is missing or invalid. That is enough for the separation lemmas.
- **Symbolic cryptography:** perfect signatures and hashes.
- **Witness lag (Tamarin finding).** A key is only safely "retired" once the **witnesses** have accepted the rotation. In the window between the controller's rotation and the witnesses processing it, a lagging witness still treats the old key as current and will receipt anchors signed with it. So a compromise of the old key *inside that window* can produce a witnessed forgery. KERI controllers are expected to wait for witness receipts of the rotation. Both models therefore count "retired" at the witnesses in the witness variants. The ProVerif phases make the witnesses switch at the phase boundary; the Tamarin theory uses `WitRetired`.

## 8. Tamarin cross-check
[`tamarin/cry01_offline_verification.spthy`](../tamarin/cry01_offline_verification.spthy), run with `python3 scripts/run_all.py --only cry01` (Tamarin 1.12.0, `--heuristic=S`). **All 66 lemma results match their expected values** (about 2 minutes on a laptop), and they agree with the ProVerif results above:

| Property | Tamarin | ProVerif |
|---|---|---|
| A: every lemma holds; the shared-secret control falsifies `no_shared_secret_path` (and `status_failure_distinguishable…`) | ✓ | ✓ (L4 fails) |
| B_carried: `auth_unforgeability_post_rotation_compromise` | falsified (truncated-KEL forgery) | L1b fails |
| B_cached: post-rotation unforgeability | verified | L1b holds |
| B_cached: `offline_evidence_always_available` | falsified (cache miss for a credential issued after the sync) | not modeled |
| C: `offline_auth_no_department_or_third_party_query`, `status_not_required_for_auth`, `status_failure_distinguishable_from_auth_failure` | all falsified | L2, L3a, L3b fail |

The first remote run of this theory produced 9 timeouts or errors, including the sanity lemmas for B_cached and C, so several "verified" results could have been vacuous. The theory was changed as follows. None of the changes alters which messages are accepted.
1. **Signature and self-certification checks are written as pattern matching** (`In(<ev, sign(ev, x)>)`, `aid = h(<pk(x), n>)`) instead of `Eq(verify(...))` restrictions. Under the built-in signing theory these accept exactly the same messages. Tamarin reports the intended "variables not derivable from premises" wellformedness warning for these rules.
2. **Issuance and witness anchoring read persistent current-key facts** (`!IssuingKey`, `!WitKeyState`) instead of consuming and re-creating a linear state fact, a loop Tamarin unrolled without end. The restrictions `NoIssueUnderRetiredKey` and `WitNoOldKeyAfterRotation` keep the original meaning (no old-key use after the rotation).
3. **AS-ROT is also enforced at the witnesses** (`OneWitnessRotationPerAID`). Without it, an attacker holding a key could rotate the witness state indefinitely.
4. **Two helper lemmas, proved and then reused:** `ixn_signature_origin` and `rot_signature_origin`. An anchor or rotation signature under an issuer key comes from the issuer, or from a revealed key.
5. **Lemma wording fixes:**
   - `no_shared_secret_path` also accepts a key whose digest was published (a pre-rotated key is public by commitment);
   - the post-rotation lemma counts retirement at the witnesses in the witness variants (see *Witness lag* above).
6. **`--heuristic=S`.** Tamarin's default heuristic did not terminate on the sanity lemmas for B_cached and C.
