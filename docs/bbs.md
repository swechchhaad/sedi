# SEDI joint check: BBS credentials + zero-knowledge presentations (ProVerif)

**Tool:** ProVerif 2.05. Correspondence, reachability and secrecy queries; observational (diff-)equivalence.
**Model generator and runner:** [`scripts/bbs_proverif.py`](../scripts/bbs_proverif.py)
**Generated models:** [`proverif/bbs/`](../proverif/bbs/)
**Raw output, with traces:** `results/bbs/`

```
python3 scripts/bbs_proverif.py            # 11 trace + 11 equivalence models (~45 s)
make bbs
```

**Result:** all 136 results match the expected outcome: 125 query results (9 trace configurations × 11 queries, plus 2 issuer-KEL configurations × 13) and 11 equivalence checks. None are inconclusive. Every failure has a reconstructed trace, and each negative control fails on the term it was built to expose.

## 1. Why this exists
The per-requirement suites (CRY-01, CRY-02, PRV-01, PRV-02, PRV-03) check KERI/ACDC one requirement at a time. Two of their findings rule out a joint ACDC design:
- **No ACDC design is unlinkable against a colluding issuer** (PRV-01 experiment E).
- **A stable holder AID makes migration work (CRY-02) but links presentations (PRV-01).** The only way to satisfy both is per-copy AIDs, which means M rotations and M recovery keys.

This suite asks a different question: is there **one design** that satisfies all five requirements together? The candidate is anonymous credentials, specifically BBS with zero-knowledge presentations. Every requirement's properties are checked on the same design, using the same primitives.

## 2. Design under test

| Component | In the model | Real-world counterpart |
|---|---|---|
| Credential | `bbs((hid, attrs, rh), skI)`. Issued once, kept in the wallet, **never shown** | BBS signature (IETF CFRG draft) |
| Holder identifier | `hid = h(pk(sk0), h(pk(sk1)))`: a self-certifying identifier that pre-commits to the next device key | a KERI AID, used as a *hidden* attribute |
| Device key | `sk0` in the old device's secure element, `sk1` in the new device's. Used only through `sign()` (HW-NX, as in CRY-02) | secure-element ECDSA P-256 key |
| Key state | honest witnesses sign `(ks, hid, current device key, epoch)` for each epoch. A rotation in epoch 1 moves the attestation to `pk(sk1)` | KERI witnesses, publishing a ZK-provable key-state root each epoch |
| Revocation | accumulator per epoch. A non-revoked holder computes its non-membership witness `nmw(rh, e)` from the public whole-list update | accumulator non-membership proofs |
| Presentation | `(t, b, C, π_auth, π_rev)`, with `C = com(rh, rc)` freshly randomised | BBS proof + ZK proof of ECDSA signature + accumulator proof |

**π_auth** proves knowledge of:
- a BBS credential on `(hid, a, rh)`;
- a witness attestation that `kd` is `hid`'s device key at epoch `e`;
- a signature by `kd` on `(nonce, t, C)`;

such that predicate `t` of `a` equals `b`, and `C` commits to `rh`.

**π_rev** proves that the `rh` committed in `C` is not revoked at epoch `e`.

**The verifier** holds only the issuer public key, the witness public key and the current epoch. It syncs the epoch on a schedule. It checks authenticity first and status second, locally.

**Migration:** the new device rotates `hid` to the pre-committed `sk1` and takes over the wallet data. No private key moves, and **the credential is not reissued**.

### Symbolic zero knowledge
The ZK encoding follows Backes, Maffei and Unruh (IEEE S&P 2008), the same encoding used to verify DAA:
- A proof is a constructor `zk(secrets, publics, randomness)`.
- A public destructor checks the relation for the publics the verifier supplies. No destructor returns the secrets.
- Proofs carry fresh randomness, so every presentation is a new term.

The trace models also use **private ghost destructors**, i.e. the knowledge extractor. They let the verifier's events name the hidden holder, attributes and revocation handle. The attacker cannot use them, and the equivalence models don't declare them.

## 3. Trace properties

phase 0 = epoch `e0`, before migration; phase 1 = epoch `e1`, after migration. The attacker controls the network. It may also obtain credentials for holders it controls, after proving control of their inception key.

| Query | Requirement | Statement |
|---|---|---|
| sanity_accept_pre / post | CRY-02.4 | the honest holder's old device is accepted in epoch 0, and the new device in epoch 1 on the **same** credential (reachability) |
| sanity_authentic_but_revoked | CRY-01.3 | a revoked holder is accepted as authentic and then fails the separate status check (reachability) |
| cry01_unforgeable | CRY-01.1 | `Accept(…, hid, a) ⇒ Issued(hid, a, rh)` |
| cry01_prv03_no_presentation_traffic | CRY-01.2, PRV-03 L1–L4 | no Department-visible message is caused by a presentation |
| cry01_status_sound | CRY-01.3 | a revoked handle never passes the status check |
| cry02_control_pre | CRY-02.3 | accepting an honest holder ⇒ its device signed this nonce and commitment |
| cry02_control_post | CRY-02.3/4/5 | after migration, acceptance ⇒ the **new** device key signed (the old key is invalid) |
| cry02_control_or_compromise | CRY-02.6 | holder control fails only after a device-key compromise |
| cry02_sk0 / sk1_secret | CRY-02.2/5 | device keys stay secret (HW-NX) |

| Config | sanity pre | sanity post | revoked | unforgeable | no pres. traffic | status sound | control pre | control post | control \| comp | sk0 | sk1 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **POS_joint** | holds | holds | holds | holds | holds | holds | holds | holds | holds | holds | holds |
| E_wallet_data_leak | holds | holds | holds | holds | holds | holds | holds | holds | holds | holds | holds |
| NEG_no_device_signature | holds | holds | holds | holds | holds | holds | **FAILS** | **FAILS** | **FAILS** | holds | holds |
| E_device_malware | holds | holds | holds | holds | holds | holds | **FAILS** | holds | holds | holds | holds |
| E_old_device_after_migration | holds | holds | holds | holds | holds | holds | holds | holds | holds | **FAILS** | holds |
| E_old_device_stale_verifier | holds | **FAILS** | holds | holds | holds | holds | holds | **FAILS** | holds | **FAILS** | holds |
| E_recovery_key | holds | holds | holds | holds | holds | holds | holds | holds | holds | holds | **FAILS** |
| E_recovery_key_and_wallet_leak | holds | holds | holds | holds | holds | holds | holds | **FAILS** | holds | holds | **FAILS** |
| NEG_online_status | holds | holds | holds | holds | **FAILS** | holds | holds | holds | holds | holds | holds |

### Reading the table
- **POS_joint: everything holds in one model.**
  - Authenticity is checked offline, separately from status, with no shared secret.
  - Only the holder's device can produce an accepted proof.
  - Migration keeps the credential and retires the old key.
  - No presentation causes Department traffic.
- **E_wallet_data_leak vs. NEG_no_device_signature.** Leaking the wallet's storage (the credential, `rh`, the witnesses) is harmless while the proof requires a device signature. Without that signature, as with a software link secret like AnonCreds, the same leak lets the attacker present as the holder. **Holder binding comes from the secure element, not from the credential secret.**
- **E_device_malware:** malware that reads the wallet and drives the secure element controls the holder before migration, the same as CRY-02's signing oracle. Migrating to `sk1` restores control.
- **Old device compromised after migration:** harmless against a verifier on the current epoch. Against a **stale** verifier the old key is accepted again and the new device is rejected. Old-key invalidation is only as fresh as the verifier's epoch, which is the same freshness condition CRY-01 and CRY-02 found.
- **Recovery key compromised:** the key alone is **not** enough here, unlike KERI CRY-02 `E_recovery_key`. The credential is a wallet secret, never shown, so the attacker also needs the wallet data. With both, the attacker controls the identifier after migration.
- **NEG_online_status:** sending the status proof to the Department breaks offline verification and PRV-03, even though the proof reveals nothing about the credential.

## 4. Equivalence properties

| Config | Experiment | Expected | Result | Distinguishing test (negatives) |
|---|---|---|---|---|
| **LINK_pos** | PRV-01. Population {H1, H2}. World 0: H1 presents to V1 and V2; world 1: H1 to V1, H2 to V2. **The attacker is the verifiers plus the issuer**: issuer key and issuance records `(hid, attrs, rh)`. The holders' undisclosed attributes differ. | equivalent | **equivalent** | none |
| **LINK_pos_across_migration** | as above, but the second presentation is after both holders rotated (new device key, epoch 1) | equivalent | **equivalent** | none |
| LINK_neg_signature_disclosed | the BBS signature is shown instead of proved | linkable | linkable | `bbs(choice[…])` |
| LINK_neg_device_key_disclosed | device public key and signature are shown (mdoc-style device binding) | linkable | linkable | `pk(choice[k10, k20])` |
| LINK_neg_revocation_handle_disclosed | the revocation handle is shown (status-list index) | linkable | linkable | `choice[rh1, rh2]` |
| **PRED_pos** | PRV-02. Age 22 (T,F,F) vs. 27 (T,T,F). The holder approves ≥21 and ≥30 and declines ≥25. **One credential, unbounded repeated requests.** | equivalent | **equivalent** | none |
| PRED_neg_arbitrary_predicates | the wallet answers every requested predicate | distinguishable | distinguishable | the ≥25 answer `tt` |
| **NI_pos** | PRV-03. Presentation vs. no presentation. The Department is the issuer and sees every Department endpoint, including scheduled syncs. | equivalent | **equivalent** | none |
| NI_neg_online_status | the verifier sends the status proof to the Department | distinguishable | distinguishable | the status query exists in world 0 only |

## 5. Hybrid issuer: KERI key state for the issuer too

In §3–4 the issuer has a static BBS key, like CRY-01 variant A. The `ISSUER_KEL` configurations make the issuer side KERI-managed as well. The verifier pins **only the issuer AID** (and the witness key). Its scheduled sync fetches the issuer's KEL:
- the inception, checked against the pinned AID;
- an interaction event anchoring the issuer's **BBS public key**;
- an interaction event anchoring **each epoch's accumulator value**.

The anchors are signed by the issuer's current KEL key. Revocation proofs (π_rev) are checked against the anchored accumulator value. This replaces ACDC's TEL with an anchored accumulator. There is no per-credential anchor, which would be a public identifier.

Two queries are added:

| Query | Statement |
|---|---|
| issuer_key_anchored | `VerifierState(e, pkI, acc) ⇒ AnchoredKey(pkI)`: the BBS key the verifier uses was anchored by the issuer |
| issuer_acc_anchored | `VerifierState(e, pkI, acc) ⇒ AnchoredAcc(e, acc)`: the accumulator value was anchored for that epoch |

| Config | the 11 queries of §3 | issuer_key_anchored | issuer_acc_anchored |
|---|---|---|---|
| **POS_issuer_kel** | all hold | holds | holds |
| NEG_unchecked_key_anchor (verifier skips the signature check on the key anchor) | all hold except **cry01_unforgeable FAILS** | **FAILS** | holds |

| Equivalence | Result |
|---|---|
| LINK_pos_issuer_kel (issuer colludes and also knows its KEL keys; proofs use the anchored accumulator) | **equivalent** |
| NI_pos_issuer_kel (the verifier's scheduled sync fetches the issuer KEL) | **equivalent** |

**Reading it:**
- **The hybrid keeps every result of the static-key design.** It also gets the issuer key and the accumulator from a self-certifying root instead of an out-of-band channel.
- **The anchor check matters.** Without it, the attacker supplies its own BBS key and issues itself credentials with any attributes: a self-made identifier and device key, so unforgeability fails. Holder control still holds even then, because a forged credential for an honest holder still needs that holder's device signature.
- **Fetching the issuer KEL leaks nothing.** It is the same for every holder and happens on a schedule, so it stays invisible to the Department (NI) and to colluding verifiers (LINK).

**Not covered yet: rotation and compromise of the issuer's BBS key.** The KEL key never rotates here and no issuer key leaks. Because credentials are not anchored one by one, a leaked *retired* BBS key could forge credentials unless the issuer either reissues, or anchors an "issued set" accumulator that presentations prove membership in. Those are the next configurations to check.

## 6. Conclusions

**This design satisfies all five requirements together in the symbolic model.** The assumptions are listed in §7. It removes the conflicts the ACDC suites found:

| ACDC finding | BBS + ZK result |
|---|---|
| Linkable against a colluding issuer (PRV-01 E) | **unlinkable** even with the issuer's key and issuance records (LINK_pos). Blind issuance is not needed for unlinkability: presentations reveal nothing about the credential. Knowing the credential is also not enough to present it (E_wallet_data_leak). That an issuer holding its *signing key* can't impersonate the holder is not modelled. |
| Stable AID: migration works but presentations link (CRY-02 × PRV-01) | the stable `hid` is a **hidden** attribute. Migration keeps unlinkability (LINK_pos_across_migration), with no per-copy AIDs and one rotation per holder. |
| Unlinkability needs bulk copies, one per presentation (PRV-01 M1/M2, PRV-02) | **one credential**, re-randomised per presentation. Unbounded repeated predicate requests stay private (PRED_pos). |
| Only issuer-precomputed predicates (PRV-02) | the predicate is proved at presentation time. In the model this is a bounded domain of three thresholds (§7). |
| Status cache miss forces an online fetch (CRY-01 B_cached, PRV-03 refresh-on-miss) | accumulator **non**-membership: a credential issued after the last sync needs no per-credential status entry |
| Device-key binding links presentations (CRY-02, mdoc-style) | the device signature sits **inside** the proof, so the key never appears (LINK_neg_device_key_disclosed shows the alternative) |

What remains are **conditions**, not contradictions:
1. **Freshness is bounded by the epoch.** Revocation and key rotation take effect at the verifier's next scheduled sync. A verifier that is not on the current epoch accepts a retired key (E_old_device_stale_verifier). This trade-off applies to any design that satisfies PRV-03. Making the epoch shorter narrows the window; syncing on presentation breaks PRV-03.
2. **Holder binding rests on the secure element (HW-NX).** It is assumed, not proved, exactly as in CRY-02.
3. **The pre-rotated recovery key and the wallet data together are a single point of takeover.** Keep them in separate places.

## 7. Assumptions and limitations
- **Symbolic ZK is perfect.** Soundness is the destructor's relation, and zero knowledge means "no destructor returns the secrets". A concrete instantiation has to prove one statement that combines:
  - a BBS proof of knowledge,
  - a ZK proof of an **ECDSA P-256 signature by a hidden key** (needed for phone secure elements),
  - a ZK proof of a **witness attestation on hidden values** (a ZK-friendly witness signature, or a Merkle root of key states),
  - an accumulator non-membership proof.

  Each part has published constructions: BBS proofs; ZK over ECDSA, e.g. Frigo & shelat's "Anonymous credentials from ECDSA" and Orange's BBS#; accumulators. **Composing them, and making that fast enough on a phone, is not established by this model.** That is where the remaining risk is.
- **The equivalence models are separate from the trace model.** All the models use the same primitives and the same design. Each equivalence model is a straight-line process: two presentations (LINK), one holder with unbounded requests (PRED), one presentation (NI). Diff-equivalence is stronger than observational equivalence, so every `equivalent` is sound.
- **Bounded predicate domain:** three thresholds (≥21, ≥25, ≥30), one rewrite rule each. Real range proofs cover arbitrary thresholds. The model abstracts that as "the verifier learns exactly `b`".
- **Accumulator soundness is assumed.** `nmw` is a private function, so nobody can compute a witness for a revoked handle. The issuer manages the accumulator honestly. Issuer key compromise is not modelled.
- **Witnesses are honest and use a single key.** Witness duplicity and thresholds (KAWA) are not modelled. The issuer key is static (§3–4) or anchored in a KEL that never rotates (§5).
- **Every holder rotates at the epoch boundary,** and witnesses attest epoch 1 only for rotated identifiers. A holder created mid-epoch gets an attestation for the current epoch at inception.
- **Not repeated here, because they don't depend on the credential scheme:**
  - PRV-02 metadata: size, timing and errors. ZK proofs are constant-size per statement, but the implementation tests in `prv02.md` §6 still apply.
  - PRV-01 network metadata: anonymous transport is still a deployment assumption.
