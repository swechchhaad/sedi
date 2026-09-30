# SEDI-PRV-01: cross-presentation unlinkability of ACDC presentations

**Tool:** ProVerif 2.05, observational (diff-)equivalence of biprocesses.
**Model generator and runner:** [`scripts/prv01_proverif.py`](../scripts/prv01_proverif.py)
**Generated models:** [`proverif/prv01/`](../proverif/prv01/), one `.pv` file per configuration.
**Raw output, with attack traces:** `results/prv01/<config>.log`

Reproduce all results (about 2 s in total):

```
python3 scripts/prv01_proverif.py            # generate + prove all 28 configurations
python3 scripts/prv01_proverif.py --list     # list configurations and flags
```

## 1. Experiment

| | World 0 (`choice` left) | World 1 (`choice` right) |
|---|---|---|
| Presentation to V1 | holder **H**, copy C1 | holder **H1**, copy C1 |
| Presentation to V2 | holder **H**, copy C2 | holder **H2**, copy C2 |

**Parties:**
- **Issuer I:** honest, except in experiment E.
- **Holders:** honest.
- **Verifiers V1 and V2:** malicious, and they pool all their observations. They are the ProVerif attacker. Every presentation is sent on the public channel, and the attacker chooses each verifier's challenge nonce.
- **Network observer N:** an active observer is the same attacker. Experiment D adds what N sees on the wire.

**Held equal in both worlds:**
- the issuer (a single key)
- the schema
- the disclosed attribute (`over21`, except in experiment B)
- the number of presentations (exactly two)
- message size and timing in experiment A (both are constants there)

If ProVerif proves the two worlds equivalent, colluding verifiers cannot tell "one person twice" from "two different people". That is the formal statement of PRV-01's "no cross-presentation linking" requirement.

**Modeling technique:** each value that could identify a holder is modeled as
- **holder-bound:** `new x1; new x2; let x2' = choice[x1, x2]`, so the value repeats in world 0 and differs in world 1; or
- **per-copy:** `new x1; new x2`, so the value is independent in both worlds.

Each privacy mechanism moves exactly one value from holder-bound to per-copy.

### ACDC abstraction
This is the same abstraction as [`tamarin/cry01_offline_verification.spthy`](../tamarin/cry01_offline_verification.spthy):

```
attribute block   ab   = h(attrs, holder-name, attribute-salt)       -- undisclosed, salted
SAID              said = h(issuer, schema, pk(issuee), ri, disclosed, ab, uuid)
credential        cred = (said, issuer, schema, pk(issuee), ri, disclosed, ab, uuid)
anchor            sign((ixn, said), skI)                             -- or, for a batch, of aggregate B
holder AID        h(aid, inception material)                         -- stable across key rotation
presentation      (addr, shape, (pres, cred, anchor, holderAID, pk(k)), sign((nonce, ...), k))
```

## 2. Privacy mechanisms

The configurations are **cumulative**: P*k* enables M1 through M*k*.

| | Mechanism | What becomes per-copy |
|---|---|---|
| P0 | baseline ACDC: one credential, stable SAID, per-holder TEL, stable Issuee AID, stable holder AID and key | nothing |
| P1 | **M1** bulk-issued copies with unique SAIDs, Merkle-batched with the **full leaf list** disclosed, as in keripy `tests/acdc/test_bulk_issuance.py` | uuid, attribute salt |
| P2 | **M2** fresh, individually anchored copy per presentation | no batch aggregate `B`, no leaf list |
| P3 | **M3** unique Issuee AID per copy | Issuee AID |
| P4 | **M4** independent TEL registry per copy | `ri` |
| P5 | **M5** no stable holder AID | holder (sender) AID |
| P6 | **M6** fresh presentation proof key | signing key `k` |
| P7 | **M7** normalized message size and timing | shape tag (only observable in experiment D) |
| P8 | **M8** private or anonymous status retrieval | status session (only observable in experiment C) |

## 3. Results

All 28 configurations matched their expected outcome.
- `true`: observational equivalence was **proved**, so the presentations are unlinkable in this model.
- `false`: ProVerif **found an attack trace** that distinguishes the two worlds.

Every `false` result below comes with a concrete reconstructed trace ("A trace has been found"), so none of them is an over-approximation artifact.

### A. Artifact-only unlinkability (cumulative)

| Config | Result | Distinguishing test found by ProVerif | Cause |
|---|---|---|---|
| P0 | **linkable** | `said₁ = said₂` | SAID |
| P1 | **linkable** | `pk(issuee₁) = pk(issuee₂)`; the full leaf list and `B` also link (see ablation) | Issuee AID, shared chain reference |
| P2 | **linkable** | `pk(issuee₁) = pk(issuee₂)` | Issuee AID |
| P3 | **linkable** | `ri₁ = ri₂` | TEL |
| P4 | **linkable** | `holderAID₁ = holderAID₂` | holder AID |
| P5 | **linkable** | `pk(k₁) = pk(k₂)` | proof material |
| P6 | **unlinkable** | none | none |
| P7 | **unlinkable** | none | none |
| P8 | **unlinkable** | none | none |

### A. Minimized counterexamples (single-leak ablations from P8)
In each run, all mechanisms are on except one, so the attack trace contains exactly one distinguishing term. That term is the minimal counterexample.

| Leak left in place | Result | Distinguishing test | Cause |
|---|---|---|---|
| one credential reused (uuid and attribute salt shared) | linkable | `ab₁ = ab₂`; SAID and uuid repeat as well | SAID |
| batched copies, full leaf list | linkable | `B₁ = B₂` | shared chain reference (batch aggregate) |
| batched copies, **Merkle inclusion proof** | linkable | `B₁ = B₂` | shared chain reference (batch aggregate) |
| stable Issuee AID | linkable | `pk(issuee₁) = pk(issuee₂)` | Issuee AID |
| per-holder TEL registry | linkable | `ri₁ = ri₂` | TEL |
| stable holder AID | linkable | `holderAID₁ = holderAID₂` | holder AID |
| stable proof key | linkable | `pk(k₁) = pk(k₂)` | proof material |
| keripy reference: M1 + M3 + M5 + M6, with a shared registry and the full list | linkable | `ri₁ = ri₂`; the list and `B` also link | TEL, shared chain reference |

Replacing the full leaf list with a Merkle inclusion proof does **not** remove the link: the batch root `B` is still common to all copies. This matches residual (a) acknowledged in keripy's example and the earlier trace-based result in [`tamarin/acdc_bulk_unlinkability.spthy`](../tamarin/acdc_bulk_unlinkability.spthy).

### B. Disclosed-field correlation (from P8)

| Config | Result | Distinguishing test | Cause |
|---|---|---|---|
| a holder-unique attribute is disclosed | **linkable** | `d₁ = d₂` | disclosed data |
| undisclosed attribute block salted per *credential*, not per copy | **linkable** | `ab₁ = ab₂` | disclosed data (blinded digest) |
| only a population-wide predicate (`over21`) is disclosed | unlinkable | none | none |

### C. Status/TEL correlation
In these configurations the holder fetches a fresh TEL status proof and carries it to the verifier. The fetch is visible to the attacker, either because the TEL host colludes or because N is watching.

| Config | Result | Distinguishing test | Cause |
|---|---|---|---|
| P8 minus M4, i.e. a per-holder registry | **linkable** | `ri₁ = ri₂` | TEL |
| P7, i.e. status fetched over an identifiable session | **linkable** | `q₁ = q₂` | status query |
| P8, i.e. private status retrieval | unlinkable | none | none |

### D. Network-metadata correlation

| Config | Result | Distinguishing test | Cause |
|---|---|---|---|
| P8, presentations carry the holder's transport address | **linkable** | `addr₁ = addr₂` | network metadata |
| P8 minus M7, with anonymous transport | **linkable** | `shape₁ = shape₂` | network metadata (size/timing) |
| P8 with anonymous transport | unlinkable | none | none |

### E. Malicious issuer

| Config | Result | Distinguishing test | Cause |
|---|---|---|---|
| everything on, but the issuer shares its issuance records with V1 and V2 | **linkable** | `name₁ = name₂` in `(issued-to, name, said)` | issuer observation |

**No mechanism in P1–P8 prevents this.** The issuer chooses or learns every SAID it signs, so it can always tie SAIDs back to the holder. Preventing it would require blind issuance or anonymous credentials (e.g., BBS+ or CL signatures), which ACDC does not provide.

### Everything on

| Config | Result |
|---|---|
| P8 + status + network, anonymous transport, honest issuer, no unique disclosed attributes | **unlinkable** |

## 4. Mechanism → attack prevented

| Mechanism | Link it removes (cause) | Link it does **not** remove on its own |
|---|---|---|
| M1 bulk issuance, unique SAIDs | SAID, uuid, blinded attribute digest | batch root `B` and leaf list; every AID, TEL and key link |
| M2 fresh, individually anchored copy | batch root `B`, leaf list (shared chain reference) | Issuee AID, TEL, holder AID, key |
| M3 unique Issuee AID per copy | Issuee AID | TEL, holder AID, key |
| M4 independent TEL per copy | registry id `ri` (TEL) | holder AID, key; status-fetch session |
| M5 no stable holder AID | holder (sender) AID | key reuse under fresh AIDs |
| M6 fresh proof key | presentation signing key (proof material) | none at the artifact level |
| M7 normalized size/timing | size/timing class (network metadata) | transport address |
| M8 private status retrieval | status-query session (status query) | none, given M4 |
| *anonymous transport (deployment assumption)* | transport address (network metadata) | none |
| *no holder-unique disclosed attributes (policy)* | disclosed data | none |
| **none of the above** | none | **issuer observation (experiment E)** |

## 5. Conclusions
These results are conditional. They do not say that "ACDC fails PRV-01".

1. **Baseline ACDC is linkable.** A single credential presented twice links through its SAID and every other stable identifier (P0).
2. **Bulk issuance alone is not enough.** M1 removes the SAID link, but a batch of copies still shares its root `B`, whether the holder discloses the full leaf list (what keripy does) or a Merkle inclusion proof. Removing that link needs individually anchored copies (M2).
3. **The keripy reference example is still linkable, and only through the gaps its authors already name.** The shared registry and the batch aggregate or list link presentations. The per-copy holder AIDs and SAIDs keripy introduces do not. This agrees with the residuals stated in `test_bulk_issuance.py`.
4. **Artifact-level unlinkability holds from P6 onward.** It needs per-copy SAIDs, individually anchored copies, per-copy Issuee AIDs, per-copy TEL registries, fresh holder AIDs and fresh proof keys, all at once. Dropping any one of them brings back a concrete link (section 3, ablations).
5. **Full PRV-01 still fails because of metadata and disclosed data:**
   - holder-unique disclosed attributes (B)
   - an attribute salt that isn't per copy (B)
   - an identifiable status-fetch session (C)
   - transport addresses or size/timing classes (D)
6. **Maximal unlinkability holds only under explicit deployment assumptions.** The FULL configuration is unlinkable only with *all* mechanisms M1–M8 **and** these three assumptions:
   - anonymous transport
   - only population-wide predicates disclosed
   - an issuer that does not collude with verifiers

   Against a colluding issuer (E), no ACDC configuration modeled here is unlinkable.

## 6. Scope and limitations
- **Soundness direction.** ProVerif checks diff-equivalence, which is *stronger* than observational equivalence, so every `true` result is sound. Every `false` result here comes with a concrete attack trace, which confirms that the distinguishing test is real in the model.
- **Bounded experiment.** Each run has two presentations and one copy each, the minimum needed for a linking attack. Mechanisms that hold here could still fail with more presentations if copies are reused. The model assumes single-use copies, which is keripy's wallet discipline of one copy per verifier.
- **Symbolic cryptography.** Hashes of salted values reveal nothing, and signatures don't reveal the signing key unless its public key is disclosed. Holder names and unique attributes are modeled as high-entropy. A *low-entropy* attribute under a disclosed salt would additionally be open to dictionary attacks, which isn't modeled.
- **Timing and ordering** are abstracted to an opaque per-holder "shape" tag (M7). Real timing side channels, and a holder's *choice* of copy order (e.g., always spending the lowest index first), are outside the symbolic model. The attacker schedules both presentations identically in both worlds.
- **KERI details that are not modeled:**
  - KEL sequence numbers and ixn positions. M2 assumes each copy is anchored in its **own** ixn event; one ixn with several seals would disclose the sibling SAIDs, exactly like the M1 batch.
  - Witness, mailbox and OOBI discovery metadata for per-copy AIDs. This is keripy's residual (b), and it falls under experiment D.
  - Delegation and edges/chaining. Keripy's index-aligned E1E edges point at per-copy far nodes, so they partition in the same way the SAIDs do.
- **M5 vs M6.** In keripy a fresh AID comes with fresh keys, so M5 and M6 are enabled together. Separating them models a misconfiguration: fresh AIDs that reuse a hardware or device key. The ablation shows that this reuse alone is enough to link presentations.
- **Why ProVerif rather than Tamarin.** A Tamarin `--diff` version of this model reported "falsified" even with **identical** worlds, i.e. no `diff` terms at all. That is a false counterexample from Tamarin's diff-equivalence engine, so the model was moved to ProVerif. CRY-01 and other stateful KERI properties stay in Tamarin. The earlier trace-based PRV-01 lemmas in [`tamarin/acdc_bulk_unlinkability.spthy`](../tamarin/acdc_bulk_unlinkability.spthy) agree with the batch-aggregate result above. Re-run with Tamarin 1.12.0, all six lemmas came out as that file's comments predict. In particular, `attack_membership_list_is_join_key` and `attack_aggregate_is_join_key_under_inclusion_proofs` are both verified, meaning the attack exists.
