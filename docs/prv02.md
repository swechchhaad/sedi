# SEDI-PRV-02: predicate-only disclosure (ProVerif)

**Tool:** ProVerif 2.05. Observational (diff-)equivalence, plus event and secrecy queries.
**Model generator and runner:** [`scripts/prv02_proverif.py`](../scripts/prv02_proverif.py)
**Generated models:** [`proverif/prv02/`](../proverif/prv02/), three per configuration (`__eq`, `__trace`, `__link`)
**Raw output, with traces:** `results/prv02/`

```
python3 scripts/prv02_proverif.py          # 7 configurations x 3 models (~2 s)
```

**Result:** all 35 results match the expected outcome. Every equivalence failure has a reconstructed trace, and each negative variant fails for its intended reason.

> **Scope warning.** Size, timing and error behavior are modeled as **abstract symbolic metadata fields**. A result about those fields does **not** establish that a real implementation is constant-time or constant-size, or that its errors are uniform. Those properties need implementation-level tests (§6).

## 1. What PRV-02 requires
1. The verifier learns only the Boolean predicate result.
2. Timing, response size and error behavior do not reveal the attribute.
3. The holder controls which predicate is evaluated.
4. Repeated predicates reveal no more than the union of the predicates explicitly evaluated.

## 2. Mechanism modeled
This follows keripy's SEDI age example (`tests/acdc/test_bulk_issuance.py`, the `sedi-age` aggregate). **ACDC has no zero-knowledge range proofs.** Instead:
- The issuer **precomputes one boolean flag per predicate** in a bounded domain.
- It signs an aggregate of **salted flag digests** `h(p, b_p, salt_p)`, plus a salted digest of the date of birth.
- To answer predicate `p`, the holder reveals `b_p` and its salt. Every other flag, and the date of birth, stays behind its salted digest.
- Each response uses a fresh bulk-issued copy, so fresh salts and a fresh aggregate, unless the `STABLE` negative variant says otherwise.

It follows that the holder can only choose *which precomputed flag to reveal*. A predicate the issuer didn't precompute can't be answered at all.

**Predicate domain:** age ≥ 18, ≥ 21, ≥ 25, ≥ 30.

**Two attribute worlds:**

| | ≥18 | ≥21 | ≥25 | ≥30 | date of birth |
|---|---|---|---|---|---|
| x0 (age 22) | T | T | **F** | F | `dob0` |
| x1 (age 27) | T | T | **T** | F | `dob1` |

The holder **approves** ≥18, ≥21 and ≥30, the predicates on which x0 and x1 agree. It declines ≥25. The question is whether the verifier can tell x0 from x1.

**Symbolic metadata:** each response carries `(size class, timing class)`, and each refusal carries an error code. The positive configuration uses constants: `std` for size and timing, `declined` for the error code. Each negative variant replaces one of them with a function of the hidden answer to ≥25 (`sizeclass(b25)`, `timeclass(b25)`, `errcode(b25)`). The events the spec asks for are emitted in the trace model:
- `PredicateRequested(V,H,p)`
- `HolderApprovedPredicate(H,p)`
- `PredicateResponse(V,p,b,meta)`
- `ErrorResponse(V,error,meta)`
- `TimingClass(V,p,meta)`
- `ResponseSize(V,p,meta)`

## 3. Lemmas → checks

| Lemma | Check |
|---|---|
| 1. Boolean-only disclosure | **x0 ≡ x1** (equivalence), and the date of birth is secret (`not attacker(dob0)`) |
| 2. Metadata independence | x0 ≡ x1, with the metadata fields present in every response |
| 3. Holder authorization | `PredicateResponse(v,p,b,m) ==> HolderApprovedPredicate(hH,p)` |
| 4. Repeated-query privacy | x0 ≡ x1 with **unbounded repeated** requests (every responder is replicated) |
| 5. No error-message leakage | x0 ≡ x1, with refusals present |
| 6. No stable predicate-proof identifier | **link** equivalence: population {H1, H2}, both age 22. World 0: H1 answers V1 and V2. World 1: H1 answers V1, H2 answers V2. |

## 4. Results

| Config | x0 ≡ x1 (L1, L2, L4, L5) | L1 DOB secret | L3 holder authorization | L6 no stable id |
|---|---|---|---|---|
| **POS_baseline** | **holds** | holds | holds | **holds** |
| NEG_size_depends_on_x | **FAILS** | holds | holds | holds |
| NEG_timing_depends_on_x | **FAILS** | holds | holds | holds |
| NEG_error_depends_on_x | **FAILS** | holds | holds | holds |
| NEG_arbitrary_predicates | **FAILS** | holds | holds | holds |
| NEG_no_holder_authorization | **FAILS** | holds | **FAILS** | holds |
| NEG_stable_proof_id | holds | holds | holds | **FAILS** |

The sanity check (a response is produced) holds in every configuration.

### Counterexample traces (distinguishing test found by ProVerif)
| Negative variant | Distinguishing test | Meaning |
|---|---|---|
| response size depends on x | `sizeclass(F) = sizeclass(choice[F,T])` | the size class of an *approved* answer encodes the hidden ≥25 answer |
| timing depends on x | `timeclass(F) = timeclass(choice[F,T])` | same, through the timing class |
| error behavior depends on x | `errcode(choice[F,T]) = errcode(T)` | refusing ≥25 as "not satisfied" versus "declined" reveals the answer |
| verifier can issue arbitrary predicates | `choice[F,T] = T` | the holder answers ≥25, the one predicate where x0 and x1 differ |
| holder does not authorize | `choice[F,T] = T`, and a trace of `PredicateResponse` with no `HolderApprovedPredicate` | the wallet answers ≥25 without approval |
| stable predicate-proof identifier | `s21A = choice[s21A, s21B]` | the reused copy's revealed salt (and its aggregate) link the two responses |

## 5. Conclusions
- **ACDC's salted boolean flags give Boolean-only disclosure, under conditions.** In the positive configuration the verifier cannot distinguish two holders whose answers agree on every approved predicate. This holds even under unbounded repeated requests, so repeated queries reveal no more than the union of the approved predicates. The date of birth stays secret. The conditions:
  1. **Holder-side approval** of every predicate, with a fixed approval set. An auto-answering wallet, or one that approves whatever is asked, leaks.
  2. **Uniform refusals.** The error for a declined predicate must not depend on its answer.
  3. **Metadata independent of the hidden attribute.** Response size, timing and errors must not depend on any flag's value, including flags that are *not* disclosed.
  4. **A fresh bulk copy per presentation.** A reused copy is a stable proof identifier: its revealed salt and aggregate repeat.
- **Monotone predicates reveal their implications.** Answering ≥21 = T also tells the verifier ≥18 = T. That is inherent in the predicate itself, not a leak, and it is within "the union of the evaluated predicates" only if the union is read as closed under implication. Flag this when choosing an approval set.
- **Only precomputed predicates exist.** The holder "controls which predicate is evaluated" only among the flags the issuer chose to include. Arbitrary thresholds would need zero-knowledge range proofs, which ACDC does not provide.

## 6. Limitations, and the implementation tests they call for
**This symbolic result does not establish constant-time or constant-size behavior of a real implementation.** The model shows only that *if* size, timing and error codes are independent of the hidden attribute, the verifier learns nothing beyond the approved Booleans, and *if* any one depends on it, the verifier can distinguish. Recommended implementation-level tests for the wallet and the verifier interface:
- **Constant size.** Serialize responses for every approved predicate across a range of hidden ages (e.g. 17–40) and assert identical byte lengths, CESR and JSON alike. Note that ACDC salts and digests are fixed-length, but field ordering, optional fields and numeric encodings are not automatically so.
- **Constant time.** Measure response latency per predicate and age class (e.g. with dudect-style statistical tests), including the refusal path. Look for early exits on false flags and for lazy loading of different credential copies.
- **Uniform errors.** Enumerate every refusal and failure path: declined, unsupported predicate, expired copy, no copies left. Assert that the error code, message text and size don't depend on any flag value.
- **Copy freshness.** Assert that no copy (SAID, aggregate, salt) is ever reused across verifiers, including after wallet restore or when bulk copies run out.

**Other modeling limits:**
- A single issuer key; symbolic cryptography.
- Salts are high-entropy. A low-entropy value under a *public* salt could be dictionary-attacked, which isn't modeled.
- The attribute domain is bounded to four precomputed predicates.
- Diff-equivalence is stronger than observational equivalence, so every `holds` is sound. Every `FAILS` above comes with a concrete trace.
