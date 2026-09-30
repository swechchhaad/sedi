# SEDI-PRV-03: architectural anti-surveillance (Department non-interference)

**Tool:** ProVerif 2.05. Observational (diff-)equivalence for non-interference and correlation; event queries for the trace lemmas.
**Model generator and runner:** [`scripts/prv03_proverif.py`](../scripts/prv03_proverif.py)
**Generated models:** [`proverif/prv03/`](../proverif/prv03/), three per configuration (`__ni`, `__trace`, `__corr`)
**Raw output, with traces:** `results/prv03/`

```
python3 scripts/prv03_proverif.py          # 12 configurations x 3 models (~3 s)
```

**Result:** all 84 results (12 configurations × 7 properties) match the expected outcome. None are inconclusive. Every equivalence failure comes with a reconstructed ProVerif trace.

## 1. The Department as a limited observer
The Department **D** is the ProVerif attacker, but it is **not omniscient**. It sees exactly one channel, `c`, which carries only traffic that reaches a Department-operated endpoint:
- the callback API;
- the TEL/status service;
- D-hosted witnesses (KEL lookups);
- any log or audit upload.

Holder ↔ verifier traffic (`hv`) and the verifier's local state (`vlocal`) are private channels D cannot read.

D is also the **issuer**. It knows its own signing key and the issuance records `(issued, holder-id, holder-endpoint, SAID)` for every credential it issued.

Nothing relies on D's promises. **Anything that reaches `c` is in D's view, and D can keep it.** That is the "structural, not policy" reading of PRV-03.

### The Department view
Every message on `c` is a record `(kind, endpoint id, content, timing class)`:

| View element | In the model |
|---|---|
| messages visible to D | everything output on `c` |
| status queries visible to D | `telquery` (credential-specific), `fetchall` (whole registry), `refresh` (a cached-status refresh) |
| KEL/TEL lookups visible to D | `kellookup` (issuer KEL from D-hosted witnesses), `telquery` |
| endpoint identifiers | `vid` / `vid1` / `vid2` (verifier), `hep` (holder endpoint), `anon` (anonymous transport) |
| timing classes | `t_pres` (at presentation), `t_sched` (scheduled), `t_slot` (fixed cover-traffic slot) |
| logs | `auditlog` (a presentation log uploaded to D). The verifier's own log is on private `vlocal`. |
| credential-specific identifiers | the SAID and the TEL registry id `ri` |

## 2. Properties

**Non-interference (the central property):**
- **World 0:** the holder presents the credential to a verifier.
- **World 1:** the holder does not present.

The private holder → verifier exchange runs in both worlds, because D cannot see it. Every D-visible message the presentation *causes* goes to D in world 0 and to a private dead-end channel in world 1. Background traffic (scheduled refreshes, cover traffic) reaches D in both worlds. The property holds exactly when D's view is equivalent in both worlds, i.e. D cannot tell whether a presentation happened.

**Trace lemmas** (on world 0). Each D-visible message is tagged by its **cause** (`pres` or `sched`) and **category** (`auth`, `status` or `log`):

| Lemma | Statement | Query |
|---|---|---|
| L1 | no Department callback during authenticity verification | no `DObs(pres, auth, ...)` |
| L2 | no D-visible status query caused by a presentation | no `DObs(pres, status, ...)` |
| L3 | no D-accessible presentation log | no presentation-caused message reaches D at all, so D has nothing to log |
| L4 | no stable credential identifier exposed to D | no `DCredId(pres, ...)` |
| L5 | no correlation of two presentations through D's view | equivalence (below) |
| L6 | the verifier can accept offline, without a D query | `Accept(s) ==> DQueried(s)` is **false** |

**L5 (correlation).** The population is fixed at two holders, with identical issuance records and background traffic in both worlds. Holder H1 holds two **bulk copies**.
- **World 0:** H1 presents to V1 and to V2, using a different copy each time.
- **World 1:** H1 presents to V1, and H2 presents to V2.

## 3. Deployment variants
| Config | Variant | Deployment |
|---|---|---|
| `A_callback` | A | the verifier asks D whether the credential is valid |
| `B_online_tel` | B | the verifier fetches the credential's TEL/status from the issuer-controlled registry; the issuer KEL is cached |
| `C_cached_snapshot` | C | offline verifier; a whole-registry status snapshot is refreshed **on a schedule**; the issuer KEL is cached |
| `C_cached_snapshot_kel_online` | C | as above, but the issuer KEL is fetched from D-hosted witnesses at presentation |
| `C_refresh_on_miss` | C | offline cache, but an uncached credential triggers a status fetch |
| `C_refresh_seen_credentials` | C | offline cache; the scheduled refresh asks for the credentials the verifier has **seen** |
| `C_cached_snapshot_audit_upload` | C | as `C_cached_snapshot`, plus an uploaded presentation log |
| `D_holder_status_scheduled` | D | holder-carried status; the holder refreshes its status proof **on a schedule** |
| `D_holder_status_on_demand` | D | holder-carried status; the holder fetches a fresh proof **just before presenting** |
| `E_anon_credential_query` | E | anonymous status query (no verifier id) that still names the credential |
| `E_anon_wholelist_on_demand` | E | anonymous whole-list / PIR retrieval, performed when a presentation arrives |
| `E_anon_wholelist_cover_traffic` | E | anonymous whole-list retrieval **in every time slot**, whether or not anyone presents |

## 4. Results

| Config | L1 no callback | L2 no status query | L3 no D log | L4 no cred id | L5 no correlation | L6 offline accept | **Non-interference** |
|---|---|---|---|---|---|---|---|
| A_callback | **FAILS** | holds | **FAILS** | **FAILS** | **FAILS** | **FAILS** | **FAILS** |
| B_online_tel | holds | **FAILS** | **FAILS** | **FAILS** | **FAILS** | **FAILS** | **FAILS** |
| C_cached_snapshot | holds | holds | holds | holds | holds | holds | **holds** |
| C_cached_snapshot_kel_online | **FAILS** | holds | **FAILS** | holds | holds | **FAILS** | **FAILS** |
| C_refresh_on_miss | holds | **FAILS** | **FAILS** | **FAILS** | **FAILS** | **FAILS** | **FAILS** |
| C_refresh_seen_credentials | holds | **FAILS** | **FAILS** | **FAILS** | **FAILS** | holds | **FAILS** |
| C_cached_snapshot_audit_upload | holds | holds | **FAILS** | **FAILS** | **FAILS** | holds | **FAILS** |
| D_holder_status_scheduled | holds | holds | holds | holds | holds | holds | **holds** |
| D_holder_status_on_demand | holds | **FAILS** | **FAILS** | **FAILS** | **FAILS** | holds | **FAILS** |
| E_anon_credential_query | holds | **FAILS** | **FAILS** | **FAILS** | **FAILS** | **FAILS** | **FAILS** |
| E_anon_wholelist_on_demand | holds | **FAILS** | **FAILS** | holds | holds | **FAILS** | **FAILS** |
| E_anon_wholelist_cover_traffic | holds | holds | holds | holds | holds | holds | **holds** |

### Counterexamples
- **A, B, C (KEL online / refresh on miss / audit upload), D on demand, E on demand.** The non-interference trace is the same shape every time: *D receives a presentation-caused message in world 0 that does not exist in world 1.* The message is the callback, the TEL query, the KEL lookup, the log upload, or the holder's fetch, respectively.
- **C with refresh of seen credentials.** The scheduled refresh happens in both worlds, but its *content* differs. D tests whether the refresh contains `h(pk(skD), schema, hid, u)` (the SAID it issued) or `none`. Moving the query to a schedule is not enough if what is queried depends on presentations.
- **Correlation (L5).** For every configuration that sends a credential identifier, D tests whether the SAID in the second query is **H2's** credential. **Bulk issuance does not help against D.** D issued H1's second copy too, so it can map every copy back to its holder. For holder-fetched status, D instead tests whether the second fetch comes from holder endpoint `hep1`.

## 5. Per-variant conclusions
- **Variant A (online callback): direct counterexample.** It violates every PRV-03 clause except L2. The callback is an authenticity check rather than a status query, so it falls under L1.
- **Variant B (online TEL/status retrieval): status-observation counterexample.** D learns *that* a presentation happened, *which* credential, and *which* verifier, so it can link presentations.
- **Where keripy sits.** keripy's verifier ([`src/keri/vdr/verifying.py:126-143`](../src/keripy/src/keri/vdr/verifying.py#L126-L143)) caches TEL state. It queues a `telquery` carrying the registry id and the credential SAID (`dict(ri=regk, i=vcid)`) in three cases:
  - the registry is unknown;
  - the credential's state is unknown;
  - the cached state is older than `CredentialExpiry`.

  All three are triggered by processing a presented credential, which is the `C_refresh_on_miss` pattern (and B when nothing is cached). **As implemented, keripy's verifier fails PRV-03** (L2, L3, L4, L5, non-interference) whenever that query reaches a Department-operated registry or witness. Configured the way `C_cached_snapshot` or `D_holder_status_scheduled` describe, it would not fail.
- **Variant C (offline verifier, cached status): holds only under explicit conditions.** All of the following are required:
  1. the status cache is a **whole-registry snapshot**, not per-credential entries;
  2. it is **refreshed on a schedule**, independently of presentations;
  3. the issuer KEL is **cached or pinned**, not fetched from D-hosted witnesses at presentation;
  4. **no presentation log** is uploaded to D.

  Breaking any one condition gives a concrete counterexample. Refresh-on-miss and refresh-of-seen-credentials fail even though the verifier "works offline" most of the time.
- **Variant D (holder-carried status): holds only with scheduled refresh.** If the holder fetches a fresh status proof right before presenting, D sees the fetch. The verifier stays offline (L6 holds), but D learns that the holder is about to present, and which credential. Verifier-side offline operation is not enough; the holder's traffic counts too.
- **Variant E (anonymous / privacy-preserving status):** what D still learns depends on *when* and *what* is fetched:
  - **An anonymous query that names the credential:** D doesn't learn which verifier asked, but it does learn *that* credential X was just checked. That's enough to observe activity and link presentations (L2, L4, L5 fail).
  - **Anonymous whole-list or PIR retrieval triggered by a presentation:** no credential identifier and no correlation (L4 and L5 hold). **D still learns that some presentation happened, and when**, from the existence and timing class of the fetch, so non-interference fails.
  - **Anonymous whole-list retrieval in every slot (cover traffic):** D's view is independent of presentations, so non-interference holds.

### What PRV-03 structurally requires (in this model)
Non-interference holds **only** for `C_cached_snapshot`, `D_holder_status_scheduled` and `E_anon_wholelist_cover_traffic`. What they have in common is that **nothing D can observe is caused by, or depends on, a presentation**:
- status material is obtained on a presentation-independent schedule, and is not credential-specific on the verifier side;
- issuer key state is cached or carried;
- there are no callbacks and no uploaded logs.

A verifier that is offline "most of the time" is not enough, and neither is anonymity of the query source.

## 6. Assumptions and limitations
- **Freshness is an explicit assumption.** ProVerif has no clock. Variants C and D hold *given* that status is refreshed on a fixed schedule that does not depend on presentations. The trade-off (how stale the verifier's status may be, how soon a revocation takes effect) is a policy parameter the model does not evaluate. A schedule that adapts to presentations (e.g. refresh sooner after a presentation) would re-introduce the leak shown by `C_refresh_on_miss`.
- **Timing is a class, not time.** `t_pres`, `t_sched` and `t_slot` are symbolic tags. A scheduled fetch that in practice clusters right after presentations, or traffic-volume and packet-size side channels, are outside the model unless added as explicit tags.
- **Which messages are presentation-caused is a modeling input.** Each configuration states which D-visible messages a presentation causes and which are background. ProVerif then checks whether D can tell the difference: through the existence of a message, its content (`C_refresh_seen_credentials`), or its linkage to issuance records (L5). The classification follows the deployment description in §3.
- **D alone.** D does not collude with verifiers and does not observe the holder ↔ verifier network path. Collusion with verifiers is PRV-01's colluding-issuer case (experiment E), where every ACDC configuration is linkable. A network-level observer is PRV-01 experiment D.
- **Holder-endpoint traffic.** In variant D, the scheduled status refresh reveals to D that a holder is active, which D already knows from issuance. It does not reveal presentations.
- **Symbolic cryptography.** Perfect hashes and signatures; PIR and anonymous transport are modeled as "the message carries no identifier / no endpoint", not as concrete protocols.
- **Diff-equivalence** is stronger than observational equivalence, so every `holds` is sound. Every non-interference and correlation failure above has a reconstructed trace, so none are approximation artifacts.
