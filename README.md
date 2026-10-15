# Cell identity verification

This service identifies capability-cell manifests, verifies caller-provided face bindings, and derives actor protocol faces from retained co-reference witness histories. A binding proves the returned cell/controller correspondence in this service's profile; it does not independently grant authority.

## Content identity ownership

The existing ContentAddress service's `semiotic-content-address` export owns carrier normalization, canonical CBOR and SHA-256 NI composition. This consumer uses `semanticAddress` once per addressed result and `decodeSemantic` for decoded manifest/cell values. It contains no separate canonicalizer, CBOR implementation, hashing implementation or legacy runtime import.

These operations address generic data carriers. Their bytes are not automatically a normalized SEN v3 term envelope or a SignCell. Historical output metadata remains `application/rmn+cbor`; this migration does not relabel it, rewrite stored bytes or assert correspondence for previously lossy inputs.

## Historical carrier admission

The runtime accepts finite acyclic ordinary data trees or shared DAGs containing:

- null, booleans and safe-integer Numbers, including negative zero (addressed as zero)
- BigInts from -18446744073709551616 through 18446744073709551615
- well-formed Unicode strings without a leading U+FEFF
- ordinary Uint8Array or Node Buffer byte strings
- dense ordinary arrays and ordinary records with own enumerable string data properties

It refuses undefined members, fractional/unsafe/nonfinite Numbers, out-of-range BigInts, malformed Unicode, own `__proto__` keys, NFC key collisions, symbols, accessors, hidden members, holes/extra array or byte properties, proxies, custom prototypes, cycles and shared-memory bytes. It validates without creating a second normalized representation. ContentAddress alone normalizes carrier strings and keys. The bounds preserve exact historical bytes and NI identities for admitted values; they do not assign a new identity to information an older provider discarded.

This Node-specific boundary uses `util.types.isProxy` before reflecting on data containers. Builtin prototypes are assumed untampered. TypeScript's `HistoricalIdentityValue` describes the carrier shape; runtime admission additionally enforces the numeric, Unicode and container restrictions above.

`normalizeCellManifest` preserves CapabilityCellManifest version 2, the existing required NI/controller checks and sorted face projection. Absent/null/undefined `faces` still means an empty record. Face claims are records of admitted carrier data. Ignored source extensions must also be admitted data. Cell identity excludes faces; manifest identity includes them.

Co-reference normalization retains ActorCoReferenceWitness version 1, trimming, protocol lowercase, timestamp conversion, evidence and standing checks. Undefined `statementRef` and `continuity` retain their existing omission behavior. Continuity keys that collide after trimming/NFC refuse rather than erase an authored member. Derivation retains chronology, equal-time conflict, revocation and the full witness identity history. This change does not redefine actor models, timestamp grammar or existing protocol/external-identifier grouping.

## Observer effect and data boundary

`verifyCellIdentity` validates request/manifest structure before reading it or invoking observers and resolves only own observer slots. Observer callbacks are explicitly executable caller-owned capabilities: invocation and async/thenable resolution retain the original semantics, including legitimate thenables and native Promise subclasses. Nonexecution guarantees apply to admission and settled-data inspection, not to effects the callback or its resolution performs.

Missing observers yield `observer-unavailable`. Callback/settlement failures and malformed outer settled result records yield `observer-refused`. A returned mismatching cell/controller yields `identity-mismatch`. Required invalid bindings refuse the profile; optional invalid bindings do not by themselves refuse it.

The outer settled result must be an ordinary own-data record. Its inert `evidence` property is then recursively checked outside the callback-refusal catch: unsupported evidence refuses the enclosing verification, for required/optional and matching/mismatching results alike. Missing/undefined evidence remains omitted on invalid faces and null on bound faces. Refusal descriptions use inert error data without invoking error getters or object string conversion.

## Runtime and supplier support

The service retains its declared Node >=22 requirement. Passing loaded-path tests on Node22 does not establish an installable dependency closure or override supplier engine declarations. Receiving must check the actual canonical suppliers' declared runtime support in the selected environment. This source consolidation does not change a host runtime, engine floor or package-manager policy.

The required canonical CBOR provider must preserve integer-versus-float wire representation when decoding, including the -2^53 boundary, without changing encoded bytes. ContentAddress must retain the existing canonical normalization and NI behavior on the historical carrier domain above. Receiving must supply these behaviors through the existing dependency process; this service contains no fallback codec.

## Qualification

`npm run verify` checks syntax, runs the original service scenarios plus historical-profile acceptance, and previews the package. Original co-reference fixtures are retained unchanged. New fixed byte/NI oracles were generated from the unchanged original service and its original carrier provider, using synthetic inputs. The fixtures contain historical outputs, not copied provider source. Production has no dependency on those historical providers.

The equivalence claim covers admitted semantic outputs. Arbitrary decoded CBOR is broader and is not asserted to be a SEN envelope or to re-encode byte-identically after semantic NFC normalization. Original finite-float/undefined/prototype/Unicode behavior outside the admitted historical profile is not silently preserved or relabeled.
