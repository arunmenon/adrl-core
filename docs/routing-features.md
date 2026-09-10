# Decision feature semantics

8 September 2026. Owners: LRN-004/005, RTG-002/003/006 and LRN-008.

`features-v2` changes lexical intent aggregation. The strongest matched signal uses
the existing class scores, rather than the first low-complexity match. Consequently,
an easy keyword cannot hide a later debugging, implementation or hard-action match.
Recognized fix/correct typo, misspelling, whitespace and indentation phrases are
normalized before aggregation, while the rest of the request remains visible.
Simple ordinal qualifiers such as "the second typo" remain mechanical. An "add"
inside a recognized small-edit phrase such as "add a flag" is not counted again
as a general implementation action; independent actions elsewhere still count.
Concurrency/concurrent now match the previously incomplete concurrency expression.

The latest user request supplies intent; earlier history still supplies the existing
context-size and trajectory features. Field names, routing thresholds, class scores,
costs, selection logic, gates and cascade rules are unchanged. Class scores remain
heuristic inputs, not calibrated success probabilities.

This is conservative lexical processing, not a semantic parser. Quotes, negation,
discussion of implementation and complex topic names can over-route. Unknown
synonyms and unrecognized actions can still be missed. Frozen before/after reports
must include these limitations, not interpret a frontier choice as model incapacity.

Decision records now carry `features-v2`. Historical v1 rows are not rewritten.
The offline learning contract remains pinned to `features-v1`: existing exact-version
dataset validation rejects v2 rows until a separate compatible learning contract
is qualified. Exploration startup rejects a mismatch between that contract and
current live feature semantics. Therefore configured v1 exploration must not be
enabled with this build; ordinary routing without an exploration artifact remains
available. No learned artifact, schema admission, training or graduation occurs here.

The optional classifier sees the existing coarse feature fields with the updated
verb class; no classifier endpoint was run for this correction. Live model quality,
classifier benefit and cost savings remain unmeasured.
