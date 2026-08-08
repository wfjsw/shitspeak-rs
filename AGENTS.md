# AGENTS.md

## Limit struct field visibility

When defining a struct, only make the fields public if there are reasons strongly justified. If the fields are only used within the module, keep them private. In most cases, you should try to create getter / setter methods instead of making public fields. This helps to encapsulate the implementation details and prevents unintended usage of the struct's internals.

## Avoid Explicit Drops

Prefer block scope instead of `drop()`.

## Regression handling

When dealing a regression / correctness hole, whether it is a new problem or is found by reviewing the code, especially when it is discovered mid-implementation, first implement a regression test to ensure the issue is real and reproducible. Then, implement a fix and ensure that the regression test passes. This ensures that the issue is properly addressed and prevents future regressions.

## Strict replication incident handling

When fixing a strict replication problem, first pull the affected nodes' live state files through SSH. Reproduce the complete relevant node state in a local cluster, including each strict repository and terminal state; clients and network latency do not need to be emulated. Observe the reported symptom in that local cluster before implementing the fix. Do not consider the work finished until the same local-cluster reproduction demonstrates that the symptom is fully resolved.

## Batch the test

Consider making all changes first and then running the test suite at once, instead of running the test suite after each change. This can save time from repetitive compilation, especially when making multiple changes that are related or dependent on each other. The range/coverage of the test itself however should never be reduced.
