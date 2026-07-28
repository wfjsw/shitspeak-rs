# AGENTS.md

## Limit struct field visibility

When defining a struct, only make the fields public if there are reasons strongly justified. If the fields are only used within the module, keep them private. In most cases, you should try to create getter / setter methods instead of making public fields. This helps to encapsulate the implementation details and prevents unintended usage of the struct's internals.

## Avoid Explicit Drops

Prefer block scope instead of `drop()`.

## Regression handling

When dealing a regression / correctness hole, whether it is a new problem or is found by reviewing the code, especially when it is discovered mid-implementation, first implement a regression test to ensure the issue is real and reproducible. Then, implement a fix and ensure that the regression test passes. This ensures that the issue is properly addressed and prevents future regressions.
