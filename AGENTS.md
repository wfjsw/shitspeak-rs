# AGENTS.md

## Limit struct field visibility

When defining a struct, only make the fields public if there are reasons strongly justified. If the fields are only used within the module, keep them private. In most cases, you should try to create getter / setter methods instead of making public fields. This helps to encapsulate the implementation details and prevents unintended usage of the struct's internals.
