# AGENTS.md

## Serena

Always use Serena's symbolic tools (`find_symbol`, `get_symbols_overview`, `replace_symbol_body`, `find_referencing_symbols`, `search_for_pattern`, `replace_content`, etc.) for code exploration and editing. Prefer them over raw `read_file` / `grep_search` when working with Rust source files.

- Activate the project with `mcp_serena_activate_project` at the start of each session.
- Use `get_symbols_overview` to understand a file's structure before reading bodies.
- Use `find_symbol` with `include_body=True` to read specific symbol definitions.
- Use `replace_symbol_body` for whole-symbol replacements; use `replace_content` for partial edits.
- Use `find_referencing_symbols` to find all callers before renaming or changing signatures.
