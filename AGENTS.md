# AGENTS.md

## Memories

Apparently we can remember what we have just said, and plan our action based on that. However, it is important to note that the memory is not stable and can be lost at any time. Therefore, always use memory tools provided by Copilot and Serena to store important information that would come up handy later. 

Examples of such memory tools include: `list_memories`, `write_memory`, `read_memory`, `delete_memory`, `rename_memory`, `edit_memory` etc. 

When you write something that would rely on another part of the conversation, either check it immediately after writing, or store it in memory and check it later when you need it. This way, you can ensure that your programs are consistent and complete, and that it would not miss important details.

## Serena

Before doing anything, first ensure the current dir is activated as project using serena or serena-plan, depends on what you are trying to do. This will allow you to use all of Serena's tools for code exploration and editing, which are much more powerful and efficient than raw file reading and searching.

Always use Serena's symbolic tools (`find_symbol`, `get_symbols_overview`, `replace_symbol_body`, `find_referencing_symbols`, `search_for_pattern`, `replace_content`, etc.) for code exploration and editing. Prefer them over raw `read_file` / `grep_search` when working with Rust source files.

- Activate the project with `mcp_serena_activate_project` at the start of each session.
- Use `get_symbols_overview` to understand a file's structure before reading bodies.
- Use `find_symbol` with `include_body=True` to read specific symbol definitions.
- Use `replace_symbol_body` for whole-symbol replacements; use `replace_content` for partial edits.
- Use `find_referencing_symbols` to find all callers before renaming or changing signatures.

## Limit struct field visibility

When defining a struct, only make the fields public if there are reasons strongly justified. If the fields are only used within the module, keep them private. In most cases, you should try to create getter / setter methods instead of making public fields. This helps to encapsulate the implementation details and prevents unintended usage of the struct's internals.
