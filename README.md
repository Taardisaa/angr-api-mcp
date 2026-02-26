# angr-api-mcp

MCP server for [angr](https://github.com/angr/angr) binary analysis API workflow retrieval.

Extracts real API usage patterns from angr's source code and angr-doc examples, then indexes them with semantic search so LLMs can query correct API call sequences.

## Installation

### Via Claude Code (recommended)

```bash
claude mcp add angr-api-mcp -- uvx angr-api-mcp
```

### Via Claude Desktop

```json
{
  "mcpServers": {
    "angr": {
      "command": "uvx",
      "args": ["angr-api-mcp"]
    }
  }
}
```

### Via pip

```bash
pip install angr-api-mcp
```

## First-time setup

After adding the server, build the index by calling the `initialize_index` tool from Claude:

```
initialize_index()
```

This clones angr and angr-doc from GitHub and builds the semantic index
(~5–10 minutes). The index is stored at `~/.local/share/angr-api-mcp/chroma_db`
and persists across restarts.

Or run from the command line:

```bash
angr-api-mcp-admin build-index

# Point at local repos to skip cloning
angr-api-mcp-admin build-index --angr-path /path/to/angr --angr-doc-path /path/to/angr-doc
```

## MCP Tools

| Tool | Description |
|---|---|
| `initialize_index` | Build the workflow index |
| `get_workflows` | Search API call sequences by task description |
| `get_api_doc` | Look up a class or method |
| `list_related_apis` | Find co-occurring APIs |
| `get_index_info` | Show index metadata |
| `clear_index` | Wipe the index |

## CLI (admin / inspection)

```bash
# Search for workflows by task
angr-api-mcp-admin inspect workflows "run CFG analysis on a binary"
angr-api-mcp-admin inspect workflows "symbolic execution to find target address"

# Look up a class or method
angr-api-mcp-admin inspect api-doc SimulationManager
angr-api-mcp-admin inspect api-doc CFGFast

# Find co-occurring APIs
angr-api-mcp-admin inspect related Project

# Index info
angr-api-mcp-admin inspect info
```
