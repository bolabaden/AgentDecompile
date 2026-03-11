> Snapshot note: this file is a captured MCP tools response example. It is not the authoritative source of truth for the current tool set.
>
> Live local validation note: the current default `agentdecompile-server` advertisement is 37 tools. Hidden compatibility tools such as `manage-comments` still remain callable, and `switch-project` is still accepted as an alias to `open-project` even though it is not advertised.

{
  "id": 4,
  "jsonrpc": "2.0",
  "result": {
    "tools": [
      {
        "description": "Analyze data flow at an address (backward slice, forward slice, variable accesses)",
        "inputSchema": {
          "properties": {
            "direction": {
              "default": "backward",
              "enum": [
                "backward",
                "forward",
                "variable_accesses"
              ],
              "type": "string"
            },
            "function_address": {
              "type": "string"
            },
            "program_path": {
              "type": "string"
            },
            "start_address": {
              "type": "string"
            },
            "variable_name": {
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "analyze-data-flow"
      },
      {
        "description": "Run auto-analysis on the program",
        "inputSchema": {
          "properties": {
            "program_path": {
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "analyze-program"
      },
      {
        "description": "Analyze virtual function tables at an address",
        "inputSchema": {
          "properties": {
            "action": {
              "default": "analyze",
              "enum": [
                "analyze",
                "callers",
                "containing"
              ],
              "type": "string"
            },
            "function_address": {
              "type": "string"
            },
            "limit": {
              "default": 100,
              "type": "integer"
            },
            "max_entries": {
              "default": 200,
              "type": "integer"
            },
            "mode": {
              "default": "analyze",
              "enum": [
                "analyze",
                "callers",
                "containing"
              ],
              "type": "string"
            },
            "operation": {
              "default": "analyze",
              "enum": [
                "analyze",
                "callers",
                "containing"
              ],
              "type": "string"
            },
            "program_path": {
              "type": "string"
            },
            "vtable_address": {
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "analyze-vtables"
      },
      {
        "description": "Apply a data type at an address",
        "inputSchema": {
          "properties": {
            "address_or_symbol": {
              "type": "string"
            },
            "archive_name": {
              "type": "string"
            },
            "data_type_string": {
              "type": "string"
            },
            "program_path": {
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "apply-data-type"
      },
      {
        "description": "capture-agentdecompile-debug-info",
        "inputSchema": {
          "properties": {
            "message": {
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "capture-agentdecompile-debug-info"
      },
      {
        "description": "Change the processor/language for the program",
        "inputSchema": {
          "properties": {
            "compiler_spec_id": {
              "type": "string"
            },
            "language_id": {
              "type": "string"
            },
            "program_path": {
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "change-processor"
      },
      {
        "description": "Check in/snapshot program changes",
        "inputSchema": {
          "properties": {
            "keep_checked_out": {
              "default": false,
              "type": "boolean"
            },
            "message": {
              "type": "string"
            },
            "program_path": {
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "checkin-program"
      },
      {
        "description": "Decompile a function to C pseudocode",
        "inputSchema": {
          "properties": {
            "binary_name": {
              "type": "string"
            },
            "name": {
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "decompile-function"
      },
      {
        "description": "Synchronize active shared repository content with the local Ghidra project",
        "inputSchema": {
          "properties": {
            "action": {
              "default": "pull",
              "enum": [
                "pull",
                "push",
                "bidirectional"
              ],
              "type": "string"
            },
            "destination_folder": {
              "type": "string"
            },
            "destination_path": {
              "type": "string"
            },
            "dry_run": {
              "default": false,
              "type": "boolean"
            },
            "force": {
              "default": false,
              "type": "boolean"
            },
            "max_results": {
              "default": 100000,
              "type": "integer"
            },
            "mode": {
              "default": "pull",
              "enum": [
                "pull",
                "push",
                "bidirectional"
              ],
              "type": "string"
            },
            "new_path": {
              "default": "/",
              "type": "string"
            },
            "operation": {
              "default": "pull",
              "enum": [
                "pull",
                "push",
                "bidirectional"
              ],
              "type": "string"
            },
            "path": {
              "default": "/",
              "type": "string"
            },
            "recursive": {
              "default": true,
              "type": "boolean"
            },
            "source_path": {
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "sync-shared-project"
      },
      {
        "description": "Export program data",
        "inputSchema": {
          "properties": {
            "create_header": {
              "default": true,
              "type": "boolean"
            },
            "format": {
              "default": "cpp",
              "enum": [
                "c",
                "cpp",
                "cxx",
                "gzf",
                "sarif",
                "xml",
                "html",
                "ascii"
              ],
              "type": "string"
            },
            "include_comments": {
              "default": false,
              "type": "boolean"
            },
            "include_globals": {
              "default": true,
              "type": "boolean"
            },
            "include_types": {
              "default": true,
              "type": "boolean"
            },
            "output_path": {
              "type": "string"
            },
            "program_path": {
              "type": "string"
            },
            "tags": {
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "export"
      },
      {
        "description": "Delete a binary from the project",
        "inputSchema": {
          "properties": {
            "binary_name": {
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "delete-project-binary"
      },
      {
        "description": "Generate a call graph for a function",
        "inputSchema": {
          "properties": {
            "action": {
              "enum": [
                "graph",
                "tree",
                "callers",
                "callees",
                "callers_decomp",
                "common_callers"
              ],
              "type": "string"
            },
            "direction": {
              "default": "calling",
              "enum": [
                "calling",
                "called"
              ],
              "type": "string"
            },
            "function_addresses": {
              "items": {
                "type": "string"
              },
              "type": "array"
            },
            "function_identifier": {
              "description": "Function identifier (alt)",
              "type": "string"
            },
            "include_call_context": {
              "type": "boolean"
            },
            "max_callers": {
              "type": "integer"
            },
            "max_depth": {
              "type": "integer"
            },
            "mode": {
              "enum": [
                "graph",
                "tree",
                "callers",
                "callees",
                "callers_decomp",
                "common_callers"
              ],
              "type": "string"
            },
            "operation": {
              "enum": [
                "graph",
                "tree",
                "callers",
                "callees",
                "callers_decomp",
                "common_callers"
              ],
              "type": "string"
            },
            "program_path": {
              "description": "Path to the program/binary",
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "get-call-graph"
      },
      {
        "description": "Get info about the currently loaded program",
        "inputSchema": {
          "properties": {
            "program_path": {
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "get-current-program"
      },
      {
        "description": "Get data at an address",
        "inputSchema": {
          "properties": {
            "address_or_symbol": {
              "description": "Address or symbol",
              "type": "string"
            },
            "program_path": {
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "get-data"
      },
      {
        "description": "Get detailed function info (decompile, disassemble, info, calls)",
        "inputSchema": {
          "properties": {
            "identifier": {
              "type": "string"
            },
            "include_callees": {
              "type": "boolean"
            },
            "include_callers": {
              "type": "boolean"
            },
            "include_comments": {
              "type": "boolean"
            },
            "include_incoming_references": {
              "type": "boolean"
            },
            "include_reference_context": {
              "type": "boolean"
            },
            "limit": {
              "default": 100,
              "type": "integer"
            },
            "offset": {
              "default": 0,
              "type": "integer"
            },
            "program_path": {
              "type": "string"
            },
            "view": {
              "default": "info",
              "enum": [
                "decompile",
                "disassemble",
                "info",
                "calls"
              ],
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "get-functions"
      },
      {
        "description": "Get cross-references to/from an address or symbol",
        "inputSchema": {
          "properties": {
            "action": {
              "default": "to",
              "enum": [
                "to",
                "from",
                "both",
                "function",
                "referencers_decomp",
                "import",
                "thunk"
              ],
              "type": "string"
            },
            "direction": {
              "type": "string"
            },
            "include_data_refs": {
              "type": "boolean"
            },
            "include_ref_context": {
              "type": "boolean"
            },
            "library_name": {
              "type": "string"
            },
            "limit": {
              "default": 100,
              "type": "integer"
            },
            "mode": {
              "default": "to",
              "enum": [
                "to",
                "from",
                "both",
                "function",
                "referencers_decomp",
                "import",
                "thunk"
              ],
              "type": "string"
            },
            "offset": {
              "default": 0,
              "type": "integer"
            },
            "operation": {
              "default": "to",
              "enum": [
                "to",
                "from",
                "both",
                "function",
                "referencers_decomp",
                "import",
                "thunk"
              ],
              "type": "string"
            },
            "program_path": {
              "type": "string"
            },
            "target": {
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "get-references"
      },
      {
        "description": "Import a binary file for analysis",
        "inputSchema": {
          "properties": {
            "binary_path": {
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "import-binary"
      },
      {
        "description": "Inspect memory: list blocks, read bytes, view data at address",
        "inputSchema": {
          "properties": {
            "action": {
              "default": "blocks",
              "enum": [
                "blocks",
                "read",
                "data_at",
                "data_items",
                "segments"
              ],
              "type": "string"
            },
            "address": {
              "type": "string"
            },
            "length": {
              "default": 256,
              "type": "integer"
            },
            "limit": {
              "type": "integer"
            },
            "mode": {
              "default": "blocks",
              "enum": [
                "blocks",
                "read",
                "data_at",
                "data_items",
                "segments"
              ],
              "type": "string"
            },
            "offset": {
              "default": 0,
              "type": "integer"
            },
            "operation": {
              "default": "blocks",
              "enum": [
                "blocks",
                "read",
                "data_at",
                "data_items",
                "segments"
              ],
              "type": "string"
            },
            "program_path": {
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "inspect-memory"
      },
      {
        "description": "List all functions in the program",
        "inputSchema": {
          "properties": {
            "action": {
              "type": "string"
            },
            "filter_by_tag": {
              "type": "string"
            },
            "filter_default_names": {
              "type": "boolean"
            },
            "has_tags": {
              "type": "boolean"
            },
            "identifiers": {
              "items": {
                "type": "string"
              },
              "type": "array"
            },
            "limit": {
              "default": 100,
              "type": "integer"
            },
            "min_reference_count": {
              "type": "integer"
            },
            "mode": {
              "type": "string"
            },
            "offset": {
              "default": 0,
              "type": "integer"
            },
            "operation": {
              "type": "string"
            },
            "program_path": {
              "type": "string"
            },
            "query": {
              "type": "string"
            },
            "untagged": {
              "type": "boolean"
            },
            "verbose": {
              "type": "boolean"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "list-functions"
      },
      {
        "description": "List open programs (GUI/headless compatible)",
        "inputSchema": {
          "properties": {},
          "required": [],
          "type": "object"
        },
        "name": "list-open-programs"
      },
      {
        "description": "List program binaries in current project",
        "inputSchema": {
          "properties": {},
          "required": [],
          "type": "object"
        },
        "name": "list-project-binaries"
      },
      {
        "description": "Get metadata for a project binary",
        "inputSchema": {
          "properties": {
            "binary_name": {
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "list-project-binary-metadata"
      },
      {
        "description": "List files in the current project",
        "inputSchema": {
          "properties": {},
          "required": [],
          "type": "object"
        },
        "name": "list-project-files"
      },
      {
        "description": "Manage bookmarks in the program",
        "inputSchema": {
          "properties": {
            "action": {
              "description": "Action to perform",
              "enum": [
                "set",
                "get",
                "search",
                "remove",
                "remove_all",
                "categories"
              ],
              "type": "string"
            },
            "address_or_symbol": {
              "description": "Address or symbol for bookmark",
              "type": "string"
            },
            "bookmarks": {
              "description": "Batch bookmarks",
              "items": {
                "type": "object"
              },
              "type": "array"
            },
            "category": {
              "description": "Bookmark category",
              "type": "string"
            },
            "comment": {
              "description": "Bookmark comment",
              "type": "string"
            },
            "limit": {
              "default": 100,
              "description": "Maximum results",
              "type": "integer"
            },
            "mode": {
              "description": "Action to perform",
              "enum": [
                "set",
                "get",
                "search",
                "remove",
                "remove_all",
                "categories"
              ],
              "type": "string"
            },
            "operation": {
              "description": "Action to perform",
              "enum": [
                "set",
                "get",
                "search",
                "remove",
                "remove_all",
                "categories"
              ],
              "type": "string"
            },
            "program_path": {
              "description": "Path to the program/binary file",
              "type": "string"
            },
            "query": {
              "description": "Search text in bookmarks",
              "type": "string"
            },
            "remove_all": {
              "default": false,
              "description": "Remove all bookmarks",
              "type": "boolean"
            },
            "type": {
              "description": "Bookmark type",
              "enum": [
                "Note",
                "Warning",
                "TODO",
                "Bug",
                "Analysis"
              ],
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "manage-bookmarks"
      },
      {
        "description": "Manage comments in the program (EOL, PRE, POST, PLATE, REPEATABLE)",
        "inputSchema": {
          "properties": {
            "action": {
              "enum": [
                "set",
                "get",
                "remove",
                "search",
                "search_decomp"
              ],
              "type": "string"
            },
            "address_or_symbol": {
              "description": "Address or symbol for comment",
              "type": "string"
            },
            "case_sensitive": {
              "type": "boolean"
            },
            "comment": {
              "description": "Comment text",
              "type": "string"
            },
            "comment_type": {
              "type": "string"
            },
            "comment_types": {
              "type": "string"
            },
            "comments": {
              "description": "Batch comments",
              "items": {
                "type": "object"
              },
              "type": "array"
            },
            "end": {
              "type": "string"
            },
            "function": {
              "type": "string"
            },
            "limit": {
              "default": 100,
              "type": "integer"
            },
            "line_number": {
              "type": "integer"
            },
            "mode": {
              "enum": [
                "set",
                "get",
                "remove",
                "search",
                "search_decomp"
              ],
              "type": "string"
            },
            "operation": {
              "enum": [
                "set",
                "get",
                "remove",
                "search",
                "search_decomp"
              ],
              "type": "string"
            },
            "override_max_functions_limit": {
              "type": "boolean"
            },
            "program_path": {
              "type": "string"
            },
            "query": {
              "description": "Search text or regex in comments",
              "type": "string"
            },
            "start": {
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "manage-comments"
      },
      {
        "description": "Manage data types: list archives, list types by category, parse from string, apply at address",
        "inputSchema": {
          "properties": {
            "action": {
              "default": "list",
              "enum": [
                "archives",
                "list",
                "by_string",
                "apply"
              ],
              "type": "string"
            },
            "address_or_symbol": {
              "type": "string"
            },
            "archive_name": {
              "type": "string"
            },
            "category_path": {
              "description": "Category path (e.g., /MyTypes)",
              "type": "string"
            },
            "data_type_string": {
              "description": "Data type as string (e.g., int, char*)",
              "type": "string"
            },
            "include_subcategories": {
              "type": "boolean"
            },
            "limit": {
              "default": 100,
              "type": "integer"
            },
            "mode": {
              "default": "list",
              "enum": [
                "archives",
                "list",
                "by_string",
                "apply"
              ],
              "type": "string"
            },
            "offset": {
              "default": 0,
              "type": "integer"
            },
            "operation": {
              "default": "list",
              "enum": [
                "archives",
                "list",
                "by_string",
                "apply"
              ],
              "type": "string"
            },
            "program_path": {
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "manage-data-types"
      },
      {
        "description": "Manage project and filesystem files (import/export/list/info/create/edit/move/version-control)",
        "inputSchema": {
          "properties": {
            "action": {
              "enum": [
                "rename",
                "delete",
                "copy",
                "move",
                "info",
                "list",
                "mkdir",
                "touch",
                "read",
                "write",
                "append",
                "import",
                "export",
                "download-shared",
                "pull-shared",
                "push-shared",
                "sync-shared",
                "checkout",
                "uncheckout",
                "unhijack"
              ],
              "type": "string"
            },
            "analyze_after_import": {
              "default": false,
              "type": "boolean"
            },
            "content": {
              "type": "string"
            },
            "create_parents": {
              "default": true,
              "type": "boolean"
            },
            "destination_folder": {
              "type": "string"
            },
            "destination_path": {
              "type": "string"
            },
            "dry_run": {
              "default": false,
              "type": "boolean"
            },
            "enable_version_control": {
              "type": "boolean"
            },
            "encoding": {
              "default": "utf-8",
              "type": "string"
            },
            "exclusive": {
              "default": false,
              "type": "boolean"
            },
            "export_type": {
              "type": "string"
            },
            "file_path": {
              "type": "string"
            },
            "force": {
              "default": false,
              "type": "boolean"
            },
            "format": {
              "type": "string"
            },
            "include_comments": {
              "type": "boolean"
            },
            "include_parameters": {
              "type": "boolean"
            },
            "include_variables": {
              "type": "boolean"
            },
            "keep": {
              "default": false,
              "type": "boolean"
            },
            "max_depth": {
              "default": 16,
              "type": "integer"
            },
            "max_results": {
              "default": 200,
              "type": "integer"
            },
            "mirror_fs": {
              "type": "boolean"
            },
            "mode": {
              "enum": [
                "pull",
                "push",
                "bidirectional"
              ],
              "type": "string"
            },
            "new_name": {
              "type": "string"
            },
            "new_path": {
              "type": "string"
            },
            "operation": {
              "enum": [
                "rename",
                "delete",
                "copy",
                "move",
                "info",
                "list",
                "mkdir",
                "touch",
                "read",
                "write",
                "append",
                "import",
                "export",
                "download-shared",
                "pull-shared",
                "push-shared",
                "sync-shared",
                "checkout",
                "uncheckout",
                "unhijack"
              ],
              "type": "string"
            },
            "path": {
              "type": "string"
            },
            "program_path": {
              "type": "string"
            },
            "recursive": {
              "default": false,
              "type": "boolean"
            },
            "source_path": {
              "type": "string"
            },
            "strip_all_container_path": {
              "type": "boolean"
            },
            "strip_leading_path": {
              "type": "boolean"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "manage-files"
      },
      {
        "description": "Manage function tags",
        "inputSchema": {
          "properties": {
            "action": {
              "enum": [
                "list",
                "add",
                "remove",
                "search"
              ],
              "type": "string"
            },
            "function": {
              "type": "string"
            },
            "mode": {
              "enum": [
                "list",
                "add",
                "remove",
                "search"
              ],
              "type": "string"
            },
            "operation": {
              "enum": [
                "list",
                "add",
                "remove",
                "search"
              ],
              "type": "string"
            },
            "program_path": {
              "type": "string"
            },
            "tags": {
              "items": {
                "type": "string"
              },
              "type": "array"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "manage-function-tags"
      },
      {
        "description": "Modify function properties (rename, set prototype, set calling convention, etc.)",
        "inputSchema": {
          "properties": {
            "action": {
              "enum": [
                "rename",
                "set_prototype",
                "set_calling_convention",
                "set_return_type",
                "delete",
                "create"
              ],
              "type": "string"
            },
            "address": {
              "description": "Address for create action",
              "type": "string"
            },
            "archive_name": {
              "type": "string"
            },
            "create_if_not_exists": {
              "type": "boolean"
            },
            "datatype_mappings": {
              "type": "string"
            },
            "function_identifier": {
              "type": "string"
            },
            "functions": {
              "type": "string"
            },
            "mode": {
              "enum": [
                "rename",
                "set_prototype",
                "set_calling_convention",
                "set_return_type",
                "delete",
                "create"
              ],
              "type": "string"
            },
            "name": {
              "type": "string"
            },
            "new_name": {
              "type": "string"
            },
            "new_type": {
              "type": "string"
            },
            "old_name": {
              "type": "string"
            },
            "operation": {
              "enum": [
                "rename",
                "set_prototype",
                "set_calling_convention",
                "set_return_type",
                "delete",
                "create"
              ],
              "type": "string"
            },
            "program_path": {
              "type": "string"
            },
            "propagate": {
              "type": "boolean"
            },
            "propagate_max_candidates": {
              "type": "integer"
            },
            "propagate_max_instructions": {
              "type": "integer"
            },
            "propagate_program_paths": {
              "items": {
                "type": "string"
              },
              "type": "array"
            },
            "prototype": {
              "type": "string"
            },
            "variable_mappings": {
              "type": "string"
            },
            "variable_name": {
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "manage-function"
      },
      {
        "description": "Search and manage string data in the program",
        "inputSchema": {
          "properties": {
            "action": {
              "default": "list",
              "enum": [
                "list",
                "regex",
                "count",
                "similarity"
              ],
              "type": "string"
            },
            "include_referencing_functions": {
              "default": false,
              "type": "boolean"
            },
            "limit": {
              "default": 100,
              "type": "integer"
            },
            "mode": {
              "default": "list",
              "enum": [
                "list",
                "regex",
                "count",
                "similarity"
              ],
              "type": "string"
            },
            "offset": {
              "default": 0,
              "type": "integer"
            },
            "operation": {
              "default": "list",
              "enum": [
                "list",
                "regex",
                "count",
                "similarity"
              ],
              "type": "string"
            },
            "program_path": {
              "type": "string"
            },
            "query": {
              "description": "Search query or regex pattern",
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "manage-strings"
      },
      {
        "description": "Manage structures and unions (create, modify, apply, parse C headers)",
        "inputSchema": {
          "properties": {
            "action": {
              "enum": [
                "parse",
                "validate",
                "create",
                "add_field",
                "modify_field",
                "modify_from_c",
                "info",
                "list",
                "apply",
                "delete",
                "parse_header"
              ],
              "type": "string"
            },
            "address_or_symbol": {
              "type": "string"
            },
            "c_definition": {
              "description": "C struct definition",
              "type": "string"
            },
            "category": {
              "type": "string"
            },
            "clear_existing": {
              "type": "boolean"
            },
            "description": {
              "type": "string"
            },
            "fields": {
              "items": {
                "type": "object"
              },
              "type": "array"
            },
            "force": {
              "type": "boolean"
            },
            "header_content": {
              "type": "string"
            },
            "include_built_in": {
              "type": "boolean"
            },
            "mode": {
              "enum": [
                "parse",
                "validate",
                "create",
                "add_field",
                "modify_field",
                "modify_from_c",
                "info",
                "list",
                "apply",
                "delete",
                "parse_header"
              ],
              "type": "string"
            },
            "name": {
              "description": "Structure name",
              "type": "string"
            },
            "name_filter": {
              "type": "string"
            },
            "operation": {
              "enum": [
                "parse",
                "validate",
                "create",
                "add_field",
                "modify_field",
                "modify_from_c",
                "info",
                "list",
                "apply",
                "delete",
                "parse_header"
              ],
              "type": "string"
            },
            "packed": {
              "type": "boolean"
            },
            "program_path": {
              "type": "string"
            },
            "size": {
              "type": "integer"
            },
            "structure_name": {
              "type": "string"
            },
            "type": {
              "enum": [
                "parse",
                "validate",
                "create",
                "add_field",
                "modify_field",
                "modify_from_c",
                "info",
                "list",
                "apply",
                "delete",
                "parse_header"
              ],
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "manage-structures"
      },
      {
        "description": "Manage symbols: list, search, create labels, rename, demangle, imports/exports",
        "inputSchema": {
          "properties": {
            "action": {
              "description": "Alias for 'mode'. Either 'mode' or 'action' may be used interchangeably.",
              "type": "string"
            },
            "address": {
              "type": "string"
            },
            "demangle_all": {
              "type": "boolean"
            },
            "filter_default_names": {
              "default": true,
              "type": "boolean"
            },
            "group_by_library": {
              "type": "boolean"
            },
            "include_external": {
              "type": "boolean"
            },
            "label_name": {
              "type": "string"
            },
            "library_filter": {
              "type": "string"
            },
            "limit": {
              "default": 100,
              "type": "integer"
            },
            "mode": {
              "default": "symbols",
              "description": "Operation mode. Also accepts 'action' as an alias.",
              "enum": [
                "symbols",
                "classes",
                "namespaces",
                "imports",
                "exports",
                "create_label",
                "count",
                "rename_data",
                "demangle"
              ],
              "type": "string"
            },
            "new_name": {
              "type": "string"
            },
            "offset": {
              "default": 0,
              "type": "integer"
            },
            "operation": {
              "description": "Alias for 'mode'. Either 'mode' or 'action' may be used interchangeably.",
              "type": "string"
            },
            "program_path": {
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "manage-symbols"
      },
      {
        "description": "Match/compare functions by signature, callees, callers",
        "inputSchema": {
          "properties": {
            "batch_size": {
              "type": "integer"
            },
            "filter_by_tag": {
              "type": "string"
            },
            "filter_default_names": {
              "type": "boolean"
            },
            "function_identifier": {
              "type": "string"
            },
            "limit": {
              "type": "integer"
            },
            "max_instructions": {
              "type": "integer"
            },
            "min_similarity": {
              "type": "integer"
            },
            "program_path": {
              "type": "string"
            },
            "propagate_comments": {
              "type": "boolean"
            },
            "propagate_names": {
              "type": "boolean"
            },
            "propagate_tags": {
              "type": "boolean"
            },
            "target_program_paths": {
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "match-function"
      },
      {
        "description": "Execute arbitrary Ghidra/PyGhidra Python code. The full Ghidra API is available (currentProgram, flatApi, monitor, state, decompiler, Transaction, AddressFactory, etc.). Returns stdout/stderr output and the value of the last expression (stored as __result__).",
        "inputSchema": {
          "properties": {
            "code": {
              "description": "Python code to execute in the Ghidra JVM context. Assign to __result__ to return a value.",
              "type": "string"
            },
            "program_path": {
              "description": "Program path (optional in GUI mode, required headless)",
              "type": "string"
            },
            "timeout": {
              "default": 30,
              "description": "Max execution time in seconds (default: 30)",
              "type": "integer"
            }
          },
          "required": [
            "code"
          ],
          "type": "object"
        },
        "name": "execute-script"
      },
      {
        "description": "Open a program or project",
        "inputSchema": {
          "properties": {
            "analyze_after_import": {
              "default": true,
              "type": "boolean"
            },
            "destination_folder": {
              "default": "/",
              "type": "string"
            },
            "enable_version_control": {
              "default": true,
              "type": "boolean"
            },
            "extensions": {
              "items": {
                "type": "string"
              },
              "type": "array"
            },
            "open_all_programs": {
              "default": true,
              "type": "boolean"
            },
            "path": {
              "type": "string"
            },
            "server_host": {
              "type": "string"
            },
            "server_password": {
              "type": "string"
            },
            "server_port": {
              "type": "integer"
            },
            "server_username": {
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "open"
      },
      {
        "description": "Search code using semantic/literal strategies (falls back to function-name literal search when semantic index is unavailable)",
        "inputSchema": {
          "properties": {
            "binary_name": {
              "type": "string"
            },
            "limit": {
              "default": 10,
              "type": "integer"
            },
            "query": {
              "type": "string"
            }
          },
          "required": [
            "query"
          ],
          "type": "object"
        },
        "name": "search-code"
      },
      {
        "description": "Search for constant values used in instructions",
        "inputSchema": {
          "properties": {
            "action": {
              "default": "common",
              "enum": [
                "specific",
                "range",
                "common"
              ],
              "type": "string"
            },
            "include_small_values": {
              "type": "boolean"
            },
            "limit": {
              "default": 1000,
              "type": "integer"
            },
            "max_value": {
              "description": "Max value (range mode)",
              "type": "integer"
            },
            "min_value": {
              "description": "Min value (range mode)",
              "type": "integer"
            },
            "mode": {
              "default": "common",
              "enum": [
                "specific",
                "range",
                "common"
              ],
              "type": "string"
            },
            "operation": {
              "default": "common",
              "enum": [
                "specific",
                "range",
                "common"
              ],
              "type": "string"
            },
            "program_path": {
              "type": "string"
            },
            "top_n": {
              "type": "integer"
            },
            "value": {
              "description": "Specific value to search (specific mode)",
              "type": "integer"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "search-constants"
      },
      {
        "description": "Get analysis suggestions for a function or address",
        "inputSchema": {
          "properties": {
            "address": {
              "type": "string"
            },
            "data_type": {
              "type": "string"
            },
            "function": {
              "type": "string"
            },
            "program_path": {
              "type": "string"
            },
            "suggestion_type": {
              "enum": [
                "comment_type",
                "comment_text",
                "function_name",
                "function_tags",
                "variable_name",
                "data_type"
              ],
              "type": "string"
            },
            "variable_address": {
              "type": "string"
            }
          },
          "required": [],
          "type": "object"
        },
        "name": "suggest"
      }
    ]
  }
}