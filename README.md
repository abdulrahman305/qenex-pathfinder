# qenex-pathfinder

A standalone Python security audit tool that scans codebases for vulnerabilities,
misconfigurations, and dangerous patterns. Works as a CLI tool, a CI check, and
an MCP server for Claude Code integration.

## Features

- **60+ security checks** across 12 categories (credentials, SQL injection,
  command injection, XXE, CORS, network, crypto, systemd, permissions,
  async/sync, dependencies, Docker)
- **AST-based analysis** for Python files -- avoids false positives from comments
  and docstrings
- **Regex-based rules** for config files, systemd units, Dockerfiles, and YAML
- **Three output formats**: colored text, JSON, SARIF 2.1.0 (GitHub Code
  Scanning / VS Code compatible)
- **MCP server** for real-time scanning from Claude Code
- **Configurable** via `.pathfinder.yml`
- **Zero mandatory dependencies** beyond PyYAML (MCP is optional)

## Installation

```bash
# From source
cd qenex-pathfinder
pip install .

# With MCP support
pip install .[mcp]

# Development
pip install .[dev]
```

## CLI Usage

```bash
# Scan current directory
pathfinder .

# Scan a specific file
pathfinder /path/to/app.py

# Filter by severity
pathfinder . --severity high

# JSON output
pathfinder . --format json

# SARIF output (for CI)
pathfinder . --format sarif > results.sarif

# Run specific rules only
pathfinder . --rules PF-CRED-001,PF-SQLI-001

# Exclude paths
pathfinder . --exclude vendor/,test_data/

# Use custom config
pathfinder . --config /path/to/.pathfinder.yml

# Run as module
python -m pathfinder .
```

### Exit Codes

| Code | Meaning                                       |
|------|-----------------------------------------------|
| 0    | No findings at or above the requested severity |
| 1    | One or more findings found                     |

## MCP Server (Claude Code Integration)

Start the MCP server for interactive scanning from Claude Code:

```bash
pathfinder --mcp
```

Or add to your Claude Code MCP configuration:

```json
{
  "mcpServers": {
    "pathfinder": {
      "command": "pathfinder",
      "args": ["--mcp"]
    }
  }
}
```

### MCP Tools

| Tool                | Description                          |
|---------------------|--------------------------------------|
| `scan_path`         | Scan a file or directory             |
| `scan_file_content` | Scan source code text directly       |
| `list_rules`        | List all available security rules    |
| `explain_finding`   | Get details about a specific rule ID |

## Rule Reference

### Credentials (PF-CRED-001 to PF-CRED-006, CWE-798)

| Rule ID      | Title                    | Severity | Method |
|-------------|--------------------------|----------|--------|
| PF-CRED-001 | Private Key in Config    | CRITICAL | Regex  |
| PF-CRED-002 | API Key in Source        | HIGH     | Regex  |
| PF-CRED-003 | Password Default Fallback| HIGH     | AST    |
| PF-CRED-004 | Hardcoded JWT/Bearer     | HIGH     | Regex  |
| PF-CRED-005 | Cloud Provider Creds     | CRITICAL | Regex  |
| PF-CRED-006 | SSH Private Key Content  | CRITICAL | Regex  |

### SQL Injection (PF-SQLI-001 to PF-SQLI-004, CWE-89)

| Rule ID      | Title                           | Severity | Method |
|-------------|----------------------------------|----------|--------|
| PF-SQLI-001 | f-string in SQL Execute          | CRITICAL | AST    |
| PF-SQLI-002 | .format() in SQL Execute         | CRITICAL | AST    |
| PF-SQLI-003 | String Concatenation in SQL      | HIGH     | AST    |
| PF-SQLI-004 | Subprocess sqlite3 Interpolation | HIGH     | AST    |

### Command Injection (PF-CMDI-001 to PF-CMDI-005, CWE-78)

| Rule ID      | Title                           | Severity | Method |
|-------------|----------------------------------|----------|--------|
| PF-CMDI-001 | shell=True with Variable         | CRITICAL | AST    |
| PF-CMDI-002 | os.system() Call                 | HIGH     | AST    |
| PF-CMDI-003 | os.popen() Call                  | HIGH     | AST    |
| PF-CMDI-004 | eval() with User Input           | HIGH     | AST    |
| PF-CMDI-005 | exec() with User Input           | HIGH     | AST    |

### XXE and Deserialization (PF-XXE-001 to PF-XXE-005, CWE-611/502)

| Rule ID     | Title                     | Severity | Method |
|------------|---------------------------|----------|--------|
| PF-XXE-001 | Unsafe xml.etree          | MEDIUM   | AST    |
| PF-XXE-002 | Unsafe xml.sax            | MEDIUM   | AST    |
| PF-XXE-003 | Unsafe lxml Parser        | MEDIUM   | AST    |
| PF-XXE-004 | Unsafe pickle             | HIGH     | AST    |
| PF-XXE-005 | Unsafe yaml.load()        | HIGH     | AST    |

### CORS (PF-CORS-001 to PF-CORS-003, CWE-942)

| Rule ID      | Title                      | Severity | Method |
|-------------|----------------------------|----------|--------|
| PF-CORS-001 | CORS Allow All Origins     | MEDIUM   | AST    |
| PF-CORS-002 | CORS Header Wildcard       | MEDIUM   | Regex  |
| PF-CORS-003 | CORS Credentials Wildcard  | HIGH     | AST    |

### Network (PF-NET-001 to PF-NET-004, CWE-668)

| Rule ID     | Title                  | Severity | Method |
|------------|------------------------|----------|--------|
| PF-NET-001 | Binding to 0.0.0.0    | MEDIUM   | Regex  |
| PF-NET-002 | Binding to ::          | MEDIUM   | Regex  |
| PF-NET-003 | Debug Mode Enabled     | MEDIUM   | Regex  |
| PF-NET-004 | Dangerous Port Exposed | MEDIUM   | Regex  |

### Cryptography (PF-CRYP-001 to PF-CRYP-005, CWE-327/328)

| Rule ID      | Title                   | Severity | Method |
|-------------|-------------------------|----------|--------|
| PF-CRYP-001 | MD5 Hash Usage          | MEDIUM   | AST    |
| PF-CRYP-002 | SHA1 Hash Usage         | MEDIUM   | AST    |
| PF-CRYP-003 | DES/3DES Usage          | HIGH     | AST    |
| PF-CRYP-004 | Random for Crypto       | HIGH     | AST    |
| PF-CRYP-005 | Hardcoded Encryption Key| CRITICAL | Regex  |

### systemd (PF-SYSD-001 to PF-SYSD-005, CWE-522)

| Rule ID      | Title                          | Severity | Method |
|-------------|--------------------------------|----------|--------|
| PF-SYSD-001 | Secret in Environment=         | HIGH     | Regex  |
| PF-SYSD-002 | Missing ProtectSystem          | LOW      | Text   |
| PF-SYSD-003 | Root Without Hardening         | MEDIUM   | Regex  |
| PF-SYSD-004 | World-Readable EnvironmentFile | HIGH     | Stat   |
| PF-SYSD-005 | ExecStart with Elevated Privs  | MEDIUM   | Regex  |

### Permissions (PF-PERM-001 to PF-PERM-004, CWE-732)

| Rule ID      | Title                        | Severity | Method |
|-------------|------------------------------|----------|--------|
| PF-PERM-001 | World-Writable File          | HIGH     | Stat   |
| PF-PERM-002 | Secret File Not 0600         | HIGH     | Stat   |
| PF-PERM-003 | SUID/SGID on Script          | CRITICAL | Stat   |
| PF-PERM-004 | Private Key World-Readable   | CRITICAL | Stat   |

### Async/Sync (PF-ASYN-001 to PF-ASYN-005, CWE-834)

| Rule ID      | Title                       | Severity | Method |
|-------------|------------------------------|----------|--------|
| PF-ASYN-001 | Sync Call in async def       | MEDIUM   | AST    |
| PF-ASYN-002 | Missing await on Coroutine   | HIGH     | AST    |
| PF-ASYN-003 | Blocking I/O in async def    | LOW      | AST    |
| PF-ASYN-004 | CPU-Bound in async def       | LOW      | AST    |
| PF-ASYN-005 | asyncio.sleep(0) Busy Loop   | LOW      | AST    |

### Dependencies (PF-DEP-001 to PF-DEP-003, CWE-1104)

| Rule ID     | Title                     | Severity | Method |
|------------|---------------------------|----------|--------|
| PF-DEP-001 | Unpinned Dependency       | LOW      | Regex  |
| PF-DEP-002 | Unpinned Docker Image     | MEDIUM   | Regex  |
| PF-DEP-003 | Known Vulnerable Package  | HIGH     | Regex  |

### Docker (PF-DOCK-001 to PF-DOCK-008, CWE-250)

| Rule ID      | Title                      | Severity | Method |
|-------------|----------------------------|----------|--------|
| PF-DOCK-001 | Container Running as Root  | MEDIUM   | Regex  |
| PF-DOCK-002 | Docker Socket Mounted      | CRITICAL | Regex  |
| PF-DOCK-003 | Privileged Mode            | CRITICAL | Regex  |
| PF-DOCK-004 | Missing no-new-privileges  | LOW      | Text   |
| PF-DOCK-005 | Host Network Mode          | HIGH     | Regex  |
| PF-DOCK-006 | Latest Tag Usage           | LOW      | Regex  |
| PF-DOCK-007 | Secrets in ENV/ARG         | HIGH     | Regex  |
| PF-DOCK-008 | No HEALTHCHECK             | LOW      | Regex  |

## SARIF Integration

SARIF output is compatible with:

- **GitHub Code Scanning**: Upload via `github/codeql-action/upload-sarif`
- **VS Code**: Install the SARIF Viewer extension
- **Azure DevOps**: Native SARIF support in pipelines

Example GitHub Actions workflow:

```yaml
- name: Run Pathfinder
  run: pathfinder . --format sarif > pathfinder.sarif
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: pathfinder.sarif
```

## Configuration

Create a `.pathfinder.yml` in your project root:

```yaml
exclude_paths:
  - "vendor/"
  - "node_modules/"
  - ".venv/"
min_severity: low
exclude_rules: []
extensions:
  - ".py"
  - ".service"
  - ".yml"
  - ".yaml"
  - ".txt"
  - ".toml"
```

## License

MIT -- Copyright (c) 2024 QENEX LTD
