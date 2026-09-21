# Contributing

## Development setup

### 1. Install the required tools

Development requires the following tools. Install them with your platform's package manager.

- [uv](https://docs.astral.sh/uv/) — Python and dependency management
- [just](https://just.systems/) — command runner for the justfile
- [Git](https://git-scm.com/) — version control
- [DuckDB](https://duckdb.org/) — querying collected data
- [Visual Studio Code](https://code.visualstudio.com/) — recommended editor
- [Node.js](https://nodejs.org/) — only needed to install agent skills

#### Windows

Install everything in one step using the
[WinGet configuration file](.config/configuration.winget) included in this repository:

```powershell
winget configure https://raw.githubusercontent.com/SpecterOps/openhound-okta/main/.config/configuration.winget
```

The configuration also enables [Windows Developer Mode](https://learn.microsoft.com/en-us/windows/advanced-settings/developer-mode). Some resources (Git, Node.js,
Developer Mode) install machine-wide, so expect a User Account Control elevation prompt.

### 2. Clone the repository with submodules

```bash
git clone --recurse-submodules https://github.com/SpecterOps/openhound-okta.git
cd openhound-okta
```

If you already cloned without submodules, run `git submodule update --init`.

### 3. Install agent skills

If you use a coding agent (Claude Code or Codex), install the shared documentation
skills from the `og-docs-automation` submodule:

```bash
npx skills add ./docs/og-docs-automation/skills --skill '*' --agent codex claude-code --project --yes
```

### 4. Install Python dependencies

uv downloads the required Python version and creates the virtual environment automatically:

```bash
uv sync --group dev
```

### 5. Enable pre-commit hooks

Enable the repository's pre-commit hooks so lint issues are caught before you push:

```bash
uv run pre-commit install
```

### 6. Open the project in VS Code

```bash
code .
```

Accept the recommended workspace extensions when prompted. Common actions are available
as VS Code tasks (**Terminal > Run Task...**), including collection, linting, type
checking, tests, and the marimo data browser.

## Common commands

The [justfile](justfile) wraps the usual development commands:

```bash
just sync        # sync dependencies (dev group)
just lint        # ruff check
just typecheck   # mypy
just test-all    # pytest
just collect     # run the Okta collector into ./output
just db          # browse the lookup database in the DuckDB UI
```

## Browsing the lookup database

Open the local `lookup.duckdb` database in the DuckDB UI:

```bash
duckdb -ui lookup.duckdb
```
