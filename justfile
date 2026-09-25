set dotenv-load := true
set windows-shell := ["C:\\Program Files\\Git\\bin\\sh.exe", "-c"]

collect +args='okta ./output':
    @echo "Collecting data"
    uv run src/main.py collect {{args}}

preprocess +args='okta ./output/okta':
    @echo "Preprocessing data"
    uv run openhound preprocess {{args}}

convert +args='okta ./output/okta ./output/graph/okta':
    @echo "Converting data"
    uv run openhound convert {{args}}

lock:
    @echo "Locking dependencies"
    uv lock

sync:
    @echo "Syncing dependencies"
    uv sync --group dev

skills:
    @echo "Installing shared agent skills"
    npx skills add https://github.com/SpecterOps/og-docs-automation --skill '*' --agent codex claude-code --project --yes
    npx skills add https://github.com/SpecterOps/openhound-template --skill '*' --agent codex claude-code --project --yes

db:
    @echo "Opening the lookup database in the DuckDB UI"
    duckdb -ui lookup.duckdb

lint:
    @echo "Checking code style"
    uv run ruff check .

typecheck:
    @echo "Running type checks"
    uv run mypy src

# Run one test area, e.g. `just test hybrid_auth`.
test area:
    uv run pytest "tests/test_{{area}}.py" -v

# Run every discovered test.
test-all:
    uv run pytest
