set dotenv-load := true

collect +args:
    @echo "Collecting data"
    uv run src/main.py collect okta {{args}}

preprocess +args:
    @echo "Collecting data"
    uv run src/main.py preprocess okta {{args}}

convert +args:
    @echo "Converting data"
    uv run src/main.py convert okta {{args}}

sync:
    @echo "Syncing dependencies"
    uv sync --group dev
