set dotenv-load := true

collect +args='okta /tmp/output/raw/':
    @echo "Collecting data"
    uv run src/main.py collect {{args}}

preprocess +args='okta /tmp/output/raw/okta':
    @echo "Preprocessing data"
    uv run openhound preprocess {{args}}

convert +args='okta /tmp/output/raw/okta /tmp/output/graph/okta':
    @echo "Converting data"
    uv run openhound convert {{args}}

sync:
    @echo "Syncing dependencies"
    uv sync --group dev
