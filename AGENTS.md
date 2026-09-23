# AGENTS.md

Guidance for coding agents working in this repository.

## What this is

`openhound-okta` is an Okta collector extension for OpenHound (SpecterOps' framework for building
BloodHound OpenGraph collectors). It collects Okta resources over the Okta API and converts them into
BloodHound-compatible graph nodes and edges. It is a Python 3.13+ project built on the
[DLT](https://dlthub.com/docs/intro) library.

The package registers itself through the `openhound.sources` entry point (`openhound_okta.main:app`);
the `openhound` CLI (and `src/main.py`) drive it.

## Commands

```bash
uv sync --group dev        # install dependencies (just sync)
just lint                  # ruff check .
just typecheck             # mypy src
just test-all              # uv run pytest
```

Pipeline stages (each wraps `openhound <stage> okta ...`):

```bash
just collect      # collect Okta data into ./output (needs .dlt/secrets.toml credentials)
just preprocess   # load collected data into DuckDB tables + derived tables
just convert      # emit OpenGraph nodes/edges into ./output/graph/okta
just db           # open lookup.duckdb in the DuckDB UI
```

After cloning, initialize the submodule: `git submodule update --init` (docs/og-docs-automation),
then `just skills` installs the shared documentation agent skills.

## Architecture

Three-stage pipeline driven by decorators on the OpenHound `app` object created in
`src/openhound_okta/main.py`:

1. **Collect** (`@app.collect`, [source.py](src/openhound_okta/source.py)) — DLT resources and
   transformers, one per Okta endpoint family (`@app.resource` / `@app.transformer`). `SourceContext`
   bundles a `ClientPool` of `OktaRESTClient`s, credentials, and page-size settings. Rows are validated
   pydantic models and written to disk by DLT.
2. **Preprocess** (`@app.preproc`, [transforms.py](src/openhound_okta/transforms.py)) — loads collected
   resources into DuckDB tables (`okta` schema; the resource→table map is
   `preprocessing_resources()` in main.py) and builds derived tables and indices.
3. **Convert** (`@app.convert`, models + [lookup.py](src/openhound_okta/lookup.py)) — re-instantiates
   models from the DuckDB rows; each model's `as_node` / `edges` properties emit OpenGraph output.
   `OktaLookup` answers cross-resource queries against DuckDB during conversion and is available to
   models as `self._lookup`.

## Conventions

- Use type hints to annotate new functions, methods, properties, variables, constants, etc.
- All modules, classes, methods, OpenHound assets, DLT resources, and transformers should have concise docstrings, including private ones.
- Comments should explain why code is shaped a certain way, not repeat what the next line does. Prefer a named helper over a long explanatory comment when the logic is reused.
- PR branch names must match `^(fix|patch|chore|feature|minor|major)/<description>` (CI enforces).
- Versioning is git-tag based (hatch-vcs); merging a PR that touches `src/`, `pyproject.toml`,
  `uv.lock`, or `README.md` triggers the release workflow. Do not hand-edit a version number.
