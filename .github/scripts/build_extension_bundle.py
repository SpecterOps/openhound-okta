"""Packages a Community extension bundle ZIP from JSON data documented in https://bloodhound.specterops.io/opengraph/developer/extension-bundles"""

import argparse
import json
import re
from pathlib import Path
from zipfile import ZIP_STORED, ZipFile, ZipInfo

MAX_BYTES = 10 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"Duplicate JSON field: {key}")
        result[key] = value
    return result


def read_json(path, root):
    require(not any(p.is_symlink() for p in [path, *path.parents]),
            f"Symlink input: {path}")
    require(path.resolve().is_relative_to(root.resolve()), f"Input escapes extension: {path}")
    require(path.is_file() and path.stat().st_size <= MAX_BYTES, f"Invalid input size: {path}")
    return json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique_object,
                      parse_constant=lambda value: require(False, f"Invalid JSON number: {value}"))


def require_text(record, field):
    require(isinstance(record.get(field), str) and record[field].strip(),
            f"Missing or invalid {field}")


def load_component_records(root, filename, directory, wrapper):
    consolidated = root / filename
    individual = root / directory
    require(not individual.is_symlink(), f"Symlink directory: {individual}")
    require(not individual.exists() or individual.is_dir(), f"Not a directory: {individual}")
    if individual.exists():
        require(not any(path.is_symlink() for path in individual.rglob("*")),
                f"Symlink inside {individual}")
    files = sorted(individual.rglob("*.json")) if individual.exists() else []
    require(len(files) <= 1000, "Too many component inputs")
    require(sum(path.stat().st_size for path in files) <= MAX_BYTES,
            "Combined component inputs exceed 10 MiB")
    require(not (consolidated.exists() and files),
            f"Use either {filename} or {directory}, not both")
    if consolidated.exists() or consolidated.is_symlink():
        data = read_json(consolidated, root)
        require(isinstance(data, dict) and set(data) == {wrapper}, f"Expected {wrapper} wrapper")
        records = data[wrapper]
        require(isinstance(records, list) and records, f"Empty or invalid {filename}")
    else:
        records = [read_json(path, root) for path in files]
    return records


def validate_query(record):
    require_text(record, "query")
    allowed = {"query_key", "name", "description", "query", "category"}
    require(not set(record) - allowed, f"Unknown component fields: {set(record) - allowed}")


def normalize_rule(record):
    if "cypher" in record or "zone" in record:
        require("seeds" not in record and record.get("zone") == "Tier Zero",
                "Only Tier Zero legacy rules can be bundled; mixed formats are invalid")
        require_text(record, "cypher")
        record["seeds"] = [{"type": 2, "value": record.pop("cypher")}]
        record.pop("zone")
    seeds = record.get("seeds")
    require(isinstance(seeds, list) and len(seeds) == 1, "Rules need exactly one seed")
    seed = seeds[0]
    require(isinstance(seed, dict) and set(seed) == {"type", "value"}
            and type(seed["type"]) is int and seed["type"] == 2, "Invalid Cypher seed")
    require_text(seed, "value")
    for field in ["enabled", "allow_disable"]:
        require(type(record.get(field, True)) is bool, f"Invalid {field}")
    allowed = {"key", "name", "description", "enabled", "allow_disable", "seeds"}
    require(not set(record) - allowed, f"Unknown component fields: {set(record) - allowed}")


def component(root, filename, directory, wrapper, key):
    records = load_component_records(root, filename, directory, wrapper)
    keys, names, converted = set(), set(), []
    for record in records:
        require(isinstance(record, dict), "Component records must be objects")
        record = dict(record)
        if wrapper == "queries":
            validate_query(record)
        else:
            normalize_rule(record)
        require_text(record, key)
        require_text(record, "name")
        for field in ["description", "category"]:
            require(field not in record or isinstance(record[field], str), f"Invalid {field}")
        require(record[key] not in keys and record["name"] not in names, "Duplicate component key or name")
        keys.add(record[key])
        names.add(record["name"])
        converted.append(record)
    return {wrapper: sorted(converted, key=lambda record: record[key])} if converted else None


def encoded(data):
    value = (json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    require(len(value) <= MAX_BYTES, "Component exceeds 10 MiB")
    return value


def build(root, output):
    schema = read_json(root / "schema.json", root)
    require(isinstance(schema, dict) and isinstance(schema.get("schema"), dict), "Missing schema metadata")
    metadata = schema["schema"]
    for field in ["name", "version", "namespace"]:
        require_text(metadata, field)
    require(re.fullmatch(r"[A-Za-z0-9_-]+", metadata["name"]), "Unsafe schema name")
    version = metadata["version"].removeprefix("v")
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?", version),
            "Invalid schema version")
    require(not {"queries", "pz_rules"} & set(schema), "Components cannot be embedded in schema")
    for field in ["node_kinds", "relationship_kinds"]:
        require(isinstance(schema.get(field), list), f"Missing {field}")
    require("relationship_findings" not in schema or schema["relationship_findings"] == [],
            "Community bundles cannot contain findings")
    parts = {"schema.json": encoded(schema)}
    for filename, directory, wrapper, key in [
        ("saved_queries.json", "saved_searches", "queries", "query_key"),
        ("pz_rules.json", "privilege_zone_rules", "pz_rules", "key"),
    ]:
        data = component(root, filename, directory, wrapper, key)
        if data is not None:
            parts[filename] = encoded(data)
    require("relationship_findings" not in schema or "pz_rules.json" in parts,
            "A findings section requires PZ rules")
    output.mkdir(parents=True, exist_ok=True)
    target = output / f"{metadata['name']}-v{version}.zip"
    with ZipFile(target, "w", compression=ZIP_STORED) as archive:
        for name, value in sorted(parts.items()):
            info = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, value)
    with ZipFile(target) as archive:
        require(archive.namelist() == sorted(parts) and archive.testzip() is None, "Invalid ZIP")
        for name, value in parts.items():
            require(archive.read(name) == value, f"ZIP content mismatch: {name}")
    print(target.name)
    return target


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extension", type=Path, default=Path("extension"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        build(args.extension, args.output)
    except (ValueError, OSError) as error:
        parser.exit(1, f"Bundle error: {error}\n")
