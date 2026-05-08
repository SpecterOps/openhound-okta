import ast
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _keyword(call: ast.Call, name: str) -> ast.keyword | None:
    return next((keyword for keyword in call.keywords if keyword.arg == name), None)


def _schema_traversability() -> dict[str, bool]:
    schema = json.loads((ROOT / "extension" / "schema.json").read_text())
    return {relationship["name"]: relationship["is_traversable"] for relationship in schema["relationship_kinds"]}


def _edge_constants() -> dict[str, str]:
    tree = ast.parse((SRC / "openhound_okta" / "kinds" / "edges.py").read_text())
    constants: dict[str, str] = {}

    for statement in tree.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue

        target = statement.targets[0]
        if not isinstance(target, ast.Name) or not target.id.isupper():
            continue

        if isinstance(statement.value, ast.Constant) and isinstance(statement.value.value, str):
            constants[target.id] = statement.value.value

    return constants


def _assert_schema_traversable_call(value: ast.AST, kind: ast.AST, path: Path) -> None:
    assert isinstance(value, ast.Call), f"{path}:{value.lineno} traversable value must call ek.traversable()"
    assert _call_name(value.func) == "traversable", f"{path}:{value.lineno} must call ek.traversable()"
    assert len(value.args) == 1, f"{path}:{value.lineno} ek.traversable() must receive the edge kind"
    assert ast.dump(value.args[0]) == ast.dump(kind), f"{path}:{value.lineno} must use the same edge kind"


def test_edge_constants_match_schema_relationship_kinds():
    schema_edges = set(_schema_traversability())
    constant_edges = set(_edge_constants().values())

    assert constant_edges == schema_edges


def test_traversable_helper_reads_schema_values():
    from openhound_okta.kinds import edges as ek

    for edge_name, is_traversable in _schema_traversability().items():
        assert ek.traversable(edge_name) is is_traversable


def test_model_traversable_values_come_from_schema():
    for path in sorted((SRC / "openhound_okta" / "models").glob("*.py")):
        tree = ast.parse(path.read_text())

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            if _call_name(node.func) == "EdgeDef":
                kind = _keyword(node, "kind")
                traversable = _keyword(node, "traversable")
                if kind and traversable:
                    _assert_schema_traversable_call(traversable.value, kind.value, path)

            if _call_name(node.func) != "Edge":
                continue

            kind = _keyword(node, "kind")
            properties = _keyword(node, "properties")
            if not kind or not properties or not isinstance(properties.value, ast.Call):
                continue
            if _call_name(properties.value.func) != "EdgeProperties":
                continue

            traversable = _keyword(properties.value, "traversable")
            if traversable:
                _assert_schema_traversable_call(traversable.value, kind.value, path)
