"""JSON Schema check (jsonschema 2020-12). Returns [(where, message)].

CI installs the pinned version from tools/requirements.txt. Without the library this reports one error
instead of silently passing.
"""


def check(schema, records):
    try:
        from jsonschema import Draft202012Validator
    except ImportError:
        return [("", "jsonschema が未インストール（pip install -r tools/requirements.txt）")]
    Draft202012Validator.check_schema(schema)
    out = []
    for e in Draft202012Validator(schema).iter_errors(records):
        path = list(e.absolute_path)
        rid = records[path[0]].get("id") or records[path[0]].get("source_id") if path and isinstance(path[0], int) else ""
        out.append((f":{rid}:{'/'.join(map(str, path[1:]))}", e.message[:200]))
    return out
