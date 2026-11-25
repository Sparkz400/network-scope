#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright the Network Scope contributors
# SPDX-License-Identifier: MIT
"""Checks the research exports with independent implementations (ROADMAP L67).

Run `network-scope-cli research export ...` into one directory first:

  research export stix  --output DIR/bundle.json
  research export ocsf  --output DIR/events.ndjson
  research export parquet --output DIR/pq     research export ndjson --output DIR/nd

then, in a virtual environment with `pip install pyarrow duckdb stix2-validator stix2 jsonschema`:

  python -I scripts/validate_research_exports.py DIR --ocsf-schema export.json

* Parquet: every table is read with pyarrow and DuckDB and compared with the NDJSON export.
* STIX 2.1: `stix2-validator` must report no error; the ids of the observables are compared with
  the ones the `stix2` library computes.
* OCSF 1.3.0: `export.json` is the compiled schema of the OCSF schema server
  (https://schema.ocsf.io/1.3.0/export/schema, built from github.com/ocsf/ocsf-schema, tag
  v1.3.0). It is turned into one JSON Schema per event class (unknown attributes refused,
  required attributes and the `at_least_one` constraints enforced, enum values and scalar types
  checked, profile attributes only with the profile) and the events are validated with
  `jsonschema`.

Any package that is not installed skips its check with a message; exit code 1 on a failure.
"""
import argparse
import importlib
import importlib.metadata
import json
import os
import sys

failures = []


def version(package):
    return importlib.metadata.version(package)


def check_parquet(work):
    try:
        import duckdb
        import pyarrow.parquet as pq
    except ImportError as e:
        return print("parquet: skipped,", e)
    manifest = json.load(open(os.path.join(work, "pq", "manifest.json"), encoding="utf-8"))
    for t in manifest["tables"]:
        path = os.path.join(work, "pq", t["file"])
        got = pq.read_table(path).to_pylist()
        want = [json.loads(line) for line in open(os.path.join(work, "nd", t["table"] + ".ndjson"), encoding="utf-8")]
        counted = duckdb.sql(f"select count(*) from read_parquet('{path}')").fetchall()[0][0]
        ok = got == want and counted == len(want)
        print(f"parquet {t['table']}: {len(got)} rows, pyarrow == ndjson: {got == want}, duckdb count {counted}")
        if not ok:
            failures.append("parquet " + t["table"])
    print(f"parquet: pyarrow {version('pyarrow')}, duckdb {version('duckdb')}")


def check_stix(path):
    try:
        import stix2
        from stix2validator import ValidationOptions, validate_file
    except ImportError as e:
        return print("stix: skipped,", e)
    result = validate_file(path, ValidationOptions(version="2.1", verbose=True))
    errors = [str(e) for r in result.object_results for e in r.errors]
    warnings = [str(w) for r in result.object_results for w in r.warnings]
    print(f"stix: is_valid={result.is_valid}, {len(errors)} errors, {len(warnings)} warnings (stix2-validator {version('stix2-validator')})")
    if not result.is_valid:
        failures.append("stix validator")
    bundle = json.load(open(path, encoding="utf-8"))
    same = different = 0
    for o in bundle["objects"]:
        if o["type"] not in ("ipv4-addr", "ipv6-addr", "mac-addr", "software"):
            continue
        props = {k: v for k, v in o.items() if k not in ("type", "spec_version", "id")}
        library = stix2.parse({"type": o["type"], "spec_version": "2.1", **props}).id
        if library == o["id"]:
            same += 1
        else:
            different += 1
            failures.append("stix id " + o["id"])
    print(f"stix: {same} observable ids equal to stix2 {version('stix2')}, {different} different")


def check_ocsf(path, schema_path):
    try:
        import jsonschema
    except ImportError as e:
        return print("ocsf: skipped,", e)
    export = json.load(open(schema_path, encoding="utf-8"))
    objects, classes = export["objects"], export["classes"]
    scalars = {
        "string_t": {"type": "string"}, "integer_t": {"type": "integer"}, "long_t": {"type": "integer"},
        "timestamp_t": {"type": "integer"}, "boolean_t": {"type": "boolean"}, "float_t": {"type": "number"},
        "port_t": {"type": "integer", "minimum": 0, "maximum": 65535},
        "ip_t": {"type": "string", "oneOf": [{"format": "ipv4"}, {"format": "ipv6"}]},
        "mac_t": {"type": "string", "pattern": "^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$"},
        "json_t": {},
    }

    def scalar(name):
        return scalars.get(name, {"type": "string"})

    def attribute(a):
        if a["type"] == "object_t":
            s = {"$ref": "#/$defs/" + a["object_type"]} if a["object_type"] != "object" else {"type": "object"}
        else:
            s = dict(scalar(a["type"]))
            if "enum" in a:
                s["enum"] = [int(k) if a["type"] in ("integer_t", "long_t") else k for k in a["enum"]]
        return {"type": "array", "items": s} if a.get("is_array") else s

    def shape(definition, profiles):
        props, required = {}, []
        for name, a in definition["attributes"].items():
            if a.get("profile") and a["profile"] not in profiles:
                continue
            props[name] = attribute(a)
            if a.get("requirement") == "required":
                required.append(name)
        out = {"type": "object", "properties": props, "required": required, "additionalProperties": False}
        constraints = definition.get("constraints") or {}
        if "at_least_one" in constraints:
            out["anyOf"] = [{"required": [n]} for n in constraints["at_least_one"]]
        if "just_one" in constraints:
            out["oneOf"] = [{"required": [n]} for n in constraints["just_one"]]
        return out

    def schema_of(cls, profiles):
        defs, todo = {}, []

        def collect(attributes):
            for a in attributes.values():
                if a["type"] == "object_t" and a["object_type"] != "object" and a["object_type"] not in defs:
                    defs[a["object_type"]] = None
                    todo.append(a["object_type"])

        collect(cls["attributes"])
        while todo:
            name = todo.pop()
            defs[name] = shape(objects[name], profiles)
            collect(objects[name]["attributes"])
        s = shape(cls, profiles)
        s["$defs"] = defs
        return s

    events = [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]
    bad = 0
    for n, e in enumerate(events, 1):
        cls = next((c for c in classes.values() if c["uid"] == e.get("class_uid")), None)
        if cls is None:
            errors = ["unknown class_uid"]
        else:
            validator = jsonschema.Draft202012Validator(
                schema_of(cls, set(e.get("metadata", {}).get("profiles", []))), format_checker=jsonschema.FormatChecker()
            )
            errors = [f"{'/'.join(map(str, x.absolute_path)) or '<event>'}: {x.message}"[:200] for x in validator.iter_errors(e)]
            if e.get("type_uid") != e["class_uid"] * 100 + e.get("activity_id", -1):
                errors.append("type_uid is not class_uid * 100 + activity_id")
        if errors:
            bad += 1
            print(f"ocsf event {n} (class {e.get('class_uid')}) invalid:", *errors, sep="\n    ")
    print(f"ocsf: {len(events)} events, {bad} invalid (schema OCSF {export['version']}, jsonschema {version('jsonschema')})")
    if bad:
        failures.append("ocsf events")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("directory")
    ap.add_argument("--ocsf-schema", help="export.json of the OCSF 1.3.0 schema server")
    args = ap.parse_args()
    check_parquet(args.directory)
    check_stix(os.path.join(args.directory, "bundle.json"))
    if args.ocsf_schema:
        check_ocsf(os.path.join(args.directory, "events.ndjson"), args.ocsf_schema)
    else:
        print("ocsf: skipped, no --ocsf-schema")
    if failures:
        print("FAILED:", ", ".join(failures))
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    main()
