"""Command line entry point: `python -m modkit <command>` / `modkit <command>`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from modkit import MODKIT_BANNER
from modkit.analyze.rules import dump_builtin, load as load_rules, validate as validate_rules
from modkit.codegen.project import (BuildOptions, Inputs, apply_patch_plan, build_plan,
                                    load_program, render_plan, verify_plan, write_project)
from modkit.elf.reader import ElfFile
from modkit.metadata.reader import MetadataFile

HERE = Path(__file__).resolve().parent
DEFAULT_RULES = HERE.parent / "rules" / "default.json"


def _paths(args) -> Inputs:
    return Inputs(metadata=Path(args.metadata) if args.metadata else None,
                  so=Path(args.so) if args.so else None,
                  dump=Path(args.dump) if args.dump else None,
                  il2cppdumper=Path(args.dumper) if args.dumper else None)


def _rules(args):
    path = Path(args.rules) if args.rules else (DEFAULT_RULES if DEFAULT_RULES.exists() else None)
    return load_rules(path)


# --------------------------------------------------------------------------- commands


def cmd_inspect(args) -> int:
    payload: dict = {"tool": MODKIT_BANNER}
    if args.metadata:
        try:
            payload["global-metadata.dat"] = MetadataFile.open(args.metadata).identify()
        except (ValueError, OSError) as exc:
            payload["global-metadata.dat"] = {"error": str(exc)}
    if args.so:
        try:
            payload["libil2cpp.so"] = ElfFile.open(args.so).info()
        except (ValueError, OSError) as exc:
            payload["libil2cpp.so"] = {"error": str(exc)}
    if args.dump:
        prog, notes = load_program(_paths(args), allow_dumper=False)
        payload["dump.cs"] = {**prog.summary(), "notes": notes}
    print(json.dumps(payload, indent=2))
    return 0


def cmd_dump(args) -> int:
    from modkit.dumper import runner
    so = Path(args.so)
    out = Path(args.out) if args.out else so.parent / "modkit-dump"
    res = runner.run(Path(args.metadata), so, out,
                     dumper=Path(args.dumper) if args.dumper else None)
    if not res.ok:
        print(f"dumper unavailable: {res.skipped}", file=sys.stderr)
        print(runner.gh_release_hint(), file=sys.stderr)
        print("modkit still works from an existing dump.cs (--dump), or in names-only mode "
              "from the metadata file alone.", file=sys.stderr)
        return 2
    print(f"dump.cs -> {res.dump_cs}")
    return 0


def cmd_analyze(args) -> int:
    prog, notes = load_program(_paths(args), allow_dumper=not args.no_dumper)
    plan = build_plan(prog, _rules(args), notes=notes)
    text = plan.to_json()
    if args.json and args.json != "-":
        Path(args.json).write_text(text, encoding="utf-8")
        print(f"plan -> {args.json} ({len(plan.features)} features)")
    else:
        print(render_plan(plan, limit=args.limit))
    return 0


def cmd_build(args) -> int:
    prog, notes = load_program(_paths(args), allow_dumper=not args.no_dumper)
    plan = build_plan(prog, _rules(args), notes=notes)
    if not plan.features:
        print("no features matched: either the dump has no RVA column (mismatched .so) or the "
              "target renames its symbols — teach modkit the names in the rules json "
              "(`modkit rules --init my-rules.json`).", file=sys.stderr)
    opts = BuildOptions(package=args.package, app_name=args.app, abi=args.abi,
                        overlay=not args.no_overlay, imgui=args.imgui, dobby=args.dobby,
                        force=args.force)
    out = Path(args.out) if args.out else Path.cwd() / f"{opts.app_name}-module"
    written = write_project(plan, out, opts)
    print(f"{MODKIT_BANNER}: {len(plan.features)} features, {len(written)} files -> {out}")
    for p in written:
        print(f"  {p.relative_to(out)}")
    if args.verify and args.so:
        print("\nverify:")
        for line in verify_plan(plan, Path(args.so)):
            print(f"  {line}")
    return 0


def cmd_verify(args) -> int:
    prog, _ = load_program(_paths(args), allow_dumper=False)
    plan = build_plan(prog, _rules(args))
    problems = verify_plan(plan, Path(args.so)) if args.so else ["--so is required to verify"]
    for line in problems:
        print(line)
    hard = [p for p in problems if not p.startswith("ok:")]
    return 1 if hard else 0


def cmd_apply(args) -> int:
    dest = apply_patch_plan(Path(args.so), Path(args.plan), Path(args.out) if args.out else None)
    print(f"patched copy -> {dest}")
    return 0


def cmd_rules(args) -> int:
    if args.init:
        print(f"default rules -> {dump_builtin(args.init)}")
        return 0
    path = Path(args.rules) if args.rules else DEFAULT_RULES
    if not path.exists():
        print(f"{path} missing", file=sys.stderr)
        return 2
    problems = validate_rules(path)
    for p in problems:
        print(f"  {p}")
    print(f"{path}: {'ok' if not problems else f'{len(problems)} problem(s)'}")
    return 0 if not problems else 1


def cmd_runtime_check(args) -> int:
    from modkit.selftest import compile_builtin_runtime
    try:
        result = compile_builtin_runtime()
    except AssertionError as exc:
        print(f"runtime-check FAILED: {exc}", file=sys.stderr)
        return 1
    print("runtime-check ok: " + ", ".join(result))
    return 0


def cmd_selftest(args) -> int:
    from modkit import selftest
    try:
        report = selftest.run(Path(args.keep) if args.keep else None, compile=not args.no_compile)
    except AssertionError as exc:
        print(f"selftest FAILED: {exc}", file=sys.stderr)
        return 1
    print(f"selftest ok ({report['dump']['classes']} types, {report['dump']['methods']} methods, "
          f"{len(report['features'])} features, {len(report['files'])} files)")
    print("  metadata: " + json.dumps(report["metadata"]))
    print("  compile:  " + ", ".join(report.get("compile", [])))
    if args.keep:
        print(f"  project kept in {args.keep}")
    return 0


# --------------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="modkit", description="offline Il2Cpp mod-menu generator")
    ap.add_argument("--version", action="version", version=MODKIT_BANNER)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(sp: argparse.ArgumentParser, *, inputs: bool = True) -> None:
        if inputs:
            sp.add_argument("--metadata", "-m", help="global-metadata.dat")
            sp.add_argument("--so", "-s", help="libil2cpp.so")
            sp.add_argument("--dump", "-d", help="dump.cs (recommended: skips the dumper)")
            sp.add_argument("--dumper", help="path to Il2CppDumper.dll or its directory")
            sp.add_argument("--no-dumper", action="store_true", help="never invoke Il2CppDumper")
        sp.add_argument("--rules", "-r", help="rules json (default: rules/default.json)")
        sp.add_argument("-v", "--verbose", action="store_true")

    sp = sub.add_parser("inspect", help="report what the input files actually are")
    common(sp)
    sp.set_defaults(func=cmd_inspect)

    sp = sub.add_parser("dump", help="run Il2CppDumper to produce dump.cs")
    sp.add_argument("--metadata", "-m", required=True)
    sp.add_argument("--so", "-s", required=True)
    sp.add_argument("--out", "-o")
    sp.add_argument("--dumper")
    sp.set_defaults(func=cmd_dump)

    sp = sub.add_parser("analyze", help="print the feature plan, write no code")
    common(sp)
    sp.add_argument("--json", help="also write the plan json here ('-' for stdout)")
    sp.add_argument("--limit", type=int, default=40)
    sp.set_defaults(func=cmd_analyze)

    sp = sub.add_parser("build", help="generate the Android module")
    common(sp)
    sp.add_argument("--out", "-o", help="destination directory")
    sp.add_argument("--package", default="com.example.game", help="target applicationId")
    sp.add_argument("--app", default="modmenu", help="module name -> lib<app>.so")
    sp.add_argument("--abi", default="arm64-v8a")
    sp.add_argument("--no-overlay", action="store_true", help="JNI console only, no egl hook")
    sp.add_argument("--imgui", action="store_true", help="third_party/imgui is vendored")
    sp.add_argument("--dobby", action="store_true", help="link third_party/dobby for hooks")
    sp.add_argument("--verify", action="store_true", help="cross-check every rva against --so")
    sp.add_argument("--force", action="store_true")
    sp.set_defaults(func=cmd_build)

    sp = sub.add_parser("verify", help="check plan offsets against the .so")
    common(sp)
    sp.set_defaults(func=cmd_verify)

    sp = sub.add_parser("apply", help="bake patch_plan.json into a copy of libil2cpp.so")
    sp.add_argument("--so", "-s", required=True)
    sp.add_argument("--plan", "-p", required=True)
    sp.add_argument("--out", "-o")
    sp.set_defaults(func=cmd_apply)

    sp = sub.add_parser("selftest", help="run the whole pipeline against a synthetic target")
    sp.add_argument("--keep", help="write the sample project here instead of a temp dir")
    sp.add_argument("--no-compile", action="store_true", help="skip the host g++ type-check")
    sp.set_defaults(func=cmd_selftest)

    sp = sub.add_parser("runtime-check", help="strict host compile-check of the Android generic runtime v2")
    sp.set_defaults(func=cmd_runtime_check)

    sp = sub.add_parser("rules", help="lint or scaffold a rules file")
    sp.add_argument("--rules", "-r")
    sp.add_argument("--init", help="write the built-in defaults to this path")
    sp.set_defaults(func=cmd_rules)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, KeyError) as exc:
        print(f"modkit: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
