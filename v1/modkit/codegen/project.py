"""Writes the generated Android module to disk, and the offline patch/verify helpers."""

from __future__ import annotations

import json
import shutil
import struct
from dataclasses import dataclass, field
from pathlib import Path

from modkit.analyze.features import analyze
from modkit.analyze.rules import RuleSet
from modkit.arch import arm64
from modkit.codegen.gen import Generator
from modkit.dumper.dumpcs import DumpParser
from modkit.elf.reader import ElfFile
from modkit.ir import FeatureKind, Plan, Program
from modkit.metadata.reader import MetadataFile


@dataclass(slots=True)
class BuildOptions:
    package: str = "com.example.game"
    app_name: str = "modmenu"
    abi: str = "arm64-v8a"
    overlay: bool = True
    imgui: bool = False
    dobby: bool = False
    force: bool = False
    autoload: bool = False
    extra: dict = field(default_factory=dict)

    def check_abi(self) -> None:
        if self.abi != "arm64-v8a":
            raise SystemExit(
                f"abi {self.abi!r} is not supported: only arm64 byte encodings are emitted. "
                "Build a Thumb-2 encoder in modkit/arch/ before trying armeabi-v7a.")


@dataclass(slots=True)
class Inputs:
    metadata: Path | None = None
    so: Path | None = None
    dump: Path | None = None
    il2cppdumper: Path | None = None

    @property
    def so_name(self) -> str:
        return self.so.name if self.so else "libil2cpp.so"


def load_program(inputs: Inputs, *, rules: RuleSet | None = None,
                 allow_dumper: bool = True, verbose: bool = False) -> tuple[Program, list[str]]:
    """Produce the IR: dump.cs first, Il2CppDumper second, metadata-only last."""
    notes: list[str] = []
    prog: Program | None = None

    if inputs.dump and inputs.dump.exists():
        parser = DumpParser()
        prog = parser.parse_file(inputs.dump, so_name=inputs.so_name)
        prog.metadata_image = inputs.metadata.name if inputs.metadata else None
        notes.append(f"dump.cs: {parser.stats.classes} types, {parser.stats.methods} methods "
                     f"({parser.stats.addressed_methods} with an RVA)")
        if parser.stats.addressed_methods == 0:
            notes.append("WARNING: dump.cs carries no RVA column — the dumper was run on a "
                         "mismatched .so; regenerate it")
    elif allow_dumper and inputs.metadata and inputs.so:
        from modkit.dumper import runner
        out = Path(inputs.so).with_suffix(".dumpdir")
        res = runner.run(inputs.metadata, inputs.so, out, dumper=inputs.il2cppdumper)
        if res.ok and res.dump_cs:
            notes.append(f"dumped with {Path(res.tool).name}")
            prog, extra = load_program(Inputs(inputs.metadata, inputs.so, res.dump_cs),
                                       allow_dumper=False)
            notes += extra
        else:
            notes.append(f"no dump.cs and dumper unavailable ({res.skipped}); {runner.gh_release_hint()}")

    if prog is None and inputs.metadata:
        meta = MetadataFile.open(inputs.metadata)
        prog = meta.build_program()
        prog.source = f"global-metadata.dat v{meta.version} (names only)"
        prog.metadata_version = meta.version
        notes.append(f"metadata-only mode: v{meta.version} ({meta.unity}); RVAs are unknown, "
                     "so only name-based candidates are produced — supply dump.cs for a buildable menu")

    if prog is None:
        raise SystemExit("nothing to analyse: pass --dump, or --metadata (with --so)")

    if inputs.metadata:
        try:
            meta = MetadataFile.open(inputs.metadata)
            prog.metadata_version = prog.metadata_version or meta.version
            for n in meta.cross_check({"metadata_version": prog.metadata_version,
                                        **prog.summary()}):
                notes.append(f"cross-check: {n}")
        except (ValueError, KeyError) as exc:
            notes.append(f"metadata cross-check skipped: {exc}")

    if inputs.so and inputs.so.exists():
        elf = ElfFile.open(inputs.so)
        info = elf.info()
        notes.append(f"libil2cpp: {info['arch']}, {'PIE' if info['pie'] else 'non-PIE'}, "
                     f".text=0x{info['text_size']:x}, {info['symbols']} symbols")
        if not elf.is_arm64():
            notes.append("ERROR: libil2cpp.so is not aarch64 — the generated patches would be wrong")
        if not elf.is_pie:
            notes.append("note: non-PIE .so: the runtime base is fixed, rva() still works")
        for lib in ("libdobby.so", "libxposed.so", "libfrida-gadget.so"):
            if lib in info["needed"]:
                notes.append(f"note: {lib} in DT_NEEDED — this .so was already modified")
    return prog, notes


def build_plan(prog: Program, rules: RuleSet, *, notes: list[str] | None = None) -> Plan:
    plan = analyze(prog, rules)
    if notes:
        plan.notes.extend(notes)
    return plan


def write_project(plan: Plan, out: Path, opts: BuildOptions) -> list[Path]:
    opts.check_abi()
    out = Path(out)
    if out.exists() and any(out.iterdir()) and not opts.force:
        raise SystemExit(f"{out} is not empty (use --force to overwrite)")
    if out.exists() and opts.force:
        shutil.rmtree(out)
    gen = Generator(plan, package=opts.package, app_name=opts.app_name, abi=opts.abi,
                    overlay=opts.overlay, imgui=opts.imgui, dobby=opts.dobby, autoload=opts.autoload)
    written: list[Path] = []
    for rel, content in gen.files().items():
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        if rel.endswith(".sh"):
            p.chmod(0o755)
        written.append(p)
    (out / "third_party").mkdir(parents=True, exist_ok=True)
    (out / "third_party" / "README.md").write_text(
        "Vendor here:\n\n"
        "* `imgui/`  — https://github.com/ocornut/imgui (docking branch is fine)\n"
        "* `dobby/`   — https://github.com/jmp03/Dobby, enables MODKIT_HAVE_DOBBY\n\n"
        "Both are optional: without imgui the loader console drives the module, without\n"
        "dobby the built-in arm64 inline hooker is used and refuses PC-relative prologues.\n",
        encoding="utf-8")
    return written


# --------------------------------------------------------------------------- checks


def verify_plan(plan: Plan, so: Path) -> list[str]:
    """Static plausibility check of every recorded RVA against the real .so."""
    problems: list[str] = []
    if not so or not Path(so).exists():
        return ["libil2cpp.so not given — cannot verify offsets"]
    elf = ElfFile.open(Path(so))
    text = elf.section(".text")
    used: dict[int, list[str]] = {}
    for f in plan.features:
        if not f.rva or f.kind is FeatureKind.FIELD_WRITE:
            continue          # instance offsets are checked at runtime, not here
        used.setdefault(f.rva, []).append(f.id)
        if text and not (text.addr <= f.rva < text.addr + text.size):
            if f.kind is FeatureKind.STATIC_WRITE:
                if elf.rva_to_off(f.rva) is None:
                    problems.append(f"{f.id}: static storage 0x{f.rva:x} is not a mapped rva")
                continue
            problems.append(f"{f.id}: rva 0x{f.rva:x} is outside .text")
            continue
        try:
            head = elf.read_at_rva(f.rva, 4)
        except ValueError as exc:
            problems.append(f"{f.id}: unreadable ({exc})")
            continue
        if len(head) < 4:
            problems.append(f"{f.id}: rva 0x{f.rva:x} is past the end of the file")
            continue
        (word,) = struct.unpack("<I", head)
        if word == 0:
            problems.append(f"{f.id}: rva 0x{f.rva:x} decodes to .word 0 — wrong .so or stale dump")
        if f.kind is FeatureKind.CONST_RETURN:
            room = (text.addr + text.size - f.rva) if text else 0
            need = len(f.patch.bytes) if f.patch else 16
            if room < need:
                problems.append(f"{f.id}: only {room} bytes left in .text, patch needs {need}")
    for rva, ids in used.items():
        if len(ids) > 1:
            problems.append(f"rva 0x{rva:x} claimed by {len(ids)} features: {', '.join(ids)}")
    return problems or [f"ok: {len(used)} distinct rvas checked against {so.name}"]


def apply_patch_plan(so: Path, plan_json: Path, out: Path | None = None) -> Path:
    """Rewrite libil2cpp.so with the const-return patches baked in (offline/repack flow)."""
    data = json.loads(Path(plan_json).read_text(encoding="utf-8"))
    elf = ElfFile.open(Path(so))
    count = 0
    for item in data.get("patches", []):
        rva = int(item["rva"], 16) if isinstance(item["rva"], str) else int(item["rva"])
        blob = bytes.fromhex(item["bytes"])
        old = elf.read_at_rva(rva, len(blob))
        item["restore"] = old.hex()
        elf.write_at_rva(rva, blob)
        count += 1
    dest = Path(out) if out else Path(so).with_suffix(".patched.so")
    dest.write_bytes(elf.blob)
    Path(str(plan_json).replace("patch_plan", "patch_plan.restore")).write_text(
        json.dumps(data, indent=2), encoding="utf-8")
    return dest


def render_plan(plan: Plan, *, limit: int = 40) -> str:
    """Human-readable plan, used by `modkit analyze` and CI logs."""
    from collections import OrderedDict
    groups: "OrderedDict[str, list]" = OrderedDict()
    for f in plan.features:
        groups.setdefault(f.group, []).append(f)
    lines = [f"plan: {len(plan.features)} features from {plan.program.summary()['classes']} types"]
    for group, feats in groups.items():
        lines.append(f"\n[{group}]")
        for f in feats[:limit]:
            addr = f"0x{f.rva:x}" if f.rva else "—"
            extra = ""
            if f.patch:
                extra = f"  [{f.patch.bytes.hex()}]"
            flags = []
            if f.needs_instance:
                slot = next((i for i, h in enumerate(plan.instance_hooks) if h.cls == f.cls), None)
                flags.append(f"slot={slot if slot is not None else 'unresolved'}")
            if f.is_static:
                flags.append("static")
            if f.enabled_by_default:
                flags.append("auto")
            flag = (" {" + ",".join(flags) + "}") if flags else ""
            lines.append(f"  {f.kind.value:<13} {f.label:<28} {f.cls}.{f.member:<24} "
                         f"{addr:<10} conf={f.confidence:.2f}{flag}{extra}")
        if len(feats) > limit:
            lines.append(f"  … {len(feats) - limit} more")
    if plan.notes:
        lines.append("\nnotes")
        lines += [f"  - {n}" for n in plan.notes]
    return "\n".join(lines)
