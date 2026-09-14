"""Optional driver for Il2CppDumper (https://github.com/Perfare/Il2CppDumper).

`dump.cs` is the highest-signal artifact for a menu build, so `modkit dump` prefers a
real dumper when one is available and falls back to the native metadata parser otherwise.
The only contract is: give back a `dump.cs` in `--out`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class DumperResult:
    ok: bool
    dump_cs: Path | None
    log: str
    tool: str
    skipped: str | None = None


def find_dotnet() -> str | None:
    return shutil.which("dotnet")


def find_dumper(home: Path | str | None = None) -> Path | None:
    """Look for Il2CppDumper.dll / Il2CppDumper(.exe|bin) in the usual places."""
    env = os.environ.get("IL2CPPDUMPER")
    cands: list[Path] = []
    if env:
        cands.append(Path(env))
    if home:
        cands.append(Path(home))
    else:
        for base in (Path.cwd(), Path.home() / "tools", Path("/opt")):
            for name in ("Il2CppDumper", "il2cppdumper", "Il2CppDumper-net6.0"):
                cands.extend(sorted(base.glob(f"{name}*/Il2CppDumper.dll")))
                cands.extend(sorted(base.glob(f"{name}*")))
    for c in cands:
        if c.is_dir():
            for probe in ("Il2CppDumper.dll", "net6.0/Il2CppDumper.dll", "net8.0/Il2CppDumper.dll"):
                if (c / probe).exists():
                    return c / probe
        elif c.exists() and c.name.lower().endswith((".dll", "dumper")):
            return c
    return None


def run(metadata: Path, so: Path, out: Path, *, dumper: Path | None = None,
        dotnet: str | None = None, config: Path | None = None, timeout: int = 900) -> DumperResult:
    """Invoke Il2CppDumper. `out` is the directory that will receive dump.cs."""
    out.mkdir(parents=True, exist_ok=True)
    dumper = dumper or find_dumper()
    if dumper is None:
        return DumperResult(False, None, "", "il2cppdumper",
                           skipped="Il2CppDumper not found; set $IL2CPPDUMPER or pass --dumper")

    dotnet = dotnet or find_dotnet()
    if dumper.suffix == ".dll":
        if dotnet is None:
            return DumperResult(False, None, "", str(dumper), skipped="dotnet runtime not found")
        cmd = [dotnet, str(dumper), str(so), str(metadata), str(out)]
    else:
        cmd = [str(dumper), str(so), str(metadata), str(out)]
    if config:
        cmd.append(str(config))

    env = dict(os.environ, DOTNET_CLI_TELEMETRY_OPTOUT="1", DOTNET_NOLOGO="1")
    try:
        proc = subprocess.run(cmd, cwd=str(out), capture_output=True, text=True,
                              timeout=timeout, env=env)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return DumperResult(False, None, f"{type(exc).__name__}: {exc}", str(dumper))

    log = (proc.stdout or "") + "\n" + (proc.stderr or "")
    (out / "dumper.log").write_text(log, encoding="utf-8")
    produced = [p for p in (out / "dump.cs", out / "dump" / "dump.cs") if p.exists()]
    if not produced:
        # some builds ask for input interactively; feed the classic 1/2 answer and retry
        retry = _interactive(dumper, dotnet, so, metadata, out, config)
        produced = [p for p in (out / "dump.cs", out / "dump" / "dump.cs") if p.exists()]
        if not produced:
            return DumperResult(False, None, log or retry, str(dumper),
                                skipped=f"exit={proc.returncode}, no dump.cs produced")
    return DumperResult(True, produced[0], log, str(dumper))


def _interactive(dumper: Path, dotnet: str | None, so: Path, metadata: Path,
                 out: Path, config: Path | None) -> str:
    """Old Il2CppDumper builds prompt for 'dummy dlls' (1/2) — answer 2, no refs needed."""
    cmd = ([dotnet, str(dumper)] if dotnet and dumper.suffix == ".dll" else [str(dumper)])
    cmd += [str(so), str(metadata), str(out)] + ([str(config)] if config else [])
    try:
        p = subprocess.run(cmd, input="2\n", cwd=str(out), capture_output=True, text=True, timeout=600)
        return (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"{type(exc).__name__}: {exc}"


def gh_release_hint() -> str:
    return ("get the dumper with:  dotnet tool install -g Il2CppDumper   "
            "or grab a release build and export IL2CPPDUMPER=/path/to/Il2CppDumper.dll")
