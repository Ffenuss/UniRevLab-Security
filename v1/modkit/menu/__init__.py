import threading

from .builder import (
    MenuControl,
    MenuSpec,
    spec_from_analysis,
    write_project,
    validate_bindings,
    review_preflight as _builder_review_preflight,
    auto_confirm_bindings,
    write_patch_payload as _builder_write_patch_payload,
    detect_render_host,
    probe_spec_from_gameplay,
)
from .phase7_guard import verify_preflight_workspace


_PAYLOAD_BUILD_LOCK = threading.RLock()


def review_preflight(spec, source_apk):
    # Phase 7 is opt-in by the completed workspace audit. Legacy/non-IL2CPP flows
    # have no such audit and preserve their historical review_preflight behavior.
    verify_preflight_workspace(source_apk)
    return _builder_review_preflight(spec, source_apk)


def write_patch_payload(spec, source_apk, runtime_so, output_zip, *, host_so=None, render_host=None):
    # Repeat the exact audit immediately before payload bytes are generated. This
    # closes the preflight -> payload handoff window without changing legacy flows.
    verify_preflight_workspace(source_apk)

    # Some production Unity ELFs (including the AFK Journey sample) have no usable
    # trailing slack in .dynstr, so the conservative direct DT_NEEDED insertion in
    # builder.py cannot add libmk.so. Patch Pack already supports the safer fallback:
    # replace one allowlisted system dependency only when the runtime itself depends
    # on that displaced library, preserving host -> runtime -> system-lib. Keep the
    # fallback scoped to this serialized payload build and always restore the class
    # method so unrelated ELF analysis is unaffected.
    from pathlib import Path
    from modkit.elf.reader import ElfFile

    runtime_path = Path(runtime_so)
    runtime_needed = tuple(ElfFile(runtime_path.read_bytes()).needed()) if runtime_path.is_file() else ()
    original_add_needed = ElfFile.add_needed

    def add_needed_with_safe_chain(elf, dependency):
        try:
            return original_add_needed(elf, dependency)
        except ValueError as direct_error:
            try:
                edit = elf.replace_needed_chain(dependency, runtime_needed=runtime_needed)
            except ValueError as chain_error:
                raise ValueError(
                    f"cannot autoload {dependency}: direct DT_NEEDED insertion failed "
                    f"({direct_error}); safe dependency-chain fallback failed ({chain_error})"
                ) from chain_error
            edit["addNeededFailure"] = str(direct_error)
            return edit

    with _PAYLOAD_BUILD_LOCK:
        ElfFile.add_needed = add_needed_with_safe_chain
        try:
            return _builder_write_patch_payload(
                spec, source_apk, runtime_so, output_zip, host_so=host_so, render_host=render_host
            )
        finally:
            ElfFile.add_needed = original_add_needed


__all__ = [
    "MenuControl",
    "MenuSpec",
    "spec_from_analysis",
    "write_project",
    "validate_bindings",
    "review_preflight",
    "auto_confirm_bindings",
    "write_patch_payload",
    "detect_render_host",
    "probe_spec_from_gameplay",
]
