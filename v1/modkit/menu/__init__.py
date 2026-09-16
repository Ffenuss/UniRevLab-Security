from .builder import (
    MenuControl,
    MenuSpec,
    spec_from_analysis,
    write_project,
    validate_bindings,
    review_preflight as _builder_review_preflight,
    auto_confirm_bindings,
    write_patch_payload,
    detect_render_host,
    probe_spec_from_gameplay,
)
from .phase7_guard import verify_preflight_workspace


def review_preflight(spec, source_apk):
    # Phase 7 is opt-in by the completed workspace audit. Legacy/non-IL2CPP flows
    # have no such audit and preserve their historical review_preflight behavior.
    verify_preflight_workspace(source_apk)
    return _builder_review_preflight(spec, source_apk)


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
