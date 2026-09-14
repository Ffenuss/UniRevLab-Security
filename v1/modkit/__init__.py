"""modkit — offline Il2Cpp mod-menu generator.

Pipeline
--------
    global-metadata.dat ─┐
    libil2cpp.so ────────┴─> [dump.cs | native metadata] ─> IR ─> rules ─> features ─> Android module
"""

__version__ = "0.9.0-dev40"

MODKIT_BANNER = f"modkit {__version__}"
