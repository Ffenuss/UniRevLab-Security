"""Unified analyzer/decompiler/runtime engine registry for ModKit 1.0."""

from .builtin import build_default_registry


def catalog():
    return build_default_registry().catalog()


def catalog_json(indent: int = 2) -> str:
    return build_default_registry().catalog_json(indent=indent)


def capability_matrix():
    return build_default_registry().capability_matrix()


__all__ = ["catalog", "catalog_json", "capability_matrix", "build_default_registry"]
