from __future__ import annotations

from pathlib import Path
import zipfile

from modkit.mobile import qml_deep


def _apk(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


def test_qml_deep_parses_source_structure_compiled_cache_and_rcc(tmp_path: Path):
    qml = b"""
import QtQuick 2.15
import QtQuick.Controls 2.15

Item {
    id: playerHud
    property int health: 100
    property real moveSpeed: 1.0
    signal damageTaken(int amount)

    function setHealth(value) {
        health = value
    }

    Rectangle {
        id: healthBar
    }
}
"""
    apk = _apk(tmp_path / "qt.apk", {
        "assets/qml/Main.qml": qml,
        "assets/qml/cache.qmlc": b"compiled qml cache",
        "assets/resources.rcc": b"qres" + b"\x00" * 64,
        "lib/arm64-v8a/libQt6Core.so": b"\x7fELF",
    })

    report = qml_deep.scan_apk_paths([apk])
    assert report["qmlSourceCount"] == 1
    assert report["compiledQmlCount"] == 1
    assert report["rccCount"] == 1
    assert report["nativeQtLibraryCount"] == 1
    assert report["policy"]["claimsSourceFromQmlc"] is False
    assert report["policy"]["qmlBytecodeFullyDecoded"] is False
    assert report["policy"]["rccPayloadFullyDecoded"] is False

    source = report["qmlSources"][0]
    assert source["imports"] == ["QtQuick 2.15", "QtQuick.Controls 2.15"]
    assert "Item" in source["components"]
    assert "Rectangle" in source["components"]
    assert "playerHud" in source["ids"]
    assert "healthBar" in source["ids"]
    assert any(row["name"] == "health" and row["type"] == "int" for row in source["properties"])
    assert any(row["name"] == "moveSpeed" for row in source["properties"])
    assert source["signals"][0]["name"] == "damageTaken"
    assert source["functions"][0]["name"] == "setHealth"

    rcc = report["rcc"][0]
    assert rcc["qresMagicObserved"] is True

    kinds = {row["kind"] for row in report["findings"]}
    assert "QML_SOURCE_STRUCTURE" in kinds
    assert "QML_COMPILED_ARTIFACT" in kinds
    assert "QT_RCC_CONTAINER" in kinds
    assert "QML_SEMANTIC_MEMBER" in kinds

    semantic = [row for row in report["findings"] if row["kind"] == "QML_SEMANTIC_MEMBER"]
    assert any("health" in row["semanticDomains"] for row in semantic)
    assert any("damage" in row["semanticDomains"] for row in semantic)
    assert any("speed" in row["semanticDomains"] for row in semantic)
    assert all(row["patchReady"] is False for row in report["findings"])
    assert all(row["automationExcluded"] is True for row in report["findings"])


def test_non_qres_rcc_stays_review(tmp_path: Path):
    apk = _apk(tmp_path / "qt-rcc.apk", {
        "assets/resources.rcc": b"notqres" + b"\x00" * 64,
    })
    report = qml_deep.scan_apk_paths([apk])
    row = next(item for item in report["findings"] if item["kind"] == "QT_RCC_CONTAINER")
    assert row["status"] == "REVIEW"
    assert row["qresMagicObserved"] is False
