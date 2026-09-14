import json
import struct
import zipfile
from pathlib import Path

from modkit.mobile.apkset import inspect_apk_paths


def _apk(path: Path, entries):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", b"manifest")
        for name, data in entries.items():
            z.writestr(name, data)


def _metadata(version=29):
    return struct.pack("<II", 0xFAB11BAF, version) + b"M" * 128


def _arm64_elf():
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = 2  # ELF64
    header[5] = 1  # little endian
    struct.pack_into("<H", header, 18, 183)  # EM_AARCH64
    return bytes(header) + b"I" * 128


def test_installed_apk_set_selects_metadata_from_base_and_arm64_libil2cpp_from_split(tmp_path):
    base = tmp_path / "base.apk"
    arm64 = tmp_path / "split_config.arm64_v8a.apk"
    _apk(base, {
        "classes.dex": b"dex\n035\0" + b"x" * 64,
        "assets/bin/Data/Managed/Metadata/global-metadata.dat": _metadata(),
    })
    _apk(arm64, {"lib/arm64-v8a/libil2cpp.so": _arm64_elf()})
    meta = tmp_path / "metadata.bin"
    lib = tmp_path / "library.so"
    report = tmp_path / "installed.json"
    result = json.loads(inspect_apk_paths(json.dumps([str(base), str(arm64)]), meta, lib, report))
    assert result["fullIl2cppPair"] is True
    assert result["pairConfidence"] == "HIGH"
    assert result["mode"] == "il2cpp-auto"
    assert result["selected"]["metadata"]["split"] == "base.apk"
    assert result["selected"]["library"]["split"] == "split_config.arm64_v8a.apk"
    assert result["selected"]["library"]["abi"] == "arm64-v8a"
    assert meta.read_bytes().startswith(struct.pack("<I", 0xFAB11BAF))
    assert lib.read_bytes().startswith(b"\x7fELF")
    assert result["pairValidation"]["metadataRejected"] == 0
    assert result["pairValidation"]["libraryRejected"] == 0
    assert report.is_file()


def test_installed_apk_set_rejects_filename_only_fake_pair(tmp_path):
    base = tmp_path / "base.apk"
    arm64 = tmp_path / "split_config.arm64_v8a.apk"
    _apk(base, {"assets/bin/Data/Managed/Metadata/global-metadata.dat": b"not metadata"})
    _apk(arm64, {"lib/arm64-v8a/libil2cpp.so": b"not elf"})
    result = json.loads(inspect_apk_paths(json.dumps([str(base), str(arm64)])))
    assert result["fullIl2cppPair"] is False
    assert result["mode"] == "split-discovery"
    assert result["pairValidation"]["metadataRejected"] == 1
    assert result["pairValidation"]["libraryRejected"] == 1


def test_installed_apk_set_without_complete_pair_stays_split_discovery(tmp_path):
    base = tmp_path / "base.apk"
    feature = tmp_path / "feature_shop.apk"
    _apk(base, {"classes.dex": b"dex\n035\0" + b"health damage level shop purchase"})
    _apk(feature, {"assets/StreamingAssets/game.lua": b"hero inventory cooldown"})
    result = json.loads(inspect_apk_paths(json.dumps([str(base), str(feature)])))
    assert result["fullIl2cppPair"] is False
    assert result["mode"] == "split-discovery"
    assert result["summary"]["splitCount"] == 2
    assert result["summary"]["dexCount"] == 1
    assert result["summary"]["contentMarkerCount"] >= 1


def test_installed_apk_set_optional_app_discovery_is_fail_soft_on_malformed_dex(tmp_path):
    base = tmp_path / "base.apk"
    _apk(base, {"classes.dex": b"dex\n035\0" + b"x" * 64})
    result = json.loads(inspect_apk_paths(json.dumps([str(base)]), scan_trust=True))
    assert result["dexTrust"]["schema"] == "modkit-dex-trust-2"
    assert "applicationDiscovery" in result
    assert result["applicationDiscovery"]["summary"]["notFoundLocal"] >= 1


def test_apkset_reports_cocos_and_script_runtime(tmp_path):
    import json, zipfile
    from modkit.mobile.apkset import inspect_apk_paths
    apk=tmp_path/'base.apk'
    with zipfile.ZipFile(apk,'w') as z:
        z.writestr('classes.dex',b'dex\n035\x00')
        z.writestr('lib/arm64-v8a/libcocos2dcpp.so',b'\x7fELF'+b'\0'*100)
        z.writestr('assets/jsb-adapter/web-adapter.js','x')
        z.writestr('assets/src/game.jsc',b'x')
        z.writestr('assets/res/config.lua','return {}')
    out=json.loads(inspect_apk_paths(json.dumps([str(apk)])))
    e=out['engineDetection']
    assert e['cocosMarkers'] >= 2
    assert e['luaEntries'] >= 1
    assert e['jsEntries'] >= 1
    assert 'cocos-creator' in e['detected']
