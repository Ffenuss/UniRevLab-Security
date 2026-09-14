import zipfile
import pytest
from modkit.patchpack import inspect_pack, apply_pack


def _apk(path, dex):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("classes3.dex", dex)
        z.writestr("assets/a.txt", b"a")


def test_patchpack_blocks_dex_class_loss(tmp_path):
    apk = tmp_path / "game.apk"
    _apk(apk, b"dex\n035\0Lcom/example/A;Lcom/example/B;")
    pack = tmp_path / "pack.zip"
    with zipfile.ZipFile(pack, "w") as z:
        z.writestr("classes3.dex", b"dex\n035\0Lcom/example/A;")
    report = inspect_pack(apk, pack)
    assert report["blocked"]
    assert any(i["code"] == "DEX_CLASS_LOSS" for i in report["issues"])


def test_patchpack_replaces_compatible_dex(tmp_path):
    apk = tmp_path / "game.apk"
    _apk(apk, b"dex\n035\0Lcom/example/A;")
    pack = tmp_path / "pack.zip"
    with zipfile.ZipFile(pack, "w") as z:
        z.writestr("classes3.dex", b"dex\n035\0Lcom/example/A;Lcom/example/C;")
    report = inspect_pack(apk, pack)
    assert not report["blocked"]
    out = tmp_path / "out.apk"
    apply_pack(apk, pack, out)
    with zipfile.ZipFile(out) as z:
        assert b"Lcom/example/C;" in z.read("classes3.dex")


def test_patchpack_realigns_stored_native_entries(tmp_path):
    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("classes3.dex", b"dex\n035\0Lcom/example/A;")
        info = zipfile.ZipInfo("lib/arm64-v8a/libexisting.so")
        info.compress_type = zipfile.ZIP_STORED
        z.writestr(info, b"native-bytes")
    pack = tmp_path / "pack.zip"
    with zipfile.ZipFile(pack, "w") as z:
        z.writestr("classes3.dex", b"dex\n035\0Lcom/example/A;Lcom/example/C;")
    out = tmp_path / "out.apk"
    result = apply_pack(apk, pack, out)
    assert result["alignment"]["storedSo"] == 16384
    with zipfile.ZipFile(out) as z:
        info = z.getinfo("lib/arm64-v8a/libexisting.so")
        data_offset = info.header_offset + 30 + len(info.filename.encode()) + len(info.extra)
        assert data_offset % 16384 == 0


def test_patchpack_native_autoload_adds_dt_needed_without_replacing_dex(tmp_path):
    import json
    from modkit.selftest import fixtures
    from modkit.elf.reader import ElfFile

    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("classes.dex", b"dex\n035\0Lcom/example/Game;")
        z.writestr("lib/arm64-v8a/libil2cpp.so", fixtures.so_blob())

    pack = tmp_path / "pack.zip"
    with zipfile.ZipFile(pack, "w") as z:
        z.writestr("lib/arm64-v8a/libmodkit_runtime.so", fixtures.so_blob())
        z.writestr("modkit-payload.json", json.dumps({
            "schema": "modkit-payload-1.0",
            "autoload": [{
                "host": "lib/arm64-v8a/libil2cpp.so",
                "dependency": "libmodkit_runtime.so",
            }],
        }))

    report = inspect_pack(apk, pack)
    assert report["blocked"] is False
    assert report["autoload"][0]["host"].endswith("libil2cpp.so")

    out = tmp_path / "out.apk"
    apply_pack(apk, pack, out)
    with zipfile.ZipFile(out) as z:
        assert z.read("classes.dex") == b"dex\n035\0Lcom/example/Game;"
        assert "lib/arm64-v8a/libmodkit_runtime.so" in z.namelist()
        host = ElfFile(z.read("lib/arm64-v8a/libil2cpp.so"))
        assert "libmodkit_runtime.so" in host.needed()


def test_patchpack_autoload_requires_payload_library(tmp_path):
    import json
    from modkit.selftest import fixtures

    apk = tmp_path / "game.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("lib/arm64-v8a/libil2cpp.so", fixtures.so_blob())
    pack = tmp_path / "pack.zip"
    with zipfile.ZipFile(pack, "w") as z:
        z.writestr("modkit-payload.json", json.dumps({
            "schema": "modkit-payload-1.0",
            "autoload": [{"host": "lib/arm64-v8a/libil2cpp.so", "dependency": "libmodkit_runtime.so"}],
        }))
    report = inspect_pack(apk, pack)
    assert report["blocked"] is True
    assert any(i["code"] == "AUTOLOAD_DEPENDENCY_MISSING" for i in report["issues"])


def test_patchpack_safe_system_chain_fallback_when_host_has_no_dynstr_slack(tmp_path):
    import json
    from modkit.selftest import fixtures
    from modkit.elf.reader import ElfFile

    host = bytearray(fixtures.so_blob())
    elf0 = ElfFile(bytes(host))
    ds = elf0.section('.dynstr')
    # Keep only the final NUL as trailing slack, like the real Drova libil2cpp.so.
    host[ds.offset + ds.size - 128: ds.offset + ds.size - 1] = b'X' * 127
    host = bytes(host)
    with pytest.raises(ValueError, match='trailing zero bytes'):
        ElfFile(host).add_needed('libmk.so')

    apk = tmp_path / 'game.apk'
    with zipfile.ZipFile(apk, 'w') as z:
        z.writestr('lib/arm64-v8a/libil2cpp.so', host)
    pack = tmp_path / 'pack.zip'
    with zipfile.ZipFile(pack, 'w') as z:
        z.writestr('lib/arm64-v8a/libmk.so', fixtures.so_blob())
        z.writestr('modkit-payload.json', json.dumps({
            'schema': 'modkit-payload-1.0',
            'autoload': [{'host':'lib/arm64-v8a/libil2cpp.so', 'dependency':'libmk.so',
                          'strategy':'safe-system-chain'}],
        }))
    report = inspect_pack(apk, pack)
    assert report['blocked'] is False
    assert report['autoload'][0]['edit']['strategy'] == 'needed-chain'
    assert report['autoload'][0]['edit']['displacedDependency'] == 'liblog.so'
    out = tmp_path / 'out.apk'
    apply_pack(apk, pack, out)
    with zipfile.ZipFile(out) as z:
        needed = ElfFile(z.read('lib/arm64-v8a/libil2cpp.so')).needed()
        assert 'libmk.so' in needed and 'liblog.so' not in needed


def test_generated_payload_blocks_runtime_hash_tamper(tmp_path):
    from modkit.menu import MenuControl, MenuSpec, write_patch_payload
    from modkit.selftest import fixtures

    apk = tmp_path / 'game.apk'
    with zipfile.ZipFile(apk, 'w') as z:
        z.writestr('classes.dex', b'dex\n035\0Lcom/example/Game;')
        z.writestr('lib/arm64-v8a/libil2cpp.so', fixtures.so_blob())
    runtime = tmp_path / 'libmodkit_runtime.so'
    runtime.write_bytes(fixtures.so_blob())
    spec = MenuSpec('Test', controls=[MenuControl(
        'god', 'God', 'toggle', rva=0x1040, binding='bool_setter', target_so='libil2cpp.so',
    )])
    pack = tmp_path / 'payload.zip'
    write_patch_payload(spec, apk, runtime, pack)

    tampered = tmp_path / 'tampered.zip'
    with zipfile.ZipFile(pack) as zin, zipfile.ZipFile(tampered, 'w') as zout:
        for info in zin.infolist():
            blob = zin.read(info)
            if info.filename == 'lib/arm64-v8a/libmodkit_runtime.so':
                blob += b'X'
            zout.writestr(info, blob)
    report = inspect_pack(apk, tampered)
    assert report['blocked'] is True
    assert any(i['code'] == 'PAYLOAD_RUNTIME_HASH_MISMATCH' for i in report['issues'])


def test_generated_payload_is_bound_to_source_apk_hash(tmp_path):
    from modkit.menu import MenuControl, MenuSpec, write_patch_payload
    from modkit.selftest import fixtures

    apk = tmp_path / 'game.apk'
    with zipfile.ZipFile(apk, 'w') as z:
        z.writestr('classes.dex', b'dex\n035\0Lcom/example/Game;')
        z.writestr('lib/arm64-v8a/libil2cpp.so', fixtures.so_blob())
    runtime = tmp_path / 'libmodkit_runtime.so'
    runtime.write_bytes(fixtures.so_blob())
    spec = MenuSpec('Test', controls=[MenuControl(
        'god', 'God', 'toggle', rva=0x1040, binding='bool_setter', target_so='libil2cpp.so',
    )])
    pack = tmp_path / 'payload.zip'
    write_patch_payload(spec, apk, runtime, pack)

    other = tmp_path / 'other.apk'
    with zipfile.ZipFile(apk) as zin, zipfile.ZipFile(other, 'w') as zout:
        for info in zin.infolist():
            zout.writestr(info, zin.read(info))
        zout.writestr('assets/different.txt', b'different source artifact')
    report = inspect_pack(other, pack)
    assert report['blocked'] is True
    assert any(i['code'] == 'PAYLOAD_SOURCE_MISMATCH' for i in report['issues'])


def test_apply_pack_embeds_auditable_receipt(tmp_path):
    import hashlib
    import json
    from modkit.selftest import fixtures

    apk = tmp_path / 'game.apk'
    original_host = fixtures.so_blob()
    with zipfile.ZipFile(apk, 'w') as z:
        z.writestr('classes.dex', b'dex\n035\0Lcom/example/Game;')
        z.writestr('lib/arm64-v8a/libil2cpp.so', original_host)

    runtime_blob = fixtures.so_blob()
    pack = tmp_path / 'pack.zip'
    with zipfile.ZipFile(pack, 'w') as z:
        z.writestr('lib/arm64-v8a/libmk.so', runtime_blob)
        z.writestr('modkit-payload.json', json.dumps({
            'schema': 'modkit-payload-1.0',
            'autoload': [{'host':'lib/arm64-v8a/libil2cpp.so', 'dependency':'libmk.so'}],
        }))

    out = tmp_path / 'out.apk'
    result = apply_pack(apk, pack, out)
    with zipfile.ZipFile(out) as z:
        receipt_blob = z.read('assets/modkit-patch-receipt.json')
        receipt = json.loads(receipt_blob)
        assert receipt['schema'] == 'modkit-patch-receipt-1.0'
        assert receipt['sourceApkSha256'] == result['sourceApkSha256']
        assert receipt['patchPackSha256'] == result['patchPackSha256']
        by_path = {m['targetPath']: m for m in receipt['modifications']}
        host = by_path['lib/arm64-v8a/libil2cpp.so']
        runtime = by_path['lib/arm64-v8a/libmk.so']
        assert host['beforeSha256'] == hashlib.sha256(original_host).hexdigest()
        assert host['afterSha256'] == hashlib.sha256(z.read('lib/arm64-v8a/libil2cpp.so')).hexdigest()
        assert runtime['beforeSha256'] is None
        assert runtime['afterSha256'] == hashlib.sha256(runtime_blob).hexdigest()
        assert result['receiptSha256'] == hashlib.sha256(receipt_blob).hexdigest()


def test_workspace_patch_replaces_generic_apk_entry(tmp_path):
    import zipfile, json
    from modkit.patchpack.core import inspect_pack, apply_pack
    apk=tmp_path/'source.apk'
    with zipfile.ZipFile(apk,'w') as z:
        z.writestr('assets/config.json','{"value":1}')
        z.writestr('classes.dex',b'dex\n035\x00')
    pack=tmp_path/'workspace.zip'
    with zipfile.ZipFile(pack,'w') as z:
        z.writestr('files/edit.bin','{"value":2}')
        z.writestr('modkit-workspace.json',json.dumps({'schema':'modkit-workspace-patch-1.0','entries':[{'packPath':'files/edit.bin','targetPath':'assets/config.json'}]}))
    report=inspect_pack(apk,pack)
    assert not report['blocked']
    assert any(m['targetPath']=='assets/config.json' and m['kind']=='workspace' for m in report['mappings'])
    out=tmp_path/'out.apk'
    apply_pack(apk,pack,out)
    with zipfile.ZipFile(out) as z:
        assert z.read('assets/config.json')==b'{"value":2}'


def test_workspace_patch_blocks_path_traversal(tmp_path):
    import zipfile, json
    from modkit.patchpack.core import inspect_pack
    apk=tmp_path/'source.apk'
    with zipfile.ZipFile(apk,'w') as z:z.writestr('assets/a.txt','a')
    pack=tmp_path/'bad.zip'
    with zipfile.ZipFile(pack,'w') as z:
        z.writestr('files/e','x')
        z.writestr('modkit-workspace.json',json.dumps({'schema':'modkit-workspace-patch-1.0','entries':[{'packPath':'files/e','targetPath':'../x'}]}))
    r=inspect_pack(apk,pack)
    assert r['blocked']
    assert any(i['code']=='WORKSPACE_TARGET_INVALID' for i in r['issues'])
