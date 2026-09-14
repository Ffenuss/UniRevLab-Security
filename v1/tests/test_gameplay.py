

def test_package_evidence_scans_nested_split_apks(tmp_path):
    import zipfile
    from modkit.mobile.gameplay import scan_apk_package_evidence
    base=tmp_path/'base.apk'; feature=tmp_path/'feature_game.apk'; apkset=tmp_path/'installed-apk-set.zip'
    with zipfile.ZipFile(base,'w') as z:
        z.writestr('AndroidManifest.xml',b'x')
        z.writestr('classes.dex',b'dex\n035\0 ordinary')
    with zipfile.ZipFile(feature,'w') as z:
        z.writestr('AndroidManifest.xml',b'x')
        z.writestr('assets/StreamingAssets/progression.lua',b'hero level cooldown diamond')
    with zipfile.ZipFile(apkset,'w') as z:
        z.write(base,'base.apk'); z.write(feature,'feature_game.apk')
    rows=scan_apk_package_evidence(apkset)
    assert any(str(x.get('artifact','')).startswith('feature_game.apk!') for x in rows)
    assert any('progression.lua' in str(x.get('artifact','')) and x.get('kind')=='script/content-layer' for x in rows)
