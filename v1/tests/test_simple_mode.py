import json, zipfile
from pathlib import Path
from modkit.mobile.simple_mode import detect_engines, build_catalog, filter_menu_spec


def test_detects_cocos_creator_lua_and_dex(tmp_path):
    apk=tmp_path/'game.apk'
    with zipfile.ZipFile(apk,'w') as z:
        z.writestr('classes.dex',b'dex\n035\x00')
        z.writestr('lib/arm64-v8a/libcocos2dcpp.so',b'\x7fELF')
        z.writestr('assets/src/main.js','x')
        z.writestr('assets/jsb-adapter/web-adapter.js','x')
        z.writestr('assets/res/skill.lua','return 1')
        z.writestr('assets/main.scene','{}')
    r=detect_engines([apk])
    assert 'cocos2dx_cpp' in r['detected']
    assert 'cocos2dx_js' in r['detected']
    assert 'cocos_creator' in r['detected']
    assert 'lua_runtime' in r['detected']
    assert 'android_dex' in r['detected']


def test_catalog_shows_ready_review_and_server_audit(tmp_path):
    (tmp_path/'menu-spec.json').write_text(json.dumps({'controls':[
        {'id':'speed','title':'Speed','category':'Gameplay','type':'slider','rva':4096,'binding':'float_setter'},
        {'id':'probe','title':'HP watch','category':'Gameplay','type':'label','probe_kind':'field-watch','rva':8192},
        {'id':'purchase','title':'Premium entitlement server','category':'Purchase','type':'toggle','rva':12288,'binding':'bool_setter'},
    ]}),encoding='utf-8')
    out=build_catalog(tmp_path)
    by={c['menuControlId']:c for c in out['cards'] if c.get('menuControlId')}
    assert by['speed']['status']=='READY' and by['speed']['buildable']
    assert by['probe']['status']=='READ_ONLY_PROBE' and not by['probe']['buildable']
    assert by['purchase']['status']=='SERVER_AUDIT' and not by['purchase']['buildable']


def test_filter_menu_spec_keeps_only_validated_local_controls(tmp_path):
    p=tmp_path/'menu.json'
    p.write_text(json.dumps({'title':'x','controls':[
        {'id':'speed','title':'Speed','type':'slider','rva':1,'binding':'float_setter'},
        {'id':'premium','title':'Server premium','category':'Billing','type':'toggle','rva':2,'binding':'bool_setter'},
        {'id':'review','title':'Review','type':'toggle','evidence_rva':3},
    ]}),encoding='utf-8')
    r=filter_menu_spec(p,json.dumps(['speed','premium','review']))
    assert r['requested']==3 and r['buildable']==1
    raw=json.loads(p.read_text())
    assert [c['id'] for c in raw['controls']]==['speed']
