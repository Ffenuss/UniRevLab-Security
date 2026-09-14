"""Independent standard-layout fixture, not the original custom metadata format."""
import hashlib
import json
import struct
import zipfile
from pathlib import Path
import pytest
from modkit.mobile.engine import (
    analyze, analyze_rodroid, deep_resolve_method, deep_resolve_autopilot, export, export_apk_unsigned, export_dump, menu_seed_from_deep,
    patch_bytes, _arm64_direct_bl_calls_to_target, _symbol_tokens, _semantic_tags,
    _dump_field_discoveries, _finalize_metadata_method_catalog, _autopilot_catalog_candidates, Cancelled,
)


def test_semantic_search_tokens_do_not_match_smooth_path():
    assert 'hp' not in _symbol_tokens('SmoothPath')
    assert 'hp' in _symbol_tokens('Player_HP')
    assert 'health' in _semantic_tags('Player::get_HitPoints')


def test_dump_fields_are_discovered_but_not_marked_patchable():
    dump='''namespace Game\npublic class Player\n{\n    private float currentHealth; // 0x34\n    public int Damage { get; set; }\n}\n'''
    rows=_dump_field_discoveries(dump,100)
    assert [r['semantic'] for r in rows] == [['health'], ['damage']]
    assert rows[0]['field_offset']==0x34
    assert all(not r['selectable'] for r in rows)


def fixture(tmp_path, version=29, relocated=False, shared=False):
    meta=bytearray(0x800)
    struct.pack_into('<II',meta,0,0xFAB11BAF,version)
    strings=bytearray()
    def string(s):
        i=len(strings);strings.extend(s.encode()+b'\0');return i
    image=string('Assembly-CSharp.dll');cls=string('Player');ns=string('Example')
    names=[string('get_Health'),string('get_Speed'),string('get_Alive')]
    def region(i,off,size):struct.pack_into('<II',meta,8+i*8,off,size)
    region(2,0x100,len(strings));meta[0x100:0x100+len(strings)]=strings
    stride=36 if version==31 else 32
    region(5,0x200,3*stride);region(19,0x300,88);region(20,0x400,40)
    for i,name in enumerate(names):
        p=0x200+i*stride
        struct.pack_into('<Iii',meta,p,name,0,i)
        shift=4 if version==31 else 0
        struct.pack_into('<iiIHHHH',meta,p+12+shift,0,-1,0x06000001+i,6,0,0,0)
    struct.pack_into('<II',meta,0x300,cls,ns)
    struct.pack_into('<i',meta,0x300+24,-1)
    struct.pack_into('<i',meta,0x300+36,0)
    struct.pack_into('<H',meta,0x300+64,3)
    struct.pack_into('<IiII',meta,0x400,image,0,0,1)
    mp=tmp_path/'global-metadata.dat';mp.write_bytes(meta)
    elf=bytearray(0x5000);elf[:6]=b'\x7fELF\x02\x01'
    struct.pack_into('<HHI',elf,16,3,183,1)
    struct.pack_into('<Q',elf,32,64)
    struct.pack_into('<HHH',elf,52,64,56,3 if relocated else 2)
    base=0x10000
    struct.pack_into('<IIQQQQQQ',elf,64,1,5,0x1000,base+0x1000,0,0x1000,0x1000,0x1000)
    struct.pack_into('<IIQQQQQQ',elf,120,1,6,0x3000,base+0x3000,0,0x2000,0x2000,0x1000)
    for p in range(0x1000,0x1100,4):struct.pack_into('<I',elf,p,0xd503201f)
    name=b'Assembly-CSharp.dll\0';elf[0x3100:0x3100+len(name)]=name
    rel=[]
    def ptr(off,value):
        if relocated:rel.append((off+base,1027,value))
        else:struct.pack_into('<Q',elf,off,value)
    ptr(0x3200,base+0x3100);struct.pack_into('<Q',elf,0x3208,3);ptr(0x3210,base+0x3300)
    for i,p in enumerate((0x1000,0x1000 if shared else 0x1040,0x1080)):ptr(0x3300+i*8,base+p)
    struct.pack_into('<Q',elf,0x3400+48,3);ptr(0x3400+56,base+0x3500)
    struct.pack_into('<Q',elf,0x3400+80,1);ptr(0x3400+88,base+0x3540)
    struct.pack_into('<Q',elf,0x3400+96,1);ptr(0x3400+104,base+0x3550)
    for i,kind in enumerate((8,12,2)):
        ptr(0x3500+i*8,base+0x3600+i*16)
        struct.pack_into('<I',elf,0x3600+i*16+8,kind<<16)
    if relocated:
        struct.pack_into('<IIQQQQQQ',elf,176,2,6,0x3700,base+0x3700,0,64,64,8)
        for i,(tag,val) in enumerate(((7,base+0x3800),(8,len(rel)*24),(9,24),(0,0))):struct.pack_into('<qQ',elf,0x3700+i*16,tag,val)
        for i,row in enumerate(rel):struct.pack_into('<QQq',elf,0x3800+i*24,*row)
    ep=tmp_path/'libil2cpp.so';ep.write_bytes(elf)
    return mp,ep


@pytest.mark.parametrize('version',[27,29,31])
@pytest.mark.parametrize('relocated',[False,True])
def test_two_files_to_modified_library(tmp_path,version,relocated):
    m,e=fixture(tmp_path,version,relocated)
    original=e.read_bytes();report=tmp_path/'analysis.json'
    result=json.loads(analyze(m,e,report))
    assert result['methods']==3 and result['resolved']==3 and result['type_table_found']
    assert [r['kind'] for r in result['candidates']]==['int32','float']
    assert result['candidates'][0]['offset']==0x1000
    out=tmp_path/'mod.zip'
    receipt=json.loads(export(report,e,json.dumps([{'id':0,'value':'777'},{'id':1,'value':'2.5'}]),out))
    with zipfile.ZipFile(out) as z:
        patched=z.read('libil2cpp.so')
        assert set(z.namelist())=={'libil2cpp.so','changes.json','analysis.json','README-RU.txt'}
        expected=bytearray(original)
        for p in receipt['changes']:
            data=bytes.fromhex(p['patch']);expected[p['offset']:p['offset']+len(data)]=data
        assert patched==bytes(expected)
        assert receipt['result_sha256']==hashlib.sha256(patched).hexdigest()
    assert e.read_bytes()==original


def test_shared_method_addresses_not_offered(tmp_path):
    m,e=fixture(tmp_path,shared=True)
    r=json.loads(analyze(m,e,tmp_path/'report.json'))
    assert r['candidates']==[]
    assert r['unavailable']['Общий адрес у нескольких методов']==2


def test_library_changed_after_analysis(tmp_path):
    m,e=fixture(tmp_path);report=tmp_path/'report.json';analyze(m,e,report)
    with e.open('r+b') as f:f.seek(0x1000);f.write(b'bad!')
    with pytest.raises(ValueError,match='изменилась'):
        export(report,e,'[{"id":0,"value":"2"}]',tmp_path/'result.zip')
    assert not (tmp_path/'result.zip').exists()


def test_invalid_and_unsupported_metadata(tmp_path):
    m,e=fixture(tmp_path);m.write_bytes(b'invalid')
    with pytest.raises(ValueError):analyze(m,e,tmp_path/'a.json')
    m,e=fixture(tmp_path,version=24)
    with pytest.raises(ValueError,match='v24'):analyze(m,e,tmp_path/'a.json')


def test_cancel_does_not_publish_partial_zip(tmp_path):
    m,e=fixture(tmp_path);report=tmp_path/'report.json';analyze(m,e,report)
    class Callback:
        def isCancelled(self):return True
        def progress(self,s):pass
    with pytest.raises(Cancelled):export(report,e,'[{"id":0,"value":"2"}]',tmp_path/'result.zip',Callback())
    assert not (tmp_path/'result.zip').exists()


@pytest.mark.parametrize('kind,value',[('bool','2'),('int8','128'),('uint32','-1'),('float','nan'),('double','inf'),('int64','1.5')])
def test_invalid_values(kind,value):
    with pytest.raises((ValueError,OverflowError)):patch_bytes(kind,value)


def test_float_instructions():
    assert patch_bytes('float','2.5')[-8:]==bytes.fromhex('0000271ec0035fd6')
    assert patch_bytes('double','2.5')[-8:]==bytes.fromhex('0000679ec0035fd6')


def test_relr_bitmaps(tmp_path):
    m,e=fixture(tmp_path,relocated=True)
    b=bytearray(e.read_bytes());size=struct.unpack_from('<Q',b,0x3718)[0]
    addresses=[]
    for pos in range(0x3800,0x3800+size,24):
        address,info,value=struct.unpack_from('<QQq',b,pos)
        struct.pack_into('<Q',b,address-0x10000,value);addresses.append(address)
    addresses.sort();words=[]
    while addresses:
        start=addresses.pop(0);words.append(start);bitmap=1
        while addresses and addresses[0] <= start+63*8:
            address=addresses.pop(0);bitmap |= 1 << ((address-start)//8)
        if bitmap!=1:words.append(bitmap)
    for i,(tag,val) in enumerate(((36,0x13800),(35,len(words)*8),(37,8),(0,0))):struct.pack_into('<qQ',b,0x3700+i*16,tag,val)
    for i,word in enumerate(words):struct.pack_into('<Q',b,0x3800+i*8,word)
    e.write_bytes(b)
    result=json.loads(analyze(m,e,tmp_path/'a.json'))
    assert len(result['candidates'])==2


def test_bti_landing_instruction_preserved(tmp_path):
    m,e=fixture(tmp_path);b=bytearray(e.read_bytes());struct.pack_into('<I',b,0x1000,0xd503245f);e.write_bytes(b)
    report=tmp_path/'a.json';analyze(m,e,report)
    export(report,e,'[{"id":0,"value":"10"}]',tmp_path/'a.zip')
    with zipfile.ZipFile(tmp_path/'a.zip') as z:
        assert z.read('libil2cpp.so')[0x1000:0x1004]==bytes.fromhex('5f2403d5')


def test_mismatched_module_count(tmp_path):
    m,e=fixture(tmp_path);b=bytearray(e.read_bytes());struct.pack_into('<Q',b,0x3208,4);e.write_bytes(b)
    result=json.loads(analyze(m,e,tmp_path/'a.json'))
    assert result['resolved']==0 and result['candidates']==[]


def test_no_type_registration_no_guessing(tmp_path):
    m,e=fixture(tmp_path);b=bytearray(e.read_bytes());struct.pack_into('<Q',b,0x3460,0);e.write_bytes(b)
    result=json.loads(analyze(m,e,tmp_path/'a.json'))
    assert result['resolved']==3 and not result['type_table_found'] and result['candidates']==[]


def test_rodroid_dump_is_source_of_truth_and_rebuilds_apk(tmp_path):
    metadata,library=fixture(tmp_path)
    dump=tmp_path/'rodroid'/'Dump0';dump.mkdir(parents=True)
    script={
        'ScriptMethod':[
            {'Address':0x11000,'Name':'Player$$get_Health','Signature':'int32_t Player$$get_Health (Player_o* __this, const MethodInfo* method);','TypeSignature':'iii','DotNetSignature':'Example.Player::get_Health()','Group':'Assembly-CSharp/Example/Player'},
            {'Address':0,'Name':'Player$$get_Damage','Signature':'int32_t Player$$get_Missing (Player_o* __this, const MethodInfo* method);','TypeSignature':'iii','DotNetSignature':'Example.Player::get_Damage()','Group':'Assembly-CSharp/Example/Player'},
        ],
        'Addresses':[0x11000,0x11040]
    }
    (dump/'script.json').write_text(json.dumps(script),encoding='utf-8')
    (dump/'dump.cs').write_text('// TypeDefIndex: 0\n// RVA: -1\n',encoding='utf-8')
    report=tmp_path/'analysis.json'
    result=json.loads(analyze_rodroid(dump,metadata,library,report))
    assert result['engine']=='Rodroid Il2CppDumper'
    assert result['source_of_truth']==['dump.cs','script.json','global-metadata+CodeRegistration']
    assert len(result['candidates'])==1 and result['unresolved']==1
    source=tmp_path/'game.apk'
    with zipfile.ZipFile(source,'w') as z:
        z.writestr('AndroidManifest.xml',b'manifest')
        z.writestr('META-INF/CERT.SF',b'old signature')
        info=zipfile.ZipInfo('lib/arm64-v8a/libil2cpp.so');info.compress_type=zipfile.ZIP_STORED
        z.writestr(info,library.read_bytes())
    unsigned=tmp_path/'rebuilt.apk'
    export_apk_unsigned(report,library,'[{"id":0,"value":"777"}]',source,unsigned)
    with zipfile.ZipFile(unsigned) as z:
        assert 'META-INF/CERT.SF' not in z.namelist()
        assert 'assets/modkit-build-receipt.json' in z.namelist()
        patched=z.read('lib/arm64-v8a/libil2cpp.so')
        assert patched != library.read_bytes()
        info=z.getinfo('lib/arm64-v8a/libil2cpp.so')
        data_offset=info.header_offset+30+len(info.filename.encode())+len(info.extra)
        assert data_offset % 16384 == 0


def test_rodroid_compact_android_return_is_file_backed(tmp_path):
    metadata,library=fixture(tmp_path)
    dump=tmp_path/'rodroid'/'Dump0';dump.mkdir(parents=True)
    script={
        'ScriptMethod':[
            {'Address':0x11000,'Name':'Player$$get_Health','Signature':'int32_t Player$$get_Health (Player_o* __this, const MethodInfo* method);','TypeSignature':'iii','DotNetSignature':'Example.Player::get_Health()','Group':'Assembly-CSharp/Example/Player'},
            {'Address':0,'Name':'Player$$get_Damage','Signature':'int32_t Player$$get_Missing (Player_o* __this, const MethodInfo* method);','TypeSignature':'iii','DotNetSignature':'Example.Player::get_Damage()','Group':'Assembly-CSharp/Example/Player'},
        ],
        'Addresses':[0x11000,0x11040]
    }
    (dump/'script.json').write_text(json.dumps(script),encoding='utf-8')
    (dump/'dump.cs').write_text('// TypeDefIndex: 0\n// RVA: -1\n',encoding='utf-8')
    report=tmp_path/'analysis.json';index=tmp_path/'analysis.ui.jsonl'
    compact=json.loads(analyze_rodroid(dump,metadata,library,report,None,True,index))
    assert compact['candidate_count']==1
    assert compact['discovery_count']>=1
    assert 'candidates' not in compact and 'method_details' not in compact and 'discoveries' not in compact
    assert compact['ui_index_file']=='analysis.ui.jsonl'
    rows=[json.loads(line) for line in index.read_text(encoding='utf-8').splitlines()]
    assert any(row.get('selectable') and row.get('label')=='Example.Player::get_Health()' for row in rows)
    full=json.loads(report.read_text(encoding='utf-8'))
    assert len(full['candidates'])==1 and len(full['method_details'])==2


def test_full_rodroid_dump_export_needs_no_selections(tmp_path):
    root=tmp_path/'rodroid';dump=root/'Dump0';dump.mkdir(parents=True)
    (dump/'dump.cs').write_text('class Player {}',encoding='utf-8')
    (dump/'script.json').write_text('{"ScriptMethod":[]}',encoding='utf-8')
    (dump/'stringliteral.json').write_text('[]',encoding='utf-8')
    (dump/'generics_dump.txt').write_text('generic',encoding='utf-8')
    report=tmp_path/'analysis.json';report.write_text('{"engine":"Rodroid"}',encoding='utf-8')
    output=tmp_path/'full-dump.zip'
    result=json.loads(export_dump(root,report,output))
    assert result['files']==5
    with zipfile.ZipFile(output) as z:
        assert {'rodroid/Dump0/dump.cs','rodroid/Dump0/script.json',
                'rodroid/Dump0/stringliteral.json','rodroid/Dump0/generics_dump.txt',
                'analysis.json','dump-manifest.json','README-RU.txt'} <= set(z.namelist())
        manifest=json.loads(z.read('dump-manifest.json'))
        assert all(len(item['sha256'])==64 for item in manifest['files'])


def test_dev22_catalog_page_index_points_to_exact_utf8_rows(tmp_path):
    base=tmp_path/'analysis.methods.jsonl.base'
    output=tmp_path/'analysis.methods.jsonl'
    source=[]
    for i in range(61):
        source.append(json.dumps({
            'catalog_only':True,'metadata_method_id':i,'label':f'Класс{i}::метод{i}',
            'rva':0x1000+i*4,'address_confirmed':True,'application_owned':True,
            'abi_materialized':False,'abi_shape_supported':False,'is_static':False,
            'generic':False,'abstract':False
        },ensure_ascii=False,separators=(',',':')))
    base.write_text('\n'.join(source)+'\n',encoding='utf-8')

    stats=_finalize_metadata_method_catalog(base,output)

    assert stats['rows']==61
    assert stats['pageSize']==30
    assert stats['pageCount']==3
    raw=(tmp_path/'analysis.methods.jsonl.pages.idx').read_bytes()
    offsets=struct.unpack('>QQQ',raw)
    data=output.read_bytes()
    for expected,offset in zip((0,30,60),offsets):
        line=data[offset:].split(b'\n',1)[0].decode('utf-8')
        assert json.loads(line)['metadata_method_id']==expected


def test_dev22_full_dump_export_includes_universal_method_catalog(tmp_path):
    root=tmp_path/'rodroid';dump=root/'Dump0';dump.mkdir(parents=True)
    (dump/'dump.cs').write_text('class Player {}',encoding='utf-8')
    (dump/'script.json').write_text('{"ScriptMethod":[]}',encoding='utf-8')
    report=tmp_path/'analysis.json';report.write_text('{"engine":"Rodroid"}',encoding='utf-8')
    catalog=tmp_path/'analysis.methods.jsonl'
    catalog.write_text('{"catalog_schema":"modkit-full-metadata-method-catalog-1.0","label":"Example.X::a"}\n',encoding='utf-8')
    (tmp_path/'analysis.methods.jsonl.idx').write_bytes(struct.pack('>Q',0))
    catalog_meta=tmp_path/'analysis.methods.meta.json'
    catalog_meta.write_text('{"rows":1,"addressConfirmed":1}',encoding='utf-8')
    deep=tmp_path/'analysis-deep';deep.mkdir()
    (deep/'method-7.json').write_text('{"schema":"modkit-deep-method-resolution-1.0","metadataMethodId":7}',encoding='utf-8')
    output=tmp_path/'full-dump.zip'

    result=json.loads(export_dump(root,report,output,None,catalog,catalog_meta,deep))

    assert result['files']==7
    with zipfile.ZipFile(output) as z:
        names=set(z.namelist())
        assert {'analysis.methods.jsonl','analysis.methods.jsonl.idx','analysis.methods.meta.json','analysis-deep/method-7.json'} <= names
        manifest=json.loads(z.read('dump-manifest.json'))
        paths={item['path'] for item in manifest['files']}
        assert {'analysis.methods.jsonl','analysis.methods.jsonl.idx','analysis.methods.meta.json','analysis-deep/method-7.json'} <= paths


def test_rodroid_rva_minus_one_can_be_resolved_uniquely_from_metadata(tmp_path):
    metadata,library=fixture(tmp_path)
    dump=tmp_path/'rodroid'/'Dump0';dump.mkdir(parents=True)
    script={
        'ScriptMethod':[
            {'Address':0x11000,'Name':'Player$$get_Health','Signature':'int32_t Player$$get_Health (Player_o* __this, const MethodInfo* method);','TypeSignature':'iii','DotNetSignature':'Example.Player::get_Health()','Group':'Assembly-CSharp/Example/Player'},
        ],
        'Addresses':[0x11000,0x11080]
    }
    (dump/'script.json').write_text(json.dumps(script),encoding='utf-8')
    (dump/'dump.cs').write_text('''// Dll : Assembly-CSharp.dll
// Namespace: Example
public class Player // TypeDefIndex: 0
{
    // RVA: -1 Offset: -1 VA: -1
    public float get_Speed() { }
}
''',encoding='utf-8')
    result=json.loads(analyze_rodroid(dump,metadata,library,tmp_path/'analysis.json'))
    assert result['resolved_metadata']==1
    assert result['unresolved']==0
    meta=[c for c in result['candidates'] if c.get('source')=='global-metadata+CodeRegistration']
    assert len(meta)==1 and meta[0]['label']=='Example.Player::get_Speed'
    assert meta[0]['rva']==0x11040


def test_rodroid_signature_contract_distinguishes_instance_setter_and_action():
    from modkit.mobile.engine import _rodroid_signature_contract
    setter = _rodroid_signature_contract(
        'void Drova_CheatGameHandler__EnableCheatMode (Drova_CheatGameHandler_o* __this, bool value, const MethodInfo* method);'
    )
    assert setter['isStatic'] is False
    assert setter['managedParamCount'] == 1
    assert setter['bindingSuggestion'] == 'bool_setter'
    assert setter['bindingBlocker'] == 'instance-method-needs-confirmed-instance-resolver'

    action = _rodroid_signature_contract(
        'void Example__ToggleConsoleWindow (const MethodInfo* method);'
    )
    assert action['isStatic'] is True
    assert action['managedParamCount'] == 0
    assert action['bindingSuggestion'] == 'action'
    assert action['bindingBlocker'] is None


def test_menu_auto_prepare_from_re_promotes_structurally_proven_candidate(tmp_path):
    from modkit.mobile.engine import menu_auto_prepare_from_re
    from modkit.selftest import fixtures

    apk = tmp_path / 'game.apk'
    with zipfile.ZipFile(apk, 'w') as z:
        z.writestr('lib/arm64-v8a/libil2cpp.so', fixtures.so_blob())
    re_report = tmp_path / 're-analysis.json'
    re_report.write_text(json.dumps({'controlCandidates': [{
        'id': 'candidate.cheat', 'title': 'Enable Cheat', 'suggestedType': 'toggle',
        'source': 'Drova.dll', 'kind': 'rodroid-discovery', 'location': 'RVA 0x1040',
        'evidenceRva': 0x1040, 'confidence': 0.97,
        'bindingSuggestion': 'bool_setter', 'isStatic': False,
        'bindingBlocker': 'instance-resolver-review-required',
        'signatureContract': {
            'signature': 'void X__EnableCheat (X_o* __this, bool value, const MethodInfo* method);',
            'bindingSuggestion': 'bool_setter', 'isStatic': False,
        },
        'resolverRva': 0x1044, 'resolverKind': 'out_ptr_bool',
        'resolverVerified': True, 'resolverMatch': 'metadata-target-type-exact',
        'instanceResolver': {
            'rva': 0x1044, 'kind': 'out_ptr_bool', 'label': 'X::TryGet', 'source': 'Drova.dll',
            'verified': True, 'match': 'metadata-target-type-exact', 'targetClass': 'X.CheatHandler',
            'contractSource': 'global-metadata+CodeRegistration',
            'contract': {'signature': 'bool X__TryGet (X_o** handler, const MethodInfo* method);'},
        },
    }], 'findings': []}), encoding='utf-8')
    menu_json = tmp_path / 'menu.json'
    out_report = tmp_path / 'auto.json'
    out_preflight = tmp_path / 'preflight.json'
    result = json.loads(menu_auto_prepare_from_re(
        re_report, menu_json, apk, tmp_path / 'project', out_report, out_preflight
    ))
    assert result['confirm']['promoted']
    assert result['preflight']['readyForPayload'] is True
    assert result['project']['runtimeMode'] == 'built-in-generic-config'
    saved = json.loads(menu_json.read_text(encoding='utf-8'))['controls'][0]
    assert saved['binding'] == 'bool_setter'
    assert saved['rva'] == 0x1040 and saved['resolver_rva'] == 0x1044


def test_rodroid_signature_contract_preserves_numeric_value_shape():
    from modkit.mobile.engine import _rodroid_signature_contract

    f = _rodroid_signature_contract(
        'void Example__SetSpeed (Example_o* __this, float value, const MethodInfo* method);'
    )
    assert f['bindingSuggestion'] == 'number_setter'
    assert f['suggestedControlType'] == 'slider_float'
    assert f['valueKind'] == 'float'
    assert f['managedValueType'] == 'System.Single'
    assert f['isStatic'] is False

    i = _rodroid_signature_contract(
        'void Example__SetLevel (int32_t value, const MethodInfo* method);'
    )
    assert i['bindingSuggestion'] == 'number_setter'
    assert i['suggestedControlType'] == 'slider_int'
    assert i['valueKind'] == 'int'
    assert i['managedValueType'] == 'System.Int32'


def test_rodroid_signature_contract_rejects_constructor_and_update_as_auto_bindings():
    from modkit.mobile.engine import _rodroid_signature_contract
    ctor = _rodroid_signature_contract('void X___ctor (int32_t value, const MethodInfo* method);')
    update = _rodroid_signature_contract('void X__Update (X_o* __this, float dt, const MethodInfo* method);')
    assert ctor['bindingSuggestion'] is None and ctor['autoBindingSafe'] is False
    assert update['bindingSuggestion'] is None and update['autoBindingSafe'] is False


def test_numeric_signature_contract_keeps_unsupported_widths_review_only():
    from modkit.mobile.engine import _rodroid_signature_contract
    i64 = _rodroid_signature_contract('void X__SetBig (int64_t value, const MethodInfo* method);')
    dbl = _rodroid_signature_contract('void X__SetScale (double value, const MethodInfo* method);')
    assert i64['suggestedControlType'] == 'slider_int' and i64['managedValueType'] == 'System.Int64'
    assert dbl['suggestedControlType'] == 'slider_float' and dbl['managedValueType'] == 'System.Double'
    for c in (i64, dbl):
        assert c['bindingSuggestion'] is None
        assert c['autoBindingSafe'] is False
        assert c['runtimeValueSupported'] is False
        assert c['bindingBlocker'] == 'generic-runtime-value-abi-unsupported'


def test_metadata_callable_contract_static_action():
    from modkit.mobile.engine import _metadata_callable_contract
    decl = {
        'name': 'ToggleConsole', 'return_decl': 'void', 'params': [],
        'declaration': 'public static void ToggleConsole() { }', 'declaration_static': True,
    }
    row = {'id': 7, 'token': 0x06000008, 'is_static': True}
    c = _metadata_callable_contract(decl, row)
    assert c['staticnessVerified'] is True
    assert c['shapeSupported'] is True
    assert c['isStatic'] is True
    assert c['managedParamCount'] == 0
    assert c['bindingSuggestion'] == 'action'
    assert c['autoBindingSafe'] is True


def test_metadata_callable_contract_static_bool_setter():
    from modkit.mobile.engine import _metadata_callable_contract
    decl = {
        'name': 'SetDebug', 'return_decl': 'void', 'params': ['bool value'],
        'declaration': 'public static void SetDebug(bool value) { }', 'declaration_static': True,
    }
    row = {'id': 8, 'token': 0x06000009, 'is_static': True}
    c = _metadata_callable_contract(decl, row)
    assert c['staticnessVerified'] is True
    assert c['managedParameters'] == [{'type': 'bool', 'name': 'value', 'byRef': False}]
    assert c['bindingSuggestion'] == 'bool_setter'
    assert c['autoBindingSafe'] is True


def test_metadata_callable_contract_numeric_setter_requires_range_review():
    from modkit.mobile.engine import _metadata_callable_contract
    decl = {
        'name': 'SetSpeed', 'return_decl': 'void', 'params': ['float value'],
        'declaration': 'public static void SetSpeed(float value) { }', 'declaration_static': True,
    }
    row = {'id': 9, 'token': 0x0600000A, 'is_static': True}
    c = _metadata_callable_contract(decl, row)
    assert c['bindingSuggestion'] == 'number_setter'
    assert c['suggestedControlType'] == 'slider_float'
    assert c['autoBindingSafe'] is True
    assert c['bindingBlocker'] is None


def test_metadata_callable_contract_instance_method_needs_instance_resolver():
    from modkit.mobile.engine import _metadata_callable_contract
    decl = {
        'name': 'EnableCheat', 'return_decl': 'void', 'params': ['bool value'],
        'declaration': 'public void EnableCheat(bool value) { }', 'declaration_static': False,
    }
    row = {'id': 10, 'token': 0x0600000B, 'is_static': False}
    c = _metadata_callable_contract(decl, row)
    assert c['isStatic'] is False
    assert c['bindingSuggestion'] == 'bool_setter'
    assert c['autoBindingSafe'] is True
    assert c['bindingBlocker'] == 'instance-method-needs-confirmed-instance-resolver'


def test_metadata_callable_contract_rejects_staticness_mismatch():
    from modkit.mobile.engine import _metadata_callable_contract
    decl = {
        'name': 'SetDebug', 'return_decl': 'void', 'params': ['bool value'],
        'declaration': 'public static void SetDebug(bool value) { }', 'declaration_static': True,
    }
    row = {'id': 11, 'token': 0x0600000C, 'is_static': False}
    c = _metadata_callable_contract(decl, row)
    assert c['staticnessVerified'] is False
    assert c['autoBindingSafe'] is False
    assert c['bindingSuggestion'] is None
    assert c['bindingBlocker'] == 'metadata-declaration-signature-mismatch'


def test_metadata_native_contract_uses_metadata_without_dump_declaration():
    from modkit.mobile.engine import _metadata_native_callable_contract
    row = {
        'id': 21, 'token': 0x06000016, 'name': 'SetSpeed', 'args': 1,
        'is_static': True, 'generic': False, 'abstract': False,
        'return_primitive': 'void',
        'parameters': [{'name': 'value', 'token': 0x08000001, 'type_index': 4,
                        'primitive': 'float', 'by_ref': False, 'type_code': 12}],
    }
    c = _metadata_native_callable_contract(row)
    assert c['contractSource'] == 'global-metadata+CodeRegistration'
    assert c['bindingSuggestion'] == 'number_setter'
    assert c['suggestedControlType'] == 'slider_float'
    assert c['isStatic'] is True
    assert c['shapeSupported'] is True
    assert 'dumpDeclaration' not in c


def test_metadata_native_contract_recognizes_tryget_out_class_resolver():
    from modkit.mobile.engine import _metadata_native_callable_contract
    row = {
        'id': 22, 'token': 0x06000017, 'name': 'TryGetCheatHandler', 'args': 1,
        'is_static': True, 'generic': False, 'abstract': False,
        'return_primitive': 'bool',
        'parameters': [{'name': 'handler', 'token': 0x08000002, 'type_index': 9,
                        'primitive': None, 'by_ref': True, 'type_code': 0x12}],
    }
    c = _metadata_native_callable_contract(row)
    assert c['bindingSuggestion'] is None
    assert c['resolverSuggestion'] == 'out_ptr_bool'
    assert c['resolverShape'] is True
    assert c['shapeSupported'] is True
    assert c['metadataParameters'][0]['byRef'] is True


def test_metadata_native_contract_recognizes_typed_singleton_return_resolver():
    from modkit.mobile.engine import _metadata_native_callable_contract
    row = {
        'id': 23, 'token': 0x06000018, 'name': 'get_Instance', 'args': 0,
        'is_static': True, 'generic': False, 'abstract': False,
        'return_primitive': None,
        'return_type_shape': {'typeCode': 0x12, 'byRef': False, 'primitive': None, 'typeDefIndex': 77},
        'return_type_definition_index': 77,
        'return_type_image': 'Game.dll', 'return_type_class': 'Game.PlayerController',
        'parameters': [],
    }
    c = _metadata_native_callable_contract(row)
    assert c['bindingSuggestion'] is None
    assert c['resolverSuggestion'] == 'return_ptr'
    assert c['returnPointerResolverShape'] is True
    assert c['resolverTargetVerified'] is True
    assert c['resolverTargetImage'] == 'Game.dll'
    assert c['resolverTargetClass'] == 'Game.PlayerController'


def test_metadata_native_contract_rejects_unsupported_reference_argument():
    from modkit.mobile.engine import _metadata_native_callable_contract
    row = {
        'id': 23, 'token': 0x06000018, 'name': 'SetState', 'args': 1,
        'is_static': True, 'generic': False, 'abstract': False,
        'return_primitive': 'void',
        'parameters': [{'name': 'state', 'token': 0x08000003, 'type_index': 10,
                        'primitive': None, 'by_ref': False, 'type_code': 0x12}],
    }
    c = _metadata_native_callable_contract(row)
    assert c['autoBindingSafe'] is False
    assert c['bindingSuggestion'] is None
    assert c['bindingBlocker'] == 'metadata-primitive-signature-unsupported'


def test_menu_spec_json_loader_preserves_verified_resolver_and_hashes(tmp_path):
    from modkit.mobile.engine import _menu_spec_from_json_path
    raw = {
        'schema': 'modkit-menu-1.1', 'title': 'X', 'iconText': 'MK',
        'targetSha256': 'a' * 64, 'sourceApkSha256': 'b' * 64,
        'controls': [{
            'id': 'x', 'title': 'X', 'type': 'toggle', 'category': 'General',
            'binding': None, 'target_so': 'libil2cpp.so', 'is_static': False,
            'call_abi': 'il2cpp', 'resolver_rva': 0x3000, 'resolver_kind': 'return_ptr',
            'resolver_verified': True, 'resolver_match': 'metadata-target-type-exact',
            'resolver_target_class': 'Game.Controller',
            'resolver_contract_source': 'global-metadata+CodeRegistration',
            'resolver_signature': 'void* Metadata__get_Instance (const MethodInfo* method);',
        }],
    }
    p = tmp_path / 'menu.json'; p.write_text(json.dumps(raw), encoding='utf-8')
    spec = _menu_spec_from_json_path(p)
    assert spec.target_sha256 == 'a' * 64 and spec.source_apk_sha256 == 'b' * 64
    c = spec.controls[0]
    assert c.resolver_verified is True
    assert c.resolver_kind == 'return_ptr'
    assert c.resolver_target_class == 'Game.Controller'


def test_re_ui_snapshot_is_bounded_for_large_reports():
    from modkit.mobile.engine import _re_ui_snapshot

    report = {
        'inventory': {'dex': ['x'] * 120, 'native': ['n'] * 90},
        'findings': [{
            'title': f'Finding {i}', 'status': 'candidate', 'confidence': 0.5,
            'rationale': 'R' * 8000,
            'evidence': [{'artifact': 'a', 'kind': 'k', 'value': 'v' * 2000, 'location': 'loc'}] * 30,
        } for i in range(120)],
        'controlCandidates': [{'title': f'Control {i}', 'semanticVerified': False} for i in range(100)],
        'nativeRelations': {
            'dexNativeLinks': [{'from': 'a', 'to': 'b', 'library': 'c', 'confidence': .5}] * 100,
            'il2cppDirectCallRefs': [{'callRva': 0x1000 + i, 'targetRva': 0x2000 + i} for i in range(100)],
        },
        'relationshipGraph': {'summary': {'nodes': 1000, 'edges': 2000}, 'nodes': [], 'completeChains': []},
        'inputSources': {'mode': 'selected-external-pair', 'il2cppReportLoaded': True},
        'pipelineDiagnostics': {'managedXrefStatus': 'xref-evidence-present', 'il2cppRows': 50000, 'externalLibraryUsed': True},
    }
    ui = _re_ui_snapshot(report)
    assert ui['findingCount'] == 120
    assert ui['visibleFindingCount'] == 48
    assert len(ui['findings']) == 48
    assert len(ui['controlCandidateLines']) == 20
    assert len(ui['relationshipLines']) <= 40
    assert len(ui['findings'][0]['rationale']) <= 2400
    assert len(ui['findings'][0]['evidenceLines']) == 12


def test_dev20_menu_seed_prefers_compact_re_sidecar(tmp_path):
    import json
    from modkit.mobile.engine import menu_seed_from_re
    full = tmp_path / 're-analysis.json'
    sidecar = tmp_path / 're-analysis.menu.json'
    full.write_text('{this would be too large or invalid}', encoding='utf-8')
    sidecar.write_text(json.dumps({
        'schema': 'modkit-re-menu-seed-1.0',
        'apk': {'sha256': 'a' * 64},
        'inventory': {'native': [{'artifact': 'lib/arm64-v8a/libil2cpp.so', 'sha256': 'b' * 64}]},
        'findings': [],
        'controlCandidates': [{
            'id': 'candidate.speed', 'title': 'SetSpeed', 'suggestedType': 'review',
            'status': 'review', 'confidence': 0.8, 'source': 'Assembly-CSharp.dll',
            'kind': 'il2cpp-metadata-callable', 'value': 'Game.Player::SetSpeed',
            'location': 'RVA 0x1234', 'evidenceRva': 0x1234, 'evidenceCount': 1,
            'corroboratingEvidence': [], 'gameplayRelevance': 77, 'gameplayRelevanceTier': 'high',
        }],
    }), encoding='utf-8')
    menu_json = tmp_path / 'menu.json'
    project = tmp_path / 'menu-project'
    result = json.loads(menu_seed_from_re(str(full), str(menu_json), str(project)))
    assert result['spec']['sourceApkSha256'] == 'a' * 64
    assert result['spec']['controls'][0]['gameplay_relevance'] == 77
    assert result['spec']['controls'][0]['gameplay_relevance_tier'] == 'high'


def test_dev20_exact_evidence_dedupe_preserves_unique_rows():
    from modkit.mobile.engine import _dedupe_re_evidence
    a = {'artifact': 'x', 'kind': 'string', 'value': 'speed', 'location': '0x1'}
    b = {'artifact': 'x', 'kind': 'string', 'value': 'speed', 'location': '0x2'}
    result = {
        'findings': [{'evidence': [dict(a), dict(a), dict(b)]}],
        'controlCandidates': [{'corroboratingEvidence': [dict(a), dict(a), dict(b)], 'evidenceCount': 99}],
    }
    _dedupe_re_evidence(result)
    assert result['findings'][0]['evidence'] == [a, b]
    assert result['controlCandidates'][0]['corroboratingEvidence'] == [a, b]
    assert result['controlCandidates'][0]['evidenceCount'] == 3


def test_dev21_all_rva_bl_scan_is_name_independent(tmp_path):
    import struct
    from modkit.mobile.engine import Elf, _arm64_direct_bl_observed_targets

    _metadata, library = fixture(tmp_path)
    blob = bytearray(library.read_bytes())
    source_rva, target_rva = 0x11000, 0x11040
    imm26 = ((target_rva - source_rva) >> 2) & 0x03FFFFFF
    struct.pack_into('<I', blob, 0x1000, 0x94000000 | imm26)
    library.write_bytes(blob)

    elf = Elf(library)
    try:
        counts, first, stats = _arm64_direct_bl_observed_targets(
            elf, {target_rva, 0x11080}, max_scan_bytes=0x1000)
    finally:
        elf.close()
    assert counts[target_rva] == 1
    assert counts.get(0x11080, 0) == 0
    assert first[target_rva]['callRva'] == source_rva
    assert stats['uniqueTargets'] == 1
    assert stats['strategy'] == 'all-unique-CodeRegistration-RVAs'


def test_dev21_rodroid_materializes_obfuscated_method_from_exact_bl_target(tmp_path):
    import struct

    metadata, library = fixture(tmp_path)
    meta_blob = bytearray(metadata.read_bytes())
    marker = b'get_Speed\x00'
    pos = meta_blob.find(marker)
    assert pos > 0
    meta_blob[pos:pos + len(marker)] = b'a\x00' + b'\x00' * (len(marker) - 2)
    metadata.write_bytes(meta_blob)

    lib_blob = bytearray(library.read_bytes())
    source_rva, target_rva = 0x11000, 0x11040
    imm26 = ((target_rva - source_rva) >> 2) & 0x03FFFFFF
    struct.pack_into('<I', lib_blob, 0x1000, 0x94000000 | imm26)
    library.write_bytes(lib_blob)

    dump = tmp_path / 'rodroid' / 'Dump0'
    dump.mkdir(parents=True)
    (dump / 'script.json').write_text(json.dumps({
        'ScriptMethod': [], 'Addresses': [0x11000, 0x11040, 0x11080]
    }), encoding='utf-8')
    (dump / 'dump.cs').write_text('// intentionally incomplete fixture\n', encoding='utf-8')

    result = json.loads(analyze_rodroid(dump, metadata, library, tmp_path / 'analysis.json'))
    hit = next(x for x in result['metadata_callable_methods'] if x['label'] == 'Example.Player::a')
    assert hit['rva'] == target_rva
    assert hit['static_incoming_direct_bl_count'] == 1
    assert hit['discovery_reason'] == 'exact-metadata-rva-observed-as-direct-bl-target'
    assert hit['method_verification']['addressConfirmed'] is True
    observed = result['metadata_observed_call_resolution']
    assert observed['uniqueTargets'] >= 1
    assert observed['materializedTargets'] >= 1


def test_dev22_full_metadata_catalog_keeps_unobserved_obfuscated_method(tmp_path):
    metadata, library = fixture(tmp_path)
    blob = bytearray(metadata.read_bytes())
    marker = b'get_Alive\x00'
    pos = blob.find(marker)
    assert pos > 0
    blob[pos:pos + len(marker)] = b'q\x00' + b'\x00' * (len(marker) - 2)
    metadata.write_bytes(blob)

    dump = tmp_path / 'rodroid' / 'Dump0'
    dump.mkdir(parents=True)
    (dump / 'script.json').write_text(json.dumps({
        'ScriptMethod': [], 'Addresses': [0x11000, 0x11040, 0x11080]
    }), encoding='utf-8')
    (dump / 'dump.cs').write_text('// intentionally incomplete fixture\n', encoding='utf-8')

    report = tmp_path / 'analysis.json'
    ui = tmp_path / 'analysis.ui.jsonl'
    catalog = tmp_path / 'analysis.methods.jsonl'
    compact = json.loads(analyze_rodroid(
        dump, metadata, library, report, None, True, ui, catalog))

    stats = compact['metadata_method_catalog']
    assert stats['available'] is True
    assert stats['rows'] == 3
    assert stats['addressConfirmed'] == 3
    assert compact['method_catalog_file'] == 'analysis.methods.jsonl'

    rows = [json.loads(line) for line in catalog.read_text(encoding='utf-8').splitlines()]
    hit = next(row for row in rows if row['label'] == 'Example.Player::q')
    assert hit['rva'] == 0x11080
    assert hit['address_confirmed'] is True
    assert hit['typed_abi'] is True
    assert hit['typed_window'] is False
    assert hit['abi_shape_supported'] is True
    assert hit['return_type'] == 'bool'
    assert hit['method_verification']['addressConfirmed'] is True
    assert hit['method_verification']['abiStatus'] == 'confirmed'
    assert hit['method_verification']['relationStatus'] == 'not-observed'
    assert hit['method_verification']['runtimeStatus'] == 'not-observed'
    assert hit['selectable'] is False
    dense_index = tmp_path / 'analysis.methods.jsonl.idx'
    page_index = tmp_path / 'analysis.methods.jsonl.pages.idx'
    assert dense_index.is_file() and page_index.is_file()
    assert page_index.read_bytes() == struct.pack('>Q', 0)
    assert len(dense_index.read_bytes()) == 3 * 8
    assert stats['pageSize'] == 30
    assert stats['pageCount'] == 1

def _write_bl(blob, source_rva, target_rva):
    file_offset = 0x1000 + (source_rva - 0x11000)
    imm26 = ((target_rva - source_rva) >> 2) & 0x03FFFFFF
    struct.pack_into('<I', blob, file_offset, 0x94000000 | imm26)


def _rodroid_fixture_dir(tmp_path):
    dump = tmp_path / 'rodroid' / 'Dump0'
    dump.mkdir(parents=True)
    (dump / 'script.json').write_text(json.dumps({
        'ScriptMethod': [], 'Addresses': [0x11000, 0x11040, 0x11080]
    }), encoding='utf-8')
    (dump / 'dump.cs').write_text('// intentionally incomplete fixture\n', encoding='utf-8')
    return dump


def test_dev23_deep_resolver_attributes_exact_incoming_and_outgoing_calls(tmp_path):
    metadata, library = fixture(tmp_path)
    blob = bytearray(library.read_bytes())
    _write_bl(blob, 0x11000, 0x11040)
    _write_bl(blob, 0x11040, 0x11080)
    library.write_bytes(blob)
    dump = _rodroid_fixture_dir(tmp_path)
    catalog = tmp_path / 'analysis.methods.jsonl'
    json.loads(analyze_rodroid(
        dump, metadata, library, tmp_path / 'analysis.json', None, True,
        tmp_path / 'analysis.ui.jsonl', catalog))

    output = tmp_path / 'analysis-deep' / 'method-1.json'
    deep = json.loads(deep_resolve_method(
        metadata, library, catalog, 1, output_path=output, dump_dir=dump))

    assert deep['schema'] == 'modkit-deep-method-resolution-1.2'
    assert deep['metadataMethodId'] == 1
    assert deep['target']['rva'] == 0x11040
    assert deep['target']['label'] == 'Example.Player::get_Speed'
    assert deep['incomingCallScan']['exactTotal'] == 1
    assert deep['incomingDirectCalls'][0]['callRva'] == 0x11000
    callers = deep['incomingDirectCalls'][0].get('sourceMethodCandidates') or []
    assert callers and callers[0]['label'] == 'Example.Player::get_Health'
    outgoing = deep['methodContext']['outgoingManagedCalls']
    assert outgoing and outgoing[0]['targetRva'] == 0x11080
    assert outgoing[0]['targetMethod']['label'] == 'Example.Player::get_Alive'
    assert deep['methodVerification']['relationStatus'] == 'confirmed-static-xref'
    assert deep['methodVerification']['runtimeStatus'] == 'not-observed'
    assert deep['runtimeTruth']['confirmed'] is False
    assert deep['menuEligibility']['eligible'] is False
    assert output.is_file()


def test_dev23_deep_resolver_selects_obfuscated_overload_by_metadata_id(tmp_path):
    metadata, library = fixture(tmp_path)
    blob = bytearray(metadata.read_bytes())
    for marker in (b'get_Speed\x00', b'get_Alive\x00'):
        pos = blob.find(marker)
        assert pos > 0
        blob[pos:pos + len(marker)] = b'a\x00' + b'\x00' * (len(marker) - 2)
    metadata.write_bytes(blob)
    dump = _rodroid_fixture_dir(tmp_path)
    catalog = tmp_path / 'analysis.methods.jsonl'
    json.loads(analyze_rodroid(
        dump, metadata, library, tmp_path / 'analysis.json', None, True,
        tmp_path / 'analysis.ui.jsonl', catalog))

    deep = json.loads(deep_resolve_method(metadata, library, catalog, 2, dump_dir=dump))
    assert deep['metadataMethodId'] == 2
    assert deep['target']['metadata_method_id'] == 2
    assert deep['target']['label'] == 'Example.Player::a'
    assert deep['target']['rva'] == 0x11080
    assert deep['catalogSnapshot']['name_key_ambiguous'] is True
    assert deep['runtimeTruth']['status'] == 'not-observed'


def test_dev23_single_target_bl_scan_keeps_exact_callsites(tmp_path):
    _metadata, library = fixture(tmp_path)
    blob = bytearray(library.read_bytes())
    _write_bl(blob, 0x11000, 0x11080)
    _write_bl(blob, 0x11040, 0x11080)
    library.write_bytes(blob)
    from modkit.mobile.engine import Elf
    elf = Elf(library)
    try:
        refs, stats = _arm64_direct_bl_calls_to_target(elf, 0x11080, max_scan_bytes=0x1000)
    finally:
        elf.close()
    assert [x['callRva'] for x in refs] == [0x11000, 0x11040]
    assert stats['matches'] == 2
    assert stats['strategy'] == 'single-exact-target-rva'

def test_dev23_deep_menu_seed_accepts_only_full_gate_candidates(tmp_path):
    deep = tmp_path / 'analysis-deep'; deep.mkdir()
    verified = {
        'schema': 'modkit-deep-method-resolution-1.0', 'metadataMethodId': 7,
        'menuEligibility': {'eligible': True},
        'runtimeTruth': {'status': 'not-observed', 'confirmed': False},
        'menuCandidate': {
            'id': 'deep.method.7', 'title': 'Example.X::SetEnabled', 'value': 'Example.X::SetEnabled',
            'suggestedType': 'toggle', 'status': 'confirmed', 'confidence': 0.94,
            'source': 'Assembly-CSharp.dll', 'kind': 'il2cpp-deep-resolved-method',
            'location': 'RVA 0x1234', 'evidenceRva': 0x1234, 'evidenceCount': 4,
            'isStatic': True, 'bindingSuggestion': 'bool_setter', 'bindingBlocker': None,
            'signatureContract': {
                'signature': 'void Metadata__SetEnabled (bool value, const MethodInfo* method);',
                'isStatic': True, 'staticnessVerified': True, 'shapeSupported': True,
                'autoBindingSafe': True, 'bindingSuggestion': 'bool_setter',
                'managedValueType': 'System.Boolean',
            },
            'semanticVerified': True, 'semanticStatus': 'verified-static-xref',
            'semanticConfidence': 0.94, 'semanticTags': ['state'], 'semanticEvidence': [],
            'contextVerified': True, 'contextStatus': 'verified-method-context',
            'contextConfidence': 0.9, 'contextEvidence': [],
            'methodVerification': {'addressConfirmed': True, 'abiConfirmed': True, 'executableReady': True},
        },
    }
    blocked = {
        'schema': 'modkit-deep-method-resolution-1.0', 'metadataMethodId': 8,
        'menuEligibility': {'eligible': False, 'blocker': 'method-local-context-verification-required'},
        'runtimeTruth': {'status': 'not-observed', 'confirmed': False},
        'menuCandidate': None,
    }
    (deep/'method-7.json').write_text(json.dumps(verified), encoding='utf-8')
    (deep/'method-8.json').write_text(json.dumps(blocked), encoding='utf-8')
    menu_json = tmp_path/'menu.json'; project = tmp_path/'menu-project'
    result = json.loads(menu_seed_from_deep(deep, menu_json, project))
    assert result['deepResults'] == 2
    assert result['eligibleControls'] == 1
    spec = json.loads(menu_json.read_text(encoding='utf-8'))
    assert len(spec['controls']) == 1
    control = spec['controls'][0]
    assert control['evidence_rva'] == 0x1234
    assert control['suggested_binding'] == 'bool_setter'
    assert control['binding'] is None
    assert (project/'native'/'bindings.generated.h').is_file()


def _write_words_at_rva(library, rva, code):
    blob = bytearray(library.read_bytes())
    off = 0x1000 + (int(rva) - 0x11000)
    blob[off:off + len(code)] = code
    library.write_bytes(blob)


def test_dev24_deep_resolver_follows_direct_bl_through_tail_thunk(tmp_path):
    from modkit.arch import arm64
    metadata, library = fixture(tmp_path)
    blob = bytearray(library.read_bytes())
    thunk = 0x11100
    _write_bl(blob, 0x11000, thunk)
    thunk_off = 0x1000 + (thunk - 0x11000)
    blob[thunk_off:thunk_off + 4] = arm64.b(0x11080 - thunk)
    library.write_bytes(blob)
    dump = _rodroid_fixture_dir(tmp_path)
    catalog = tmp_path / 'analysis.methods.jsonl'
    json.loads(analyze_rodroid(dump, metadata, library, tmp_path/'analysis.json', None, True,
                               tmp_path/'analysis.ui.jsonl', catalog))
    deep = json.loads(deep_resolve_method(metadata, library, catalog, 2,
                                          output_path=tmp_path/'analysis-deep'/'method-2.json', dump_dir=dump))
    assert deep['schema'] == 'modkit-deep-method-resolution-1.2'
    assert deep['incomingThunkCalls'][0]['callRva'] == 0x11000
    assert deep['incomingThunkCalls'][0]['immediateTargetRva'] == thunk
    assert deep['incomingThunkCalls'][0]['targetRva'] == 0x11080
    assert deep['target']['static_incoming_thunk_count'] == 1
    assert deep['methodVerification']['relationStatus'] == 'confirmed-static-xref'


def test_dev24_deep_resolver_resolves_pointer_load_blr_exactly(tmp_path):
    from modkit.arch import arm64
    metadata, library = fixture(tmp_path)
    slot = 0x13F00
    code = (arm64.adrp(16, 0x11000, slot & ~0xFFF)
            + arm64.add_imm(16, 16, slot & 0xFFF)
            + arm64.ldr_imm(16, 16, 0, size=8)
            + arm64.blr(16))
    blob = bytearray(library.read_bytes())
    blob[0x1000:0x1000+len(code)] = code
    struct.pack_into('<Q', blob, 0x3F00, 0x11080)
    library.write_bytes(blob)
    dump = _rodroid_fixture_dir(tmp_path)
    catalog = tmp_path/'analysis.methods.jsonl'
    json.loads(analyze_rodroid(dump, metadata, library, tmp_path/'analysis.json', None, True,
                               tmp_path/'analysis.ui.jsonl', catalog))
    out = tmp_path/'analysis-deep'/'method-2.json'
    deep = json.loads(deep_resolve_method(metadata, library, catalog, 2, output_path=out, dump_dir=dump))
    assert deep['incomingIndirectCalls'][0]['callRva'] == 0x1100C
    assert deep['incomingIndirectCalls'][0]['targetRva'] == 0x11080
    assert deep['target']['static_incoming_indirect_count'] == 1
    assert any(x['slotRva'] == slot for x in deep['functionPointerSlots'])
    assert deep['incomingCallScan']['indirectExactMatches'] == 1
    # Second identical request must reuse the persisted Deep Resolver result.
    cached = json.loads(deep_resolve_method(metadata, library, catalog, 2, output_path=out, dump_dir=dump))
    assert cached['cache']['hit'] is True
    assert cached['inputIdentity']['cacheKey'] == deep['inputIdentity']['cacheKey']


def test_dev24_virtual_blr_shape_is_review_not_exact_target(tmp_path):
    from modkit.arch import arm64
    from modkit.mobile.engine import Elf, _arm64_extended_calls_to_target
    metadata, library = fixture(tmp_path)
    code = arm64.ldr_imm(8, 0, 0, size=8) + arm64.ldr_imm(8, 8, 0x80, size=8) + arm64.blr(8)
    _write_words_at_rva(library, 0x11000, code)
    elf = Elf(library)
    try:
        exact, virtual, stats = _arm64_extended_calls_to_target(elf, 0x11080, metadata_slot=0)
    finally:
        elf.close()
    assert exact == []
    assert virtual and virtual[0]['callRva'] == 0x11008
    assert virtual[0]['vtableSlotOffset'] == 0x80
    assert virtual[0]['slotCorrelationStatus'] == 'candidate-only-no-static-receiver-type'
    assert stats['virtualCandidates'] >= 1


def test_dev24_deep_auto_prepare_links_verified_method_to_menu_preflight(tmp_path):
    from modkit.mobile.engine import menu_auto_prepare_from_deep
    from modkit.selftest import fixtures
    so = fixtures.so_blob()
    so_sha = hashlib.sha256(so).hexdigest()
    apk = tmp_path/'game.apk'
    with zipfile.ZipFile(apk, 'w') as z:
        z.writestr('lib/arm64-v8a/libil2cpp.so', so)
    deep_dir = tmp_path/'analysis-deep'; deep_dir.mkdir()
    result = {
        'schema': 'modkit-deep-method-resolution-1.2', 'metadataMethodId': 7,
        'inputIdentity': {'metadataSha256': 'a'*64, 'librarySha256': so_sha, 'cacheKey': 'c'*64},
        'menuEligibility': {'eligible': True},
        'runtimeTruth': {'status': 'not-observed', 'confirmed': False},
        'menuCandidate': {
            'id': 'deep.method.7', 'title': 'Example.X::SetEnabled', 'value': 'Example.X::SetEnabled',
            'suggestedType': 'toggle', 'status': 'confirmed', 'confidence': 0.97,
            'source': 'Assembly-CSharp.dll', 'kind': 'il2cpp-deep-resolved-method',
            'location': 'RVA 0x1040', 'evidenceRva': 0x1040, 'evidenceCount': 5,
            'isStatic': True, 'bindingSuggestion': 'bool_setter', 'bindingBlocker': None,
            'signatureContract': {
                'signature': 'void Metadata__SetEnabled (bool value, const MethodInfo* method);',
                'isStatic': True, 'staticnessVerified': True, 'shapeSupported': True,
                'autoBindingSafe': True, 'bindingSuggestion': 'bool_setter',
                'managedValueType': 'System.Boolean',
            },
            'semanticVerified': True, 'semanticStatus': 'verified-static-xref',
            'semanticConfidence': 0.95, 'semanticTags': ['state'], 'semanticEvidence': [],
            'contextVerified': True, 'contextStatus': 'verified-method-context',
            'contextConfidence': 0.90, 'contextEvidence': [],
            'methodVerification': {'addressConfirmed': True, 'abiConfirmed': True,
                                   'executableReady': True, 'runtimeStatus': 'not-observed'},
        },
    }
    (deep_dir/'method-7.json').write_text(json.dumps(result), encoding='utf-8')
    menu = tmp_path/'menu.json'; project = tmp_path/'project'
    linked = json.loads(menu_auto_prepare_from_deep(
        deep_dir, menu, apk, project, tmp_path/'auto.json', tmp_path/'preflight.json'))
    assert linked['eligibleControls'] == 1
    assert linked['confirm']['promoted']
    assert linked['preflight']['readyForPayload'] is True
    saved = json.loads(menu.read_text(encoding='utf-8'))
    assert saved['targetSha256'] == so_sha
    assert saved['sourceApkSha256'] == hashlib.sha256(apk.read_bytes()).hexdigest()
    assert saved['controls'][0]['binding'] == 'bool_setter'
    assert saved['controls'][0]['rva'] == 0x1040
    assert linked['project']['runtimeMode'] == 'built-in-generic-config'


def _dev25_enable_metadata_vtable(metadata):
    """Turn the standard 3-method fixture into one concrete 3-slot vtable."""
    blob = bytearray(metadata.read_bytes())
    version = struct.unpack_from('<I', blob, 4)[0]
    stride = 36 if version == 31 else 32
    # GlobalMetadataHeader region 17 = vtableMethods.
    struct.pack_into('<II', blob, 8 + 17 * 8, 0x500, 12)
    for i in range(3):
        # kIl2CppMetadataUsageMethodDef + v27+ decoded method index encoding.
        encoded = (3 << 29) | (i << 1) | 1
        struct.pack_into('<I', blob, 0x500 + i * 4, encoded)
        shift = 4 if version == 31 else 0
        flags_off = 0x200 + i * stride + 24 + shift
        flags = struct.unpack_from('<H', blob, flags_off)[0] | 0x40
        struct.pack_into('<H', blob, flags_off, flags)
        struct.pack_into('<H', blob, 0x200 + i * stride + 28 + shift, i)
    # TypeDefinition.vtableStart=0, vtable_count=3.
    struct.pack_into('<i', blob, 0x300 + 56, 0)
    struct.pack_into('<H', blob, 0x300 + 74, 3)
    metadata.write_bytes(blob)


def test_dev25_metadata_vtable_entries_decode_methoddef_slots(tmp_path):
    from modkit.mobile.engine import Metadata
    metadata, _library = fixture(tmp_path)
    _dev25_enable_metadata_vtable(metadata)
    meta = Metadata(metadata)
    try:
        td = meta.type_definition(0)
        entries = meta.vtable_entries_for_type(0)
    finally:
        meta.close()
    assert td['label'] == 'Example.Player'
    assert td['vtableCount'] == 3
    assert [(x['metadataSlot'], x['metadataMethodId']) for x in entries] == [(0, 0), (1, 1), (2, 2)]


def test_dev25_receiver_type_and_vtable_offsets_resolve_exact_virtual_target(tmp_path):
    from modkit.arch import arm64
    metadata, library = fixture(tmp_path)
    _dev25_enable_metadata_vtable(metadata)
    # Same concrete receiver type, two virtual callsites. With metadata slots
    # {0,1,2}, physical offsets {0x120,0x140} have exactly one common vtable
    # base: 0x120. Therefore 0x140 resolves to logical slot 2 -> method id 2.
    call0 = arm64.ldr_imm(8, 0, 0, size=8) + arm64.ldr_imm(8, 8, 0x120, size=8) + arm64.blr(8)
    call2 = arm64.ldr_imm(8, 0, 0, size=8) + arm64.ldr_imm(8, 8, 0x140, size=8) + arm64.blr(8)
    _write_words_at_rva(library, 0x11000, call0)
    _write_words_at_rva(library, 0x11040, call2)
    dump = _rodroid_fixture_dir(tmp_path)
    catalog = tmp_path/'analysis.methods.jsonl'
    json.loads(analyze_rodroid(dump, metadata, library, tmp_path/'analysis.json', None, True,
                               tmp_path/'analysis.ui.jsonl', catalog))
    deep = json.loads(deep_resolve_method(metadata, library, catalog, 2,
                                          output_path=tmp_path/'analysis-deep'/'method-2.json', dump_dir=dump))
    assert deep['schema'] == 'modkit-deep-method-resolution-1.2'
    assert deep['dispatchCorrelation']['confirmedExactTarget'] is True
    assert deep['dispatchCorrelation']['status'] == 'confirmed-receiver-vtable-target'
    assert deep['dispatchCorrelation']['receiverGroups'][0]['vtableBaseOffset'] == 0x120
    calls = deep['incomingVirtualCalls']
    assert len(calls) == 1
    assert calls[0]['callRva'] == 0x11048
    assert calls[0]['resolvedMetadataSlot'] == 2
    assert calls[0]['resolvedMetadataMethodId'] == 2
    assert calls[0]['receiverTypeProof']['typeDefIndex'] == 0
    assert calls[0]['slotCorrelationStatus'] == 'confirmed-exact-receiver-vtable-target'
    assert deep['target']['static_incoming_virtual_count'] == 1
    assert deep['methodVerification']['relationStatus'] == 'confirmed-static-xref'
    assert any(x['kind'] == 'native-virtual-vtable-target' for x in deep['methodVerification']['evidence'])


def test_dev25_single_virtual_offset_stays_review_when_vtable_base_is_ambiguous(tmp_path):
    from modkit.arch import arm64
    metadata, library = fixture(tmp_path)
    _dev25_enable_metadata_vtable(metadata)
    call = arm64.ldr_imm(8, 0, 0, size=8) + arm64.ldr_imm(8, 8, 0x140, size=8) + arm64.blr(8)
    _write_words_at_rva(library, 0x11040, call)
    dump = _rodroid_fixture_dir(tmp_path)
    catalog = tmp_path/'analysis.methods.jsonl'
    json.loads(analyze_rodroid(dump, metadata, library, tmp_path/'analysis.json', None, True,
                               tmp_path/'analysis.ui.jsonl', catalog))
    deep = json.loads(deep_resolve_method(metadata, library, catalog, 2, dump_dir=dump))
    assert deep['dispatchCorrelation']['confirmedExactTarget'] is False
    assert deep['incomingVirtualCalls'] == []
    assert deep['incomingVirtualCandidates']
    assert deep['incomingVirtualCandidates'][0]['slotCorrelationStatus'] == 'review-ambiguous-vtable-base'


def test_dev26_autopilot_catalog_prefilter_is_structural_and_diverse(tmp_path):
    catalog=tmp_path/'analysis.methods.jsonl'
    rows=[]
    for i in range(12):
        rows.append({
            'metadata_method_id':i,'label':f'Game.Player::M{i}','class':'Game.Player','rva':0x1000+i*4,
            'address_confirmed':True,'abi_shape_supported':True,'application_owned':True,
            'generic':False,'abstract':False,'binding_suggestion':'bool_setter' if i%2 else 'action',
            'auto_binding_safe':True,'relation_status':'observed-static-xref' if i<6 else 'not-observed',
            'semantic':['state'],'method_role':'setter','provenance':'game-primary','is_static':True,
            'static_incoming_direct_bl_count':2,
        })
    rows.append({'metadata_method_id':99,'label':'ThirdParty.X::SetEnabled','class':'ThirdParty.X','rva':0x3000,
                 'address_confirmed':True,'abi_shape_supported':True,'application_owned':False,
                 'binding_suggestion':'bool_setter'})
    catalog.write_text('\n'.join(json.dumps(x) for x in rows)+'\n',encoding='utf-8')
    q=_autopilot_catalog_candidates(catalog,max_candidates=8,per_class=3)
    assert len(q['selected'])==3
    assert all(x['metadataMethodId']!=99 for x in q['selected'])
    assert all(x['selectionPolicy'].startswith('confirmed-address') for x in q['selected'])


def test_dev26_autopilot_deep_batch_stops_after_diverse_proven_controls(tmp_path, monkeypatch):
    import modkit.mobile.engine as eng
    catalog=tmp_path/'analysis.methods.jsonl'
    rows=[]
    for i,(cls,tags) in enumerate([('Player',['health']),('Combat',['damage']),('World',['world']),('Move',['movement']),('Eco',['economy'])]):
        rows.append({'metadata_method_id':i,'label':f'Game.{cls}::SetX','class':f'Game.{cls}','rva':0x1000+i*4,
                     'address_confirmed':True,'abi_shape_supported':True,'application_owned':True,
                     'generic':False,'abstract':False,'binding_suggestion':'bool_setter','auto_binding_safe':True,
                     'relation_status':'observed-static-xref','semantic':tags,'method_role':'setter','provenance':'game-primary','is_static':True})
    catalog.write_text('\n'.join(json.dumps(x) for x in rows)+'\n',encoding='utf-8')
    def fake(meta,lib,cat,mid,output_path=None,cb=None,dump_dir=None):
        row={'metadataMethodId':mid,'menuEligibility':{'eligible':True},'runtimeTruth':{'confirmed':False},
             'menuCandidate':{'id':f'deep.method.{mid}','title':f'M{mid}','suggestedType':'toggle','status':'confirmed',
                              'confidence':.95,'source':'Assembly-CSharp.dll','kind':'il2cpp-deep-resolved-method',
                              'location':f'RVA 0x{0x1000+mid*4:x}','evidenceRva':0x1000+mid*4,'evidenceCount':3,
                              'isStatic':True,'bindingSuggestion':'bool_setter','signatureContract':{'signature':'void X (bool value, const MethodInfo* method);'},
                              'semanticVerified':True,'contextVerified':True,'canonicalImplementationRva':0x1000+mid*4}}
        if output_path: Path(output_path).write_text(json.dumps(row),encoding='utf-8')
        return json.dumps(row)
    monkeypatch.setattr(eng,'deep_resolve_method',fake)
    out=deep_resolve_autopilot('m','l',catalog,tmp_path/'deep',max_deep=5,target_controls=3)
    assert out['eligibleCount']>=3
    assert len(out['categories'])>=3
    saved=json.loads(next((tmp_path/'deep').glob('method-*.json')).read_text())
    assert saved['menuCandidate']['category'] in {'Combat','Movement','Progression / Economy','World / State','General'}


def test_dev26_deep_menu_deduplicates_same_canonical_implementation(tmp_path):
    deep=tmp_path/'analysis-deep'; deep.mkdir()
    base={'menuEligibility':{'eligible':True},'runtimeTruth':{'confirmed':False},
          'inputIdentity':{'metadataSha256':'a'*64,'librarySha256':'b'*64}}
    for mid,conf in [(1,.80),(2,.95)]:
        row={**base,'metadataMethodId':mid,'menuCandidate':{
            'id':f'deep.method.{mid}','title':f'Alias{mid}','suggestedType':'button','status':'confirmed','confidence':conf,
            'source':'Assembly-CSharp.dll','kind':'il2cpp-deep-resolved-method','location':'RVA 0x1234','evidenceRva':0x1234,
            'canonicalImplementationRva':0x1234,'evidenceCount':3,'isStatic':True,'bindingSuggestion':'action',
            'signatureContract':{'signature':'void X (const MethodInfo* method);'},'semanticVerified':True,
            'semanticConfidence':conf,'contextVerified':True,'contextConfidence':conf}}
        (deep/f'method-{mid}.json').write_text(json.dumps(row),encoding='utf-8')
    result=json.loads(menu_seed_from_deep(deep,tmp_path/'menu.json',tmp_path/'project'))
    assert result['eligibleControls']==1
    spec=json.loads((tmp_path/'menu.json').read_text())
    assert spec['controls'][0]['title']=='Alias2'


def test_dev27_typed_cross_object_byte_store_resolves_exact_parameter_field():
    from modkit.arch import arm64
    from modkit.mobile.gameplay import typed_field_accesses
    class FakeElf:
        def __init__(self, data): self.b=data
        def offset(self, rva, size=1, executable=False):
            if rva != 0x1000 or size > len(self.b): raise ValueError('outside')
            return 0
    code=arm64.str_imm(9,1,0x19,size=1)+arm64.ret()
    field={'declaringType':'IGame.RealMapUnit','name':'alive','fieldDefinitionIndex':7,
           'fieldTypeDefinitionIndex':None,'domains':['health']}
    method={'rva':0x1000,'declaringTypeIndex':1,'isStatic':False,'parameterTypeDefinitionIndices':[7]}
    got=typed_field_accesses(FakeElf(code),method,0x1008,{7:{0x19:[field]}})
    assert len(got)==1
    assert got[0]['access']=='store'
    assert got[0]['baseRegister']=='x1'
    assert got[0]['baseProvenance']=='arg0'
    assert got[0]['declaringType']=='IGame.RealMapUnit'
    assert got[0]['field']=='alive'
    assert got[0]['fieldOffset']==0x19
    assert got[0]['domains']==['health']


def test_dev27_gameplay_coverage_separates_field_package_and_script_search(tmp_path):
    from modkit.mobile.gameplay import build_gameplay_coverage
    graph=tmp_path/'analysis.evidence-graph.jsonl'
    fields=tmp_path/'analysis.fields.jsonl'
    fields.write_text(json.dumps({'declaringType':'IGame.RealMapUnit','name':'alive','runtimeOffset':0x19,
                                  'fieldDefinitionIndex':1,'domains':['health']})+'\n',encoding='utf-8')
    graph.write_text('\n'.join([
        json.dumps({'metadataMethodId':1,'label':'IGame.LuaManager::LoadLuaFiles','class':'IGame.LuaManager','name':'LoadLuaFiles',
                    'rva':0x1000,'applicationOwned':True,'semanticDomains':[],'typedFieldAccesses':[]}),
        json.dumps({'metadataMethodId':2,'label':'IGame.AvatarActor::SetActionSpeeder','class':'IGame.AvatarActor','name':'SetActionSpeeder',
                    'rva':0x2000,'applicationOwned':True,'semanticDomains':['movement'],
                    'typedFieldAccesses':[{'field':'actionSpeed','domains':['movement'],'fieldOffset':0x8c}]})
    ])+'\n',encoding='utf-8')
    package=[{'artifact':'assets/catalog.json','kind':'content-string','value':'diamond','domains':['currency'],'status':'package-observed'}]
    out=build_gameplay_coverage(graph,fields,package)
    cards={x['domain']:x for x in out['cards']}
    assert out['scriptContentLayerDetected'] is True
    assert cards['health']['status']=='FIELD OBSERVED'
    assert cards['health']['fields'][0]['name']=='alive'
    assert cards['health']['numericHpSetterAttributed'] is False
    assert cards['movement']['status']=='CONFIRMED'
    assert cards['currency']['status']=='PACKAGE OBSERVED'
    assert cards['damage']['status']=='SCRIPT/CONTENT SEARCH'


def test_dev27_package_scan_is_discovery_only_and_filters_framework_noise(tmp_path):
    import zipfile
    from modkit.mobile.gameplay import scan_apk_package_evidence
    apk=tmp_path/'game.apk'
    with zipfile.ZipFile(apk,'w') as z:
        z.writestr('assets/game.json','diamond gold\nkeepAlive SQL GRANT CriMana currencyCode')
        z.writestr('assets/scripts/player.lua','return 1')
        z.writestr('assets/bin/Data/Managed/Resources/System.Data.dll-resources.dat','GRANT currency')
    hits=scan_apk_package_evidence(apk,max_total_bytes=1024*1024)
    assert any(x.get('kind')=='script/content-layer' for x in hits)
    currency=[x for x in hits if 'currency' in (x.get('domains') or [])]
    assert any('diamond' in x.get('value','').lower() or 'gold' in x.get('value','').lower() for x in currency)
    assert not any('grant' in x.get('value','').lower() for x in currency)
    assert not any('keepalive' in x.get('value','').lower() for x in hits if x.get('domains'))
    assert not any('resource' in (x.get('domains') or []) for x in hits)
