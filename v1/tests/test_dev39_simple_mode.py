import json, zipfile
from modkit.mobile.simple_mode import build_catalog
from modkit.mobile.security_scan import scan_apk_paths


def test_local_currency_can_be_ready_dex_without_server_audit(tmp_path):
    (tmp_path/'analysis.gameplay-coverage.json').write_text(json.dumps({'findings':[{'title':'Currency','status':'CONFIRMED','category':'currency','trustBoundary':'local','class':'game.PlayerWallet','method':'getGold','artifact':'classes2.dex','codeOffset':123}]}),encoding='utf-8')
    out=build_catalog(tmp_path); card=next(c for c in out['cards'] if c['title']=='Currency')
    assert card['status']=='READY_DEX' and card['actionable'] and not card['serverAudit']


def test_framework_rows_are_kept_but_low_priority(tmp_path):
    (tmp_path/'installed-scan.json').write_text(json.dumps({'methods':[{'label':'androidx.room.RawQuery::observedEntities() -> java.lang.Class[]','status':'CONFIRMED','artifact':'classes.dex','class':'androidx.room.RawQuery','method':'observedEntities','codeOffset':42,'evidenceRole':'framework/third-party'}]}),encoding='utf-8')
    out=build_catalog(tmp_path); card=next(c for c in out['cards'] if c['title'].startswith('androidx.room.RawQuery'))
    assert card['ownership']=='FRAMEWORK' and card['lowSignal'] and not card['important']


def test_security_scanner_groups_endpoints_and_crypto(tmp_path):
    apk=tmp_path/'base.apk'
    with zipfile.ZipFile(apk,'w') as z:
        z.writestr('classes.dex',b'dex\n035\x00 https://api.example.test/v1/profile wss://socket.example.test/live Retrofit baseUrl')
        z.writestr('assets/config.txt','AES/GCM encryption_key SecretKeySpec')
    sec=scan_apk_paths([apk],tmp_path/'security-surfaces.json')
    assert sec['activeConnectionAttempted'] is False and sec['credentialValueExtraction'] is False and sec['keyValueExtraction'] is False
    assert sec['groups']['endpoints']['uniqueValueCount']>=2 and sec['groups']['crypto']['count']>=2
    out=build_catalog(tmp_path)
    assert any(c['source']=='SecuritySummary' and c['title']=='Network / API Endpoints' for c in out['cards'])
    assert any(c['source']=='SecuritySummary' and c['title']=='Crypto / Key Handling' for c in out['cards'])
