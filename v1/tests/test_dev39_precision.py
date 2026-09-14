import struct

from modkit.reworkspace.dex import DexFile, DexMethodRef, DexDefinedMethod
from modkit.reworkspace.trust import surfaces_for_method
from modkit.mobile.gameplay import _package_domains


def _uleb(v):
    out=bytearray()
    while True:
        b=v & 0x7f; v >>= 7
        if v: out.append(b|0x80)
        else: out.append(b); return bytes(out)


def test_dex_virtual_method_idx_diff_restarts_from_zero():
    d=DexFile.__new__(DexFile); blob=bytearray(256)
    d.class_defs_size=1; d.class_defs_off=0; d.method_ids_size=16
    d._types=['pkg.C']; d._strings=[]; d._protos=[]; d._methods=None; d._method_cache={}; d._defined=None
    data_off=64; struct.pack_into('<I',blob,24,data_off)
    payload=_uleb(0)+_uleb(0)+_uleb(1)+_uleb(1)+_uleb(5)+_uleb(1)+_uleb(100)+_uleb(2)+_uleb(1)+_uleb(120)
    blob[data_off:data_off+len(payload)]=payload; d.blob=bytes(blob)
    refs={i:DexMethodRef(i,'pkg.C',f'm{i}','void',[]) for i in (2,5)}; d.method_ref=lambda i:refs[i]; d._refs=lambda off:([f's{off}'],[])
    rows=list(d.iter_defined_methods()); assert [r.index for r in rows]==[5,2]; assert [r.code_offset for r in rows]==[100,120]


def test_framework_get_order_is_not_monetization():
    m=DexDefinedMethod(1,'androidx.core.internal.view.SupportMenuItem','getOrder','int',[],1,10,[],[])
    assert 'monetization' not in surfaces_for_method(m)


def test_package_currency_filters_locale_and_analytics_noise():
    assert 'currency' not in _package_domains('java.util.Currency')
    assert 'currency' not in _package_domains('reportWithRevenue currency')
    assert 'currency' not in _package_domains('KEY_CURRENCY currencyToSymbol')
    assert 'currency' in _package_domains('diamond wallet reward')
    assert 'currency' in _package_domains('gold coin shop price')
