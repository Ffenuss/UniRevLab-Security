import struct
import pytest
from modkit.reworkspace.dex import DexError, _descriptor, _uleb


def test_descriptor_names():
    assert _descriptor('I') == 'int'
    assert _descriptor('[Z') == 'boolean[]'
    assert _descriptor('Ljava/lang/String;') == 'java.lang.String'
    assert _descriptor('[[Ljava/lang/Object;') == 'java.lang.Object[][]'


def test_uleb_reader():
    assert _uleb(bytes([0x7f]),0) == (0x7f,1)
    assert _uleb(bytes([0x80,0x01]),0) == (0x80,2)
    with pytest.raises(DexError): _uleb(b'\x80',0)


def test_bad_dex_is_rejected():
    from modkit.reworkspace.dex import DexFile
    with pytest.raises(DexError): DexFile(b'not dex')


def test_evidence_role_filters_framework_packages():
    from modkit.reworkspace.trust import evidence_role
    assert evidence_role('com.google.android.billingclient.api.BillingClient') == 'framework/third-party'
    assert evidence_role('com.vendor.game.payment.IapService') == 'application/bundled-sdk'
