from dataclasses import replace
import pytest
from app.recovery.model import Reference
from app.recovery.mqtt import ReportingReply
from app.recovery.radio import RadioVerifier
R=Reference("0x00124b0000000010",1,"genOnOff","onOff")

def reply():
    return ReportingReply(R,"g","tx",100,"ok",{"id":R.ieee,"endpoint":1,"cluster":"genOnOff",
                           "configs":[{"status":0,"direction":0,"attrId":0,"dataType":16,"minRepIntval":1,"maxRepIntval":300}]})


def test_real_reporting_response_confirms_only_current_generation():
    v=RadioVerifier(); r=reply()
    assert v.validate(R,r,"g",101).confirmed
    assert not v.validate(R,r,"other",101).confirmed
    assert not v.validate(R,r,"g",1001).confirmed


@pytest.mark.parametrize("change", [{"retained":True},{"status":"error"},{"at":200},
 {"reference":replace(R,ieee="0x00124b0000000099")},
 {"data":{"id":R.ieee,"endpoint":2,"cluster":"genOnOff","configs":[]}},
 {"data":{"id":R.ieee,"endpoint":1,"cluster":"genOnOff","configs":[{"status":134,"attrId":0}]}},
 {"data":{"id":R.ieee,"endpoint":1,"cluster":"genOnOff","configs":[{"status":0,"direction":0,"attrId":99}]}},
 {"data":{"id":R.ieee,"endpoint":1,"cluster":"genOnOff","configs":[{"healthy":True}]}},
 {"data":{"id":"other","endpoint":1,"cluster":"genOnOff","configs":[]}}])
def test_bad_or_foreign_reply_never_confirms_radio(change):
    assert not RadioVerifier().validate(R,replace(reply(),**change),"g",101).confirmed


def test_unknown_attribute_is_unconfirmed_not_an_actuator_command():
    r=replace(R,attribute="vendorUnknown")
    assert not RadioVerifier().validate(r,replace(reply(),reference=r),"g",101).confirmed
