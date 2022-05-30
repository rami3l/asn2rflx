from pprint import pprint
from textwrap import dedent

import asn1tools as asn1
from asn2rflx import prelude
from asn2rflx.convert import AsnTypeConverter
from pytest import fixture
from rflx import model
from rflx.identifier import ID
from rflx.model.model import Model
from rflx.pyrflx import PyRFLX

ASSETS = "assets/"


@fixture(scope="session")
def foo() -> dict[ID, model.Type]:
    return AsnTypeConverter().convert_spec(asn1.compile_files(ASSETS + "foo.asn"))


@fixture(scope="session")
def rocket() -> dict[ID, model.Type]:
    return AsnTypeConverter().convert_spec(
        asn1.compile_files(ASSETS + "rocket_mod.asn")
    )


def test_foo_decode(foo: dict[ID, model.Type]) -> None:
    types = foo.values()
    pprint({str(ty) for ty in types})
    model = PyRFLX(model=Model(types=[*prelude.MODEL.types, *types]))
    pkg = model.package("Foo")

    (expected := pkg.new_message("Question")).parse(
        b"\x30\x13"  # SEQUENCE
        b"\x02\x01"  # INTEGER
        b"\x05"  # 5
        b"\x16\x0e"  # IA5String
        b"Anybody there?"
    )

    assert expected.get("Tag_Class") == 0
    assert expected.get("Tag_Form") == 1
    assert expected.get("Tag_Num") == 16
    assert expected.get("Untagged_Value_id_Untagged_Value") == b"\x05"
    assert expected.get("Untagged_Value_question_Untagged_Value") == b"Anybody there?"


def test_rocket_decode(rocket: dict[ID, model.Type]) -> None:
    types = rocket.values()
    pprint({str(ty) for ty in types})
    model = PyRFLX(model=Model(types=[*prelude.MODEL.types, *types]))
    pkg = model.package("World-Schema")

    (expected := pkg.new_message("Rocket")).parse(
        bytes.fromhex(
            "301C"  # SEQUENCE
            "0202"  # INTEGER
            "0080"  # 128
            "0406"  # OCTET STRING
            "414141"  # "AAAAAA"
            "0603"  # OBJECT IDENTIFIER
            "2A0304"  # "1.2.3.4"
            "3009"  # SEQUENCE OF
            "020105"  # INTEGER : 5
            "020106"  # INTEGER : 6
            "020107"  # INTEGER : 7
        )
    )

    assert expected.get("Untagged_Value_range_Untagged_Value") == b"\x00\x80"
    assert expected.get("Untagged_Value_name_Untagged_Value") == b"AAAAAA"
    assert expected.get("Untagged_Value_ident_Untagged_Value") == b"\x2a\x03\x04"
