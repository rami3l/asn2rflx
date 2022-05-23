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
    model = PyRFLX(model=Model(types=[*prelude.MODEL.types, *foo.values()]))
    pkg = model.package("Foo")

    (expected := pkg.new_message("Question")).parse(
        b"\x30\x13"  # SEQUENCE
        b"\x02\x01"  # INTEGER
        b"\x05"  # 5
        b"\x16\x0e"  # IA5String
        b"Anybody there?"
    )

    assert expected.get("Untagged_Value_id_Untagged_Value") == b"\x05"
    assert expected.get("Untagged_Value_question_Untagged_Value") == b"Anybody there?"


def test_foo_dump(foo: dict[ID, model.Type]) -> None:
    assert {str(ty) for ty in foo.values()} == {
        dedent(
            """\
            type Question is
               message
                  Tag_Class : Prelude::Asn_Tag_Class;
                  Tag_Form : Prelude::Asn_Tag_Form;
                  Tag_Num : Prelude::Asn_Tag_Num
                     then null
                        if Tag_Num /= 16
                           or Tag_Class /= 0
                           or Tag_Form /= 1
                     then Untagged_Length
                        if Tag_Num = 16
                           and Tag_Class = 0
                           and Tag_Form = 1;
                  Untagged_Length : Prelude::Asn_Length;
                  Untagged_Value_id_Tag_Class : Prelude::Asn_Tag_Class;
                  Untagged_Value_id_Tag_Form : Prelude::Asn_Tag_Form;
                  Untagged_Value_id_Tag_Num : Prelude::Asn_Tag_Num
                     then Untagged_Value_id_Untagged_Length
                        if Untagged_Value_id_Tag_Num = 2
                           and Untagged_Value_id_Tag_Class = 0
                           and Untagged_Value_id_Tag_Form = 0
                     then Untagged_Value_question_Tag_Class
                        if Untagged_Value_id_Tag_Num /= 2
                           or Untagged_Value_id_Tag_Class /= 0
                           or Untagged_Value_id_Tag_Form /= 0;
                  Untagged_Value_id_Untagged_Length : Prelude::Asn_Length
                     then Untagged_Value_id_Untagged_Value
                        with Size => Untagged_Value_id_Untagged_Length * 8;
                  Untagged_Value_id_Untagged_Value : Opaque;
                  Untagged_Value_question_Tag_Class : Prelude::Asn_Tag_Class;
                  Untagged_Value_question_Tag_Form : Prelude::Asn_Tag_Form;
                  Untagged_Value_question_Tag_Num : Prelude::Asn_Tag_Num
                     then null
                        if Untagged_Value_question_Tag_Num /= 22
                           or Untagged_Value_question_Tag_Class /= 0
                           or Untagged_Value_question_Tag_Form /= 0
                     then Untagged_Value_question_Untagged_Length
                        if Untagged_Value_question_Tag_Num = 22
                           and Untagged_Value_question_Tag_Class = 0
                           and Untagged_Value_question_Tag_Form = 0;
                  Untagged_Value_question_Untagged_Length : Prelude::Asn_Length
                     then Untagged_Value_question_Untagged_Value
                        with Size => Untagged_Value_question_Untagged_Length * 8;
                  Untagged_Value_question_Untagged_Value : Opaque;
               end message"""
        ),
        dedent(
            """\
            type Answer is
               message
                  Tag_Class : Prelude::Asn_Tag_Class;
                  Tag_Form : Prelude::Asn_Tag_Form;
                  Tag_Num : Prelude::Asn_Tag_Num
                     then null
                        if Tag_Num /= 16
                           or Tag_Class /= 0
                           or Tag_Form /= 1
                     then Untagged_Length
                        if Tag_Num = 16
                           and Tag_Class = 0
                           and Tag_Form = 1;
                  Untagged_Length : Prelude::Asn_Length;
                  Untagged_Value_id_Tag_Class : Prelude::Asn_Tag_Class;
                  Untagged_Value_id_Tag_Form : Prelude::Asn_Tag_Form;
                  Untagged_Value_id_Tag_Num : Prelude::Asn_Tag_Num
                     then Untagged_Value_answer_Tag_Class
                        if Untagged_Value_id_Tag_Num /= 2
                           or Untagged_Value_id_Tag_Class /= 0
                           or Untagged_Value_id_Tag_Form /= 0
                     then Untagged_Value_id_Untagged_Length
                        if Untagged_Value_id_Tag_Num = 2
                           and Untagged_Value_id_Tag_Class = 0
                           and Untagged_Value_id_Tag_Form = 0;
                  Untagged_Value_id_Untagged_Length : Prelude::Asn_Length
                     then Untagged_Value_id_Untagged_Value
                        with Size => Untagged_Value_id_Untagged_Length * 8;
                  Untagged_Value_id_Untagged_Value : Opaque;
                  Untagged_Value_answer_Tag_Class : Prelude::Asn_Tag_Class;
                  Untagged_Value_answer_Tag_Form : Prelude::Asn_Tag_Form;
                  Untagged_Value_answer_Tag_Num : Prelude::Asn_Tag_Num
                     then null
                        if Untagged_Value_answer_Tag_Num /= 1
                           or Untagged_Value_answer_Tag_Class /= 0
                           or Untagged_Value_answer_Tag_Form /= 0
                     then Untagged_Value_answer_Untagged_Length
                        if Untagged_Value_answer_Tag_Num = 1
                           and Untagged_Value_answer_Tag_Class = 0
                           and Untagged_Value_answer_Tag_Form = 0;
                  Untagged_Value_answer_Untagged_Length : Prelude::Asn_Length
                     then Untagged_Value_answer_Untagged_Value
                        if Untagged_Value_answer_Untagged_Length'Size = Prelude::Asn_Raw_BOOLEAN'Size;
                  Untagged_Value_answer_Untagged_Value : Prelude::Asn_Raw_BOOLEAN;
               end message"""
        ),
    }


def test_rocket_decode(rocket: dict[ID, model.Type]) -> None:
    model = PyRFLX(model=Model(types=[*prelude.MODEL.types, *rocket.values()]))
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
