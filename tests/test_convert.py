from textwrap import dedent
from typing import Mapping, cast

import asn1tools as asn1
from asn1tools.codecs import ber
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
    spec = asn1.compile_files(ASSETS + "foo.asn")
    cvt = AsnTypeConverter()
    res: dict[ID, model.Type] = {}
    for path, tys in spec.modules.items():
        res |= {
            (ty1 := cvt.convert(ty.type, path).tlv_ty()).qualified_identifier: ty1
            for ty in tys.values()
        }
    return res


def test_foo_encode(foo: dict[ID, model.Type]) -> None:
    model = PyRFLX(model=Model(types=[*prelude.MODEL.types, *foo.values()]))
    pkg = model.package("Foo")

    got = pkg.new_message("Question")
    # TODO: I cannot test it this way because there's no "id" in the underlying RFLX message!
    # got.set("id", 5)
    # got.set("question", "Anybody there?")

    (expected := pkg.new_message("Question")).parse(
        b"\x30\x13\x02\x01\x05\x16\x0e\x41\x6e\x79\x62"
        b"\x6f\x64\x79\x20\x74\x68\x65\x72\x65\x3f"
    )

    assert got == expected


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
