from textwrap import dedent
from typing import cast

import asn1tools as asn1
from asn1tools.codecs.ber import CompiledType
from asn2rflx.convert import AsnTypeConverter
from pytest import fixture

ASSETS = "assets/"


@fixture
def converter():
    return AsnTypeConverter(base_path="Converter")


def test_foo(converter: AsnTypeConverter):
    foo = asn1.compile_files(ASSETS + "foo.asn")
    assert {
        str(converter.convert(cast(CompiledType, ty).type).tlv_ty())
        for ty in foo.types.values()
    } == {
        dedent(
            """\
            type Question is
               message
                  Tag_Class : Prelude::Asn_Tag_Class;
                  Tag_Form : Prelude::Asn_Tag_Form;
                  Tag_Num : Prelude::Asn_Tag_Num
                     then null
                        if not (Tag_Num = 16
                            and Tag_Class = 0
                            and Tag_Form = 1)
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
                        if not (Tag_Num = 2
                            and Tag_Class = 0
                            and Tag_Form = 0);
                  Untagged_Value_id_Untagged_Length : Prelude::Asn_Length
                     then Untagged_Value_id_Untagged_Value
                        with Size => Untagged_Value_id_Untagged_Length * 8;
                  Untagged_Value_id_Untagged_Value : Opaque;
                  Untagged_Value_question_Tag_Class : Prelude::Asn_Tag_Class;
                  Untagged_Value_question_Tag_Form : Prelude::Asn_Tag_Form;
                  Untagged_Value_question_Tag_Num : Prelude::Asn_Tag_Num
                     then null
                        if not (Tag_Num = 22
                            and Tag_Class = 0
                            and Tag_Form = 0)
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
                        if not (Tag_Num = 16
                            and Tag_Class = 0
                            and Tag_Form = 1)
                     then Untagged_Length
                        if Tag_Num = 16
                           and Tag_Class = 0
                           and Tag_Form = 1;
                  Untagged_Length : Prelude::Asn_Length;
                  Untagged_Value_id_Tag_Class : Prelude::Asn_Tag_Class;
                  Untagged_Value_id_Tag_Form : Prelude::Asn_Tag_Form;
                  Untagged_Value_id_Tag_Num : Prelude::Asn_Tag_Num
                     then Untagged_Value_answer_Tag_Class
                        if not (Tag_Num = 2
                            and Tag_Class = 0
                            and Tag_Form = 0)
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
                        if not (Tag_Num = 1
                            and Tag_Class = 0
                            and Tag_Form = 0)
                     then Untagged_Value_answer_Untagged_Length
                        if Untagged_Value_answer_Tag_Num = 1
                           and Untagged_Value_answer_Tag_Class = 0
                           and Untagged_Value_answer_Tag_Form = 0;
                  Untagged_Value_answer_Untagged_Length : Prelude::Asn_Length
                     then null
                        if Untagged_Value_answer_Untagged_Length'Length /= Prelude::Asn_Raw_BOOLEAN'Length
                     then Untagged_Value_answer_Untagged_Value
                        if Untagged_Value_answer_Untagged_Length'Length = Prelude::Asn_Raw_BOOLEAN'Length;
                  Untagged_Value_answer_Untagged_Value : Prelude::Asn_Raw_BOOLEAN;
               end message"""
        ),
    }
