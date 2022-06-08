import random
from typing import Union, cast

import asn1tools as asn1
import hypothesis as hypot
import hypothesis.strategies as strats
import pytest
from asn1tools.codecs.ber import encode_signed_integer
from asn2rflx import prelude
from asn2rflx.convert import AsnTypeConverter
from rflx.model.model import Model
from rflx.pyrflx import PyRFLX
from rflx.pyrflx.typevalue import MessageValue

ASSETS = "assets/"

ASN_SHORT_LEN = 10
ASN_SHORT_INTS = strats.integers(
    min_value=-(256 ** (ASN_SHORT_LEN - 1)),
    max_value=256 ** (ASN_SHORT_LEN - 1) - 1,
)
ASN_SHORT_IA5STRINGS = strats.text(
    alphabet=strats.characters(max_codepoint=127),
    max_size=ASN_SHORT_LEN,
)
ASN_SHORT_OCTET_STRINGS = strats.text(max_size=ASN_SHORT_LEN)


# TODO: Support long lengths here.
@hypot.given(id=ASN_SHORT_INTS, question=ASN_SHORT_IA5STRINGS)
@hypot.example(id=0, question="")
@hypot.settings(deadline=2 * 60000)
@pytest.mark.xdist_group(name="foo")
def test_foo_decode(
    id: int,
    question: str,
) -> None:
    foo_spec = asn1.compile_files(ASSETS + "foo.asn")
    foo = AsnTypeConverter().convert_spec(foo_spec)

    types = foo.values()
    # pprint({str(ty) for ty in types})
    model = PyRFLX(model=Model(types=[*prelude.MODEL.types, *types]))
    pkg = model.package("Foo")

    (expected := pkg.new_message("Question")).parse(
        foo_spec.encode("Question", {"id": id, "question": question})
    )

    assert expected.get("Tag_Class") == 0
    assert expected.get("Tag_Form") == 1
    assert expected.get("Tag_Num") == 16

    assert expected.get("Untagged_Value_id_Untagged_Value") == encode_signed_integer(id)

    assert expected.get("Untagged_Value_question_Untagged_Value") == question.encode()


@hypot.given(
    range=ASN_SHORT_INTS,
    name=ASN_SHORT_OCTET_STRINGS,
    payload=strats.one_of(
        ASN_SHORT_INTS,
        strats.lists(ASN_SHORT_INTS, max_size=3),
    ),
)
@hypot.example(range=0, name="", payload=0)
@hypot.settings(deadline=4 * 60000)
@pytest.mark.xdist_group(name="rocket")
def test_rocket_decode(
    range: int,
    name: str,
    payload: Union[int, list[int]],
) -> None:
    rocket_spec = asn1.compile_files(ASSETS + "rocket_mod.asn")
    rocket = AsnTypeConverter().convert_spec(rocket_spec)

    types = rocket.values()
    # pprint({str(ty) for ty in types})
    model = PyRFLX(model=Model(types=[*prelude.MODEL.types, *types]))
    pkg = model.package("World_Schema")

    name1 = name.encode()
    is_one = isinstance(payload, int)
    payload1 = ("one", payload) if is_one else ("many", payload)
    (expected := pkg.new_message("Rocket")).parse(
        rocket_spec.encode(
            "Rocket",
            {"range": range, "name": name1, "ident": "1.2.3.4", "payload": payload1},
        )
    )

    assert expected.get("Untagged_Value_range_Untagged_Value") == encode_signed_integer(
        range
    )
    assert expected.get("Untagged_Value_name_Untagged_Value") == name1
    assert expected.get("Untagged_Value_ident_Untagged_Value") == b"\x2a\x03\x04"

    got_payload = expected.get(
        f"Untagged_Value_payload_{'one' if is_one else 'many'}_Value"
    )
    if is_one:
        assert got_payload == encode_signed_integer(payload)
    else:
        assert [i.bytestring[2:] for i in cast(list[MessageValue], got_payload)] == [
            encode_signed_integer(i) for i in cast(list[int], payload)
        ]


@hypot.given(
    name=ASN_SHORT_OCTET_STRINGS,
    variant=strats.from_regex("[ac][ie]", fullmatch=True),
    payload=strats.one_of(
        ASN_SHORT_INTS,
        strats.lists(ASN_SHORT_INTS, max_size=4),
    ),
)
@pytest.mark.xdist_group(name="tagged")
def test_tagged_decode(
    name: str,
    variant: str,
    payload: Union[int, list[int]],
) -> None:
    tagged_spec = asn1.compile_files(ASSETS + "tagged.asn")
    tagged = AsnTypeConverter().convert_spec(tagged_spec)

    types = tagged.values()
    # pprint({str(ty) for ty in types})
    model = PyRFLX(model=Model(types=[*prelude.MODEL.types, *types]))
    pkg = model.package("Tagged_Test")

    name1 = name.encode()
    is_one = isinstance(payload, int)
    choice = variant + ("p" if is_one else "c")
    payload1 = (choice, payload)
    (expected := pkg.new_message("Tagged")).parse(
        tagged_spec.encode("Tagged", {"name": name1, "payload": payload1})
    )

    assert expected.get("Untagged_Value_name_Untagged_Value") == name1

    payload_field = f"Untagged_Value_payload_{choice}_Value"
    if variant.endswith("e"):  # Explicit tagging
        payload_field += "_Inner_Untagged_Value"
    if is_one:
        assert expected.get(payload_field) == encode_signed_integer(payload)
    else:
        assert [
            i.bytestring[2:]
            for i in cast(list[MessageValue], expected.get(payload_field))
        ] == [encode_signed_integer(i) for i in cast(list[int], payload)]
