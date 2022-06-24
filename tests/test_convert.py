from typing import Union, cast

import asn1tools as asn1
import hypothesis as hypot
import hypothesis.strategies as strats
import pytest
from asn1tools.codecs.ber import encode_signed_integer
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
@hypot.settings(deadline=None)
@pytest.mark.xdist_group(name="foo")
def test_foo_decode(
    id: int,
    question: str,
) -> None:
    foo_spec = asn1.compile_files(ASSETS + "foo.asn")
    foo = AsnTypeConverter(skip_proof=False).convert_spec(foo_spec)

    types = foo.values()
    # pprint({str(ty) for ty in types})
    model = PyRFLX(model=Model(types=[*types]))
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
@hypot.example(range=0, name="", payload=[])
@hypot.settings(deadline=None)
@pytest.mark.xdist_group(name="rocket")
def test_rocket_decode(
    range: int,
    name: str,
    payload: Union[int, list[int]],
) -> None:
    rocket_spec = asn1.compile_files(ASSETS + "rocket_mod.asn")
    rocket = AsnTypeConverter(skip_proof=False).convert_spec(rocket_spec)

    types = rocket.values()
    # pprint({str(ty) for ty in types})
    model = PyRFLX(model=Model(types=[*types]))
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
@hypot.example(name="", variant="ai", payload=[])
@hypot.example(name="", variant="ae", payload=[])
@hypot.example(name="", variant="ci", payload=[])
@hypot.example(name="", variant="ce", payload=[])
@hypot.settings(deadline=None)
@pytest.mark.xdist_group(name="tagged")
def test_tagged_decode(
    name: str,
    variant: str,
    payload: Union[int, list[int]],
) -> None:
    tagged_spec = asn1.compile_files(ASSETS + "tagged.asn")
    tagged = AsnTypeConverter(skip_proof=False).convert_spec(tagged_spec)

    types = tagged.values()
    # pprint({str(ty) for ty in types})
    model = PyRFLX(model=Model(types=[*types]))
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


def test_snmpv1_decode() -> None:
    snmpv1_spec = asn1.compile_files(
        [
            ASSETS + "rfc1155.asn",
            ASSETS + "rfc1157.asn",
        ]
    )
    snmpv1 = AsnTypeConverter(skip_proof=True).convert_spec(snmpv1_spec)

    types = snmpv1.values()
    # pprint({str(ty) for ty in types})
    model = PyRFLX(model=Model(types=[*types]))
    pkg = model.package("RFC1157_SNMP")

    (expected := pkg.new_message("Message")).parse(
        b"0G\x02\x01\x00\x04\x06public\xa2:\x02\x01'\x02\x01\x00\x02\x01\x000/"
        b"0\x11\x06\x08+\x06\x01\x02\x01\x01\x05\x00\x04\x05B6300"
        b"0\x1a\x06\x08+\x06\x01\x02\x01\x01\x06\x00\x04\x0eChandra's cube"
    )

    assert expected.get("Tag_Class") == 0
    assert expected.get("Tag_Form") == 1
    assert expected.get("Tag_Num") == 16

    pdu = "Untagged_Value_data_get_response_Value_"

    assert expected.get(pdu + "request_id_Untagged_Value") == b"\x27"
    assert expected.get(pdu + "error_status_Untagged_Value") == b"\x00"
    assert expected.get(pdu + "error_index_Untagged_Value") == b"\x00"

    variable_bindings = pdu + "variable_bindings_Untagged_Value"
    assert [
        i.bytestring[2:]
        for i in cast(list[MessageValue], expected.get(variable_bindings))
    ] == [
        b"\x06\x08+\x06\x01\x02\x01\x01\x05\x00" + b"\x04\x05B6300",
        b"\x06\x08+\x06\x01\x02\x01\x01\x06\x00" + b"\x04\x0eChandra's cube",
    ]
