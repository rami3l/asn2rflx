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
        converter.convert(cast(CompiledType, ty).type) for ty in foo.types.values()
    } == set()
