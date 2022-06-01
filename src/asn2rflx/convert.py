from dataclasses import dataclass
from functools import singledispatchmethod
from typing import cast

import asn1tools as asn1
from asn1tools.codecs import ber
from frozendict import frozendict
from rflx import model
from rflx.identifier import ID

from asn2rflx import prelude
from asn2rflx.utils import strid


@dataclass
class AsnTypeConverter:
    """A converter from `asn1tools`' BER types to RecordFlux types."""

    base_path: str = ""

    # In Python 3.10+ this should be done with the `match-case` construct...
    @singledispatchmethod
    def convert(self, _, relpath: str = "") -> prelude.BerType:
        raise NotImplementedError

    # ASN.1 Types

    @convert.register  # type: ignore [no-redef]
    def _(self, _: ber.Boolean, relpath: str = "") -> prelude.BerType:
        return prelude.BOOLEAN

    @convert.register  # type: ignore [no-redef]
    def _(self, _: ber.Null, relpath: str = "") -> prelude.BerType:
        return prelude.NULL

    @convert.register  # type: ignore [no-redef]
    def _(self, _: ber.Integer, relpath: str = "") -> prelude.BerType:
        return prelude.INTEGER

    @convert.register  # type: ignore [no-redef]
    def _(self, _: ber.ObjectIdentifier, relpath: str = "") -> prelude.BerType:
        return prelude.OBJECT_IDENTIFIER

    @convert.register  # type: ignore [no-redef]
    def _(self, _: ber.BitString, relpath: str = "") -> prelude.BerType:
        return prelude.BIT_STRING

    @convert.register  # type: ignore [no-redef]
    def _(self, _: ber.OctetString, relpath: str = "") -> prelude.BerType:
        return prelude.OCTET_STRING

    @convert.register  # type: ignore [no-redef]
    def _(self, _: ber.PrintableString, relpath: str = "") -> prelude.BerType:
        return prelude.PrintableString

    @convert.register  # type: ignore [no-redef]
    def _(self, _: ber.IA5String, relpath: str = "") -> prelude.BerType:
        return prelude.IA5String

    # ASN.1 type constructors

    @convert.register  # type: ignore [no-redef]
    def _(self, message: ber.Sequence, relpath: str = "") -> prelude.BerType:
        fields = cast(list[ber.Type], message.root_members)
        return prelude.SequenceBerType(
            strid(list(filter(None, [self.base_path, relpath]))),
            message.name,
            frozendict({field.name: self.convert(field, relpath) for field in fields}),
        )

    @convert.register  # type: ignore [no-redef]
    def _(self, sequence: ber.SequenceOf, relpath: str = "") -> prelude.BerType:
        return prelude.SequenceOfBerType(
            strid(list(filter(None, [self.base_path, relpath]))),
            self.convert(sequence.element_type, relpath).tlv_ty(),
        )

    @convert.register  # type: ignore [no-redef]
    def _(self, message: ber.Choice, relpath: str = "") -> prelude.BerType:
        fields = cast(list[ber.Type], message.members)
        return prelude.ChoiceBerType(
            strid(list(filter(None, [self.base_path, relpath]))),
            message.name,
            frozendict({field.name: self.convert(field, relpath) for field in fields}),
        )

    def convert_spec(self, spec: asn1.compiler.Specification) -> dict[ID, model.Type]:
        """
        Converts an ASN.1 specification to a mapping from qualified RecordFlux
        identifiers to the corresponding RecordFlux type.
        """
        res: dict[ID, model.Type] = {}
        for path, tys in spec.modules.items():
            res |= {
                (ty1 := self.convert(ty.type, path).tlv_ty()).qualified_identifier: ty1
                for ty in tys.values()
            }
        return res
