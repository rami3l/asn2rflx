from dataclasses import dataclass
from functools import singledispatchmethod
from typing import cast

from asn1tools.codecs import ber

from asn2rflx import prelude
from asn2rflx.rflx import to_simple_message
from rflx import model
from rflx.identifier import ID, StrID


@dataclass
class AsnTypeConverter:
    """A converter from `asn1tools`' BER types to RecordFlux types."""

    base_path: StrID = ""

    # In Python 3.10+ this should be done with the `match-case` construct...
    @singledispatchmethod
    def convert(self, _) -> model.Type:
        raise NotImplementedError

    # ASN.1 Types

    @convert.register  # type: ignore [no-redef]
    def _(self, _: ber.Boolean) -> model.Type:
        return prelude.BOOLEAN.tlv_ty()

    @convert.register  # type: ignore [no-redef]
    def _(self, _: ber.Null) -> model.Type:
        return prelude.NULL.tlv_ty()

    @convert.register  # type: ignore [no-redef]
    def _(self, _: ber.Integer) -> model.Type:
        return prelude.INTEGER.tlv_ty()

    @convert.register  # type: ignore [no-redef]
    def _(self, _: ber.ObjectIdentifier) -> model.Type:
        return prelude.OBJECT_IDENTIFIER.tlv_ty()

    @convert.register  # type: ignore [no-redef]
    def _(self, _: ber.BitString) -> model.Type:
        return prelude.BIT_STRING.tlv_ty()

    @convert.register  # type: ignore [no-redef]
    def _(self, _: ber.OctetString) -> model.Type:
        return prelude.OCTET_STRING.tlv_ty()

    @convert.register  # type: ignore [no-redef]
    def _(self, _: ber.PrintableString) -> model.Type:
        return prelude.PrintableString.tlv_ty()

    @convert.register  # type: ignore [no-redef]
    def _(self, _: ber.IA5String) -> model.Type:
        return prelude.IA5String.tlv_ty()

    # ASN.1 type constructors

    @convert.register  # type: ignore [no-redef]
    def _(self, message: ber.Sequence) -> model.Type:
        fields = cast(list[ber.Type], message.root_members)
        return to_simple_message(
            ID([self.base_path, message.name]),
            {field.name: self.convert(field) for field in fields},
        )

    @convert.register  # type: ignore [no-redef]
    def _(self, sequence: ber.SequenceOf) -> model.Type:
        return prelude.SequenceOfBerType(
            ID([self.base_path, sequence.name]),
            self.convert(sequence.element_type),
        )

    @convert.register  # type: ignore [no-redef]
    def _(self, _: ber.Choice) -> model.Type:
        # TODO: Finish this!
        return ...
