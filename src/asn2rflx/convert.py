from dataclasses import dataclass
from functools import singledispatchmethod
from typing import cast

from asn1tools.codecs import ber

from asn2rflx import prelude
from asn2rflx.rflx import simple_message
from rflx import model
from rflx.identifier import ID, StrID


@dataclass
class AsnTypeConverter:
    """A converter from `asn1tools`' BER types to RecordFlux types."""

    base_path: StrID = ""

    # In Python 3.10+ this should be done with the `match-case` construct...
    @singledispatchmethod
    def convert(self, _, relpath: StrID = "") -> model.Type:
        raise NotImplementedError

    # ASN.1 Types

    @convert.register  # type: ignore [no-redef]
    def _(self, _: ber.Boolean, relpath: StrID = "") -> model.Type:
        return prelude.BOOLEAN.tlv_ty()

    @convert.register  # type: ignore [no-redef]
    def _(self, _: ber.Null, relpath: StrID = "") -> model.Type:
        return prelude.NULL.tlv_ty()

    @convert.register  # type: ignore [no-redef]
    def _(self, _: ber.Integer, relpath: StrID = "") -> model.Type:
        return prelude.INTEGER.tlv_ty()

    @convert.register  # type: ignore [no-redef]
    def _(self, _: ber.ObjectIdentifier, relpath: StrID = "") -> model.Type:
        return prelude.OBJECT_IDENTIFIER.tlv_ty()

    @convert.register  # type: ignore [no-redef]
    def _(self, _: ber.BitString, relpath: StrID = "") -> model.Type:
        return prelude.BIT_STRING.tlv_ty()

    @convert.register  # type: ignore [no-redef]
    def _(self, _: ber.OctetString, relpath: StrID = "") -> model.Type:
        return prelude.OCTET_STRING.tlv_ty()

    @convert.register  # type: ignore [no-redef]
    def _(self, _: ber.PrintableString, relpath: StrID = "") -> model.Type:
        return prelude.PrintableString.tlv_ty()

    @convert.register  # type: ignore [no-redef]
    def _(self, _: ber.IA5String, relpath: StrID = "") -> model.Type:
        return prelude.IA5String.tlv_ty()

    # ASN.1 type constructors

    @convert.register  # type: ignore [no-redef]
    def _(self, message: ber.Sequence, relpath: StrID = "") -> model.Type:
        fields = cast(list[ber.Type], message.root_members)
        return prelude.SequenceBerType(
            simple_message(
                ID(list(filter(None, [self.base_path, relpath, message.name]))),
                {field.name: self.convert(field) for field in fields},
            )
        )

    @convert.register  # type: ignore [no-redef]
    def _(self, sequence: ber.SequenceOf, relpath: StrID = "") -> model.Type:
        return prelude.SequenceOfBerType(
            ID(list(filter(None, [self.base_path, relpath, sequence.name]))),
            self.convert(sequence.element_type),
        )

    @convert.register  # type: ignore [no-redef]
    def _(self, _: ber.Choice) -> model.Type:
        # TODO: Finish this!
        return ...
