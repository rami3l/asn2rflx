from functools import singledispatch
from typing import cast

from asn1tools.codecs import ber

from asn2rflx import prelude
from asn2rflx.rflx import to_simple_message
from rflx import model


# In Python 3.10+ this should be done with the `match-case` construct...
@singledispatch
def to_rflx_ty(_: ber.Type) -> model.Type:
    raise NotImplementedError


# ASN.1 Types


@to_rflx_ty.register  # type: ignore [no-redef]
def _(_: ber.Boolean) -> model.Type:
    return prelude.BOOLEAN.tlv_ty()


@to_rflx_ty.register  # type: ignore [no-redef]
def _(_: ber.Null) -> model.Type:
    return prelude.NULL.tlv_ty()


@to_rflx_ty.register  # type: ignore [no-redef]
def _(_: ber.Integer) -> model.Type:
    return prelude.INTEGER.tlv_ty()


@to_rflx_ty.register  # type: ignore [no-redef]
def _(_: ber.ObjectIdentifier) -> model.Type:
    return prelude.OBJECT_IDENTIFIER.tlv_ty()


@to_rflx_ty.register  # type: ignore [no-redef]
def _(_: ber.BitString) -> model.Type:
    return prelude.BIT_STRING.tlv_ty()


@to_rflx_ty.register  # type: ignore [no-redef]
def _(_: ber.OctetString) -> model.Type:
    return prelude.OCTET_STRING.tlv_ty()


@to_rflx_ty.register  # type: ignore [no-redef]
def _(_: ber.PrintableString) -> model.Type:
    return prelude.PrintableString.tlv_ty()


@to_rflx_ty.register  # type: ignore [no-redef]
def _(_: ber.IA5String) -> model.Type:
    return prelude.IA5String.tlv_ty()


# ASN.1 type constructors


@to_rflx_ty.register  # type: ignore [no-redef]
def _(message: ber.Sequence) -> model.Type:
    fields = cast(list[ber.Type], message.root_members)
    # TODO: Use a class to store parent path and stuff. So that the message.name must prepend its parent.
    return to_simple_message(
        message.name, {field.name: to_rflx_ty(field) for field in fields}
    )


@to_rflx_ty.register  # type: ignore [no-redef]
def _(sequence: ber.SequenceOf) -> model.Type:
    return prelude.SequenceOfBerType(sequence.name, to_rflx_ty(sequence.element_type))


@to_rflx_ty.register  # type: ignore [no-redef]
def _(_: ber.Choice) -> model.Type:
    # TODO: Finish this!
    return ...
