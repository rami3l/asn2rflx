from functools import singledispatch

from asn1tools.codecs import ber
from rflx import model

from asn2rflx import prelude


@singledispatch
def to_rflx(_) -> model.Type:
    raise NotImplementedError


@to_rflx.register
def _(_: ber.Boolean) -> model.Type:
    return prelude.BOOLEAN.tlv_ty()


@to_rflx.register
def _(_: ber.Null) -> model.Type:
    return prelude.NULL.tlv_ty()


@to_rflx.register
def _(_: ber.Integer) -> model.Type:
    return prelude.INTEGER.tlv_ty()
