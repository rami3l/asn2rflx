from more_itertools import windowed

from asn2rflx.prelude import AsnTag
from rflx import model
from rflx.identifier import StrID
from rflx.model.message import FINAL, INITIAL, Field, Link


def simple_message(ident: StrID, fields: dict[StrID, model.Type]) -> model.Message:
    """
    Returns a simple RecordFlux message (record/struct) out of a mapping from field
    names to their repective types.
    """
    fields_ = {Field(f): t for f, t in fields.items()}
    links = [Link(*pair) for pair in windowed([INITIAL, *fields_.keys(), FINAL], 2)]
    return model.UnprovenMessage(ident, links, fields_).merged().proven()


def tagged_union_message(
    ident: StrID, variants: dict[StrID, tuple[AsnTag, model.Type]]
) -> model.Message:
    ...
