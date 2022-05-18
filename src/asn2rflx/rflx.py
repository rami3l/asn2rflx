from more_itertools import windowed

from rflx import model
from rflx.identifier import StrID
from rflx.model.message import FINAL, INITIAL, Field, Link


def to_simple_message(
    ident: StrID, fields: dict[StrID, model.Type]
) -> model.AbstractMessage:
    """
    Returns a simple RecordFlux message (record/struct) out of a mapping from field
    names to their repective types.
    """
    fields_ = {Field(f): t for f, t in fields.items()}
    links = [Link(*pair) for pair in windowed([INITIAL, *fields_.keys(), FINAL], 2)]
    return model.Message(ident, links, fields_)
