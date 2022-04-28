from abc import abstractmethod
from dataclasses import dataclass
from itertools import starmap
from typing import Protocol

import rflx.model as model
from more_itertools import sliding_window
from rflx.expression import Number
from rflx.model.message import Field, Link

PRELUDE_NAME: str = "Prelude"

# HACK: We support only low tags for now. Actually there are low tags and high tags, and the latter is another LV coding in itself :(
TAG_T: model.Type = model.RangeInteger(
    f"{PRELUDE_NAME}::Tag_T", first=Number(0), last=Number(30), size=Number(16**2)
)


class BerType(Protocol):
    @property
    def name(self) -> str:
        # TODO: Should be class getter?
        raise NotImplementedError

    def rflx_ty(self) -> model.Type:
        """The raw RecordFlux representation of this type."""
        raise NotImplementedError

    @property
    def tag(self) -> int:
        raise NotImplementedError

    def lv_ty(self) -> model.Type:
        """The untagged length-value (LV) encoding of this type."""
        raise NotImplementedError

    def tlv_ty(self) -> model.Type:
        """The tag-length-value (TLV) encoding of this type."""
        links = sliding_window(["Initial", "Tag", "Untagged", "Final"], n=2)
        fields = {"Tag": TAG_T, "Untagged": self.lv_ty()}
        return model.Message(
            f"{PRELUDE_NAME}::{self.name}",
            structure=list(starmap(Link, links)),
            types={Field(f): t for f, t in fields.items()},
        )


@dataclass()
class SimpleBerType(BerType):
    name: str


class StructuredBerType(BerType):
    ...
