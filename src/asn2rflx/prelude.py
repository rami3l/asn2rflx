from dataclasses import dataclass
from enum import Enum, unique
from typing import Protocol

import rflx.model as model
from overrides import overrides
from rflx.expression import Equal, Length, Mul, Number, Variable
from rflx.model.message import FINAL, INITIAL, Field, Link
from rflx.model.type_ import OPAQUE

PRELUDE_NAME: str = "Prelude"


@unique
class AsnTag(Enum):
    # HACK: We support only low tags for now. Actually there are low tags and high tags, and the latter is another LV coding in itself :(
    UT_BOOLEAN = 0x01
    UT_INTEGER = 0x02
    UT_BIT_STRING = 0x03
    UT_OCTET_STRING = 0x04
    UT_NULL = 0x05
    UT_OBJECT_IDENTIFIER = 0x06
    UT_Enumeration = 0x0A
    UT_UTF8String = 0x0C
    UT_SEQUENCE = 0x10
    UT_SET = 0x11
    UT_PrintableString = 0x13
    UT_IA5String = 0x16
    UT_UTCTime = 0x17
    UT_GeneralizedTime = 0x18


ASN_TAG_TY: model.Type = model.Enumeration(
    PRELUDE_NAME + "::Asn_Tag",
    literals=[(i.name, Number(i.value)) for i in AsnTag],
    size=Number(8),
    always_valid=True,
)

ASN_LENGTH_TY: model.Type = model.RangeInteger(
    PRELUDE_NAME + "::Asn_Length", first=Number(0x00), last=Number(0x81), size=Number(8)
)


@unique
class AsnRawBoolean(Enum):
    B_FALSE = 0x00
    B_TRUE = 0xFF


ASN_RAW_BOOLEAN_TY: model.Type = model.Enumeration(
    PRELUDE_NAME + "::Asn_Raw_Boolean",
    literals=[(i.name, Number(i.value)) for i in AsnRawBoolean],
    size=Number(8),
    always_valid=False,
)


class BerType(Protocol):
    @property
    def path(self) -> str:
        """The parent path of this type, eg. `Prelude`."""
        return ""

    @property
    def ident(self) -> str:
        """The identifier of this type, eg. `INTEGER`."""
        raise NotImplementedError

    @property
    def tag(self) -> AsnTag:
        raise NotImplementedError

    def v_ty(self) -> model.Type:
        """The `RAW` RecordFlux representation of this type."""
        return OPAQUE

    def lv_ty(self) -> model.Type:
        """The `UNTAGGED`, length-value (LV) encoding of this type."""
        f = Field
        links = [
            # TODO: Add support for long length 0x81
            Link(INITIAL, f("Length")),
            Link(f("Length"), f("Value"), size=Mul(Variable("Length"), Number(8))),
            Link(f("Value"), FINAL),
        ]
        fields = {f("Length"): ASN_LENGTH_TY, f("Value"): self.v_ty()}
        path = self.path + "::" if self.path else ""
        return model.Message(path + "UNTAGGED_" + self.ident, links, fields)

    def tlv_ty(self) -> model.Type:
        """The tag-length-value (TLV) encoding of this type."""
        # TODO: Handle non-universal tag (TAG_CLASS).
        f = Field
        tag_match = Equal(Variable("Tag"), Variable(self.tag.name))
        links = [
            Link(INITIAL, f("Tag")),
            # If the current tag is not what we want, then directly jump to FINAL.
            Link(f("Tag"), FINAL, condition=-tag_match),
            Link(f("Tag"), f("Untagged"), condition=tag_match),
            Link(f("Untagged"), FINAL),
        ]
        fields = {f("Tag"): ASN_TAG_TY, f("Untagged"): self.lv_ty()}
        path = self.path + "::" if self.path else ""
        return model.UnprovenMessage(path + self.ident, links, fields).merged()


@dataclass
class SimpleBerType(BerType):
    _path: str

    @property
    def path(self) -> str:
        return self._path

    _ident: str

    @property
    def ident(self) -> str:
        return self._ident

    _tag: AsnTag

    @property
    def tag(self) -> AsnTag:
        return self._tag


@dataclass
class DefiniteBerType(SimpleBerType):
    """A `SimpleBerType` with a known underlying RecordFlux Type."""

    _v_ty: model.Type

    @overrides
    def v_ty(self) -> model.Type:
        return self._v_ty

    @overrides
    def lv_ty(self) -> model.Type:
        """The `UNTAGGED`, length-value (LV) encoding of this type."""
        f = Field
        len_match = Equal(Length("Length"), Length(self.v_ty().full_name))
        links = [
            Link(INITIAL, f("Length")),
            Link(f("Length"), FINAL, condition=-len_match),
            Link(f("Length"), f("Value"), condition=len_match),
            Link(f("Value"), FINAL),
        ]
        fields = {f("Length"): ASN_LENGTH_TY, f("Value"): self.v_ty()}
        path = self.path + "::" if self.path else ""
        return model.Message(path + "UNTAGGED_" + self.ident, links, fields)


@dataclass
class StructuredBerType(BerType):
    ...


BOOLEAN = DefiniteBerType(
    PRELUDE_NAME, "BOOLEAN", AsnTag.UT_BOOLEAN, ASN_RAW_BOOLEAN_TY
)
INTEGER = SimpleBerType(PRELUDE_NAME, "INTEGER", AsnTag.UT_INTEGER)
