from dataclasses import dataclass
from enum import Enum, unique
from functools import lru_cache, reduce
from typing import Protocol, cast

from asn1tools.codecs.ber import Class as AsnTagClass
from asn1tools.codecs.ber import Tag as AsnTagNum
from more_itertools import flatten
from overrides import overrides

from asn2rflx.rflx import to_simple_message
from rflx import model
from rflx.expression import And, Equal, Expr, Length, Mul, Not, Number, Variable
from rflx.identifier import ID
from rflx.model.message import FINAL, INITIAL, Field, Link
from rflx.model.type_ import OPAQUE

PRELUDE_NAME: str = "Prelude"


class AsnTagForm:
    PRIMITIVE = 0
    CONSTRUCTED = 1


@dataclass(frozen=True)
class AsnTag:
    class_: int = AsnTagClass.UNIVERSAL
    form: int = AsnTagForm.PRIMITIVE
    num: int = AsnTagNum.END_OF_CONTENTS

    @classmethod
    @lru_cache(16)
    def ty(cls) -> model.Type:
        """The ASN Tag message type in RecordFlux."""
        return to_simple_message(
            ID([PRELUDE_NAME, "Asn_Tag"]),
            {
                "Class": ASN_TAG_CLASS_TY,
                "Form": ASN_TAG_FORM_TY,
                "Num": ASN_TAG_NUM_TY,
            },
        )

    @lru_cache(16)
    def matches(self, ident: str) -> Expr:
        kvs = {"Class": self.class_, "Form": self.form, "Num": self.num}
        eqs = (
            cast(Expr, Equal(Variable(f"{ident}_{k}"), Number(v)))
            for k, v in kvs.items()
        )
        return reduce(And, eqs)


@unique
class AsnRawBoolean(Enum):
    B_FALSE = 0x00
    B_TRUE = 0xFF


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

    @lru_cache(16)
    def v_ty(self) -> model.Type:
        """The `RAW` RecordFlux representation of this type."""
        return OPAQUE

    @lru_cache(16)
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
        full_ident = ID(list(filter(None, [self.path, "UNTAGGED_" + self.ident])))
        return model.UnprovenMessage(full_ident, links, fields).merged().proven()

    @lru_cache(16)
    def tlv_ty(self) -> model.Type:
        """The tag-length-value (TLV) encoding of this type."""
        # TODO: Handle non-universal tag (TAG_CLASS).
        f = Field
        tag_match = self.tag.matches("Tag")
        links = [
            Link(INITIAL, f("Tag")),
            # If the current tag is not what we want, then directly jump to FINAL.
            Link(f("Tag"), FINAL, condition=Not(tag_match)),
            Link(f("Tag"), f("Untagged"), condition=tag_match),
            Link(f("Untagged"), FINAL),
        ]
        fields = {f("Tag"): ASN_TAG_TY, f("Untagged"): self.lv_ty()}
        full_ident = ID(list(filter(None, [self.path, self.ident])))
        return model.UnprovenMessage(full_ident, links, fields).merged().proven()


@dataclass(frozen=True)
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


@dataclass(frozen=True)
class DefiniteBerType(SimpleBerType):
    """A `SimpleBerType` with a known underlying RecordFlux Type."""

    _v_ty: model.Type

    @lru_cache(16)
    @overrides
    def v_ty(self) -> model.Type:
        return self._v_ty

    @lru_cache(16)
    @overrides
    def lv_ty(self) -> model.Type:
        """The `UNTAGGED`, length-value (LV) encoding of this type."""
        f = Field
        v_ty = self.v_ty()
        links = [Link(INITIAL, f("Length"))]
        fields = {f("Length"): cast(model.Type, ASN_LENGTH_TY)}
        is_null_v_ty = isinstance(v_ty, model.AbstractMessage) and (
            not v_ty.structure or not v_ty.types
        )
        if is_null_v_ty:
            # Special case for NULL, since its v_ty is `null message`.
            links.append(Link(f("Length"), FINAL))
        else:
            len_match = Equal(Length("Length"), Length(v_ty.full_name))
            links += [
                Link(f("Length"), FINAL, condition=-len_match),
                Link(f("Length"), f("Value"), condition=len_match),
                Link(f("Value"), FINAL),
            ]
            fields[f("Value")] = v_ty
        full_ident = ID(list(filter(None, [self.path, "UNTAGGED_" + self.ident])))
        return model.Message(full_ident, links, fields)


@dataclass(frozen=True)
class SequenceBerType(BerType):
    _v_ty: model.Type

    @overrides
    def v_ty(self) -> model.Type:
        return self._v_ty

    @property
    def path(self) -> str:
        return str(self._v_ty.package)

    @property
    def ident(self) -> str:
        return self._v_ty.name

    @property
    def tag(self) -> AsnTag:
        return AsnTag(form=AsnTagForm.CONSTRUCTED, num=AsnTagNum.SEQUENCE)


@dataclass(frozen=True)
class SequenceOfBerType(BerType):
    _path: str

    @property
    def path(self) -> str:
        return self._path

    @property
    def ident(self) -> str:
        return "SEQUENCE_OF_" + self.elem_tlv_ty.name

    @property
    def tag(self) -> AsnTag:
        return AsnTag(form=AsnTagForm.CONSTRUCTED, num=AsnTagNum.SEQUENCE)

    elem_tlv_ty: model.Type

    @lru_cache(16)
    @overrides
    def v_ty(self) -> model.Type:
        return model.Sequence(
            ID(list(filter(None, [self.path, "Asn_Raw_" + self.ident]))),
            self.elem_tlv_ty,
        )


HELPER_TYPES = [
    ASN_TAG_CLASS_TY := model.RangeInteger(
        ID([PRELUDE_NAME, "Asn_Tag_Class"]),
        first=Number(0b00),
        last=Number(0b11),
        size=Number(2),
    ),
    ASN_TAG_FORM_TY := model.RangeInteger(
        ID([PRELUDE_NAME, "Asn_Tag_Form"]),
        first=Number(0b0),
        last=Number(0b1),
        size=Number(1),
    ),
    ASN_TAG_NUM_TY := model.RangeInteger(
        ID([PRELUDE_NAME, "Asn_Tag_Num"]),
        first=Number(0b00000),
        last=Number(0b11111),
        size=Number(5),
    ),
    ASN_TAG_TY := AsnTag.ty(),
    ASN_LENGTH_TY := model.RangeInteger(
        ID([PRELUDE_NAME, "Asn_Length"]),
        first=Number(0x00),
        last=Number(0x7F),
        size=Number(8),
    ),
    ASN_RAW_BOOLEAN_TY := model.Enumeration(
        ID([PRELUDE_NAME, "Asn_Raw_BOOLEAN"]),
        literals=[(i.name, Number(i.value)) for i in AsnRawBoolean],
        size=Number(8),
        always_valid=False,
    ),
    ASN_RAW_NULL_TY := model.Message(
        ID([PRELUDE_NAME, "Asn_Raw_NULL"]),
        structure=[],
        types={},
        # HACK: See https://github.com/Componolit/RecordFlux/blob/79de5e735fa0ce9889f2dd60efc156ec5b743d11/tests/data/models.py#L40
        skip_proof=True,
    ),
]

BER_TYPES = [
    # NOTE: To avoid colliding with a keyword,
    # an `_` is needed at the end of `BOOLEAN` and `NULL`.
    BOOLEAN := DefiniteBerType(
        PRELUDE_NAME, "BOOLEAN_", AsnTag(num=AsnTagNum.BOOLEAN), ASN_RAW_BOOLEAN_TY
    ),
    NULL := DefiniteBerType(
        PRELUDE_NAME, "NULL_", AsnTag(num=AsnTagNum.NULL), ASN_RAW_NULL_TY
    ),
    INTEGER := SimpleBerType(PRELUDE_NAME, "INTEGER", AsnTag(num=AsnTagNum.INTEGER)),
    OBJECT_IDENTIFIER := SimpleBerType(
        PRELUDE_NAME, "OBJECT_IDENTIFIER", AsnTag(num=AsnTagNum.OBJECT_IDENTIFIER)
    ),
    # TODO: In BER, strings can be primitive or structured.
    # Now we only consider the case where it's simple.
    BIT_STRING := SimpleBerType(
        PRELUDE_NAME, "BIT_STRING", AsnTag(num=AsnTagNum.BIT_STRING)
    ),
    OCTET_STRING := SimpleBerType(
        PRELUDE_NAME, "OCTET_STRING", AsnTag(num=AsnTagNum.OCTET_STRING)
    ),
    PrintableString := SimpleBerType(
        PRELUDE_NAME, "PrintableString", AsnTag(num=AsnTagNum.PRINTABLE_STRING)
    ),
    # T61String := SimpleBerType(
    #     PRELUDE_NAME, "T61String", AsnTag(num=AsnTagNum.T61_STRING)
    # ),
    IA5String := SimpleBerType(
        PRELUDE_NAME, "IA5String", AsnTag(num=AsnTagNum.IA5_STRING)
    ),
]

MODEL = model.Model(
    types=HELPER_TYPES + list(flatten([ty.lv_ty(), ty.tlv_ty()] for ty in BER_TYPES))
)
"""Base prelude without any structured types."""
