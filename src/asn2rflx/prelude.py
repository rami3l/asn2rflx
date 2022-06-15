from dataclasses import dataclass
from enum import Enum, unique
from functools import lru_cache, reduce
from typing import Mapping, Optional, Protocol, cast

from asn1tools.codecs.ber import Tag as AsnTagNum
from frozendict import frozendict
from more_itertools import windowed
from more_itertools.recipes import flatten
from rflx import model
from rflx.expression import And, Equal, Expr, Mul, Not, Number, Size, Variable
from rflx.identifier import ID
from rflx.model.message import FINAL, INITIAL, Field, Link
from rflx.model.type_ import OPAQUE

from asn2rflx.error import Asn2RflxError
from asn2rflx.utils import strid

PRELUDE_NAME: str = "Prelude"


class AsnTagClass:
    UNIVERSAL = 0b00
    APPLICATION = 0b01
    CONTEXT_SPECIFIC = 0b10
    PRIVATE = 0b11


class AsnTagForm:
    PRIMITIVE = 0
    CONSTRUCTED = 1


@dataclass(frozen=True)
class AsnTag:
    num: int = AsnTagNum.END_OF_CONTENTS
    class_: int = AsnTagClass.UNIVERSAL
    form: int = AsnTagForm.PRIMITIVE

    LONG_TAG_UNSUPPORTED_ERROR = NotImplementedError(
        "Long ASN.1 Tags are not supported for the moment"
    )

    @classmethod
    @lru_cache
    def ty(cls) -> model.Type:
        """The ASN Tag message type in RecordFlux."""
        return simple_message(
            strid([PRELUDE_NAME, "Asn_Tag"]),
            {
                "Class": ASN_TAG_CLASS_TY,
                "Form": ASN_TAG_FORM_TY,
                "Num": ASN_TAG_NUM_TY,
            },
            skip_proof=False,
        )

    @lru_cache
    def matches(self, ident: str) -> Expr:
        kvs = {"Class": self.class_, "Form": self.form, "Num": self.num}
        eqs = (
            cast(Expr, Equal(Variable(f"{ident}_{k}"), Number(v)))
            for k, v in kvs.items()
        )
        return reduce(And, eqs)

    @property
    def as_bytearray(self) -> bytearray:
        byte: int = (self.class_ << 1 | self.form) << 5 | self.num
        return bytearray([byte])

    @classmethod
    def from_bytearray(cls, arr: bytearray) -> "AsnTag":
        if len(arr) != 1:
            raise cls.LONG_TAG_UNSUPPORTED_ERROR
        byte: int = arr[0]
        return AsnTag(
            num=byte & ((1 << 5) - 1),
            form=byte >> 5 & 1,
            class_=byte >> 6,
        )


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
    def full_ident(self) -> ID:
        """The fully qualified identifier of this type, eg. `Prelude::INTEGER`."""
        return ID(list(filter(None, [self.path, self.ident])))

    @property
    def tag(self) -> AsnTag:
        raise NotImplementedError(
            f"no tag definition found for type `{type(self)}`: got {self}"
        )

    @lru_cache(1)
    def v_ty(self, skip_proof: bool = False) -> model.Type:
        """The `RAW` RecordFlux representation of this type."""
        return OPAQUE

    @lru_cache
    def lv_ty(self, skip_proof: bool = False) -> model.Type:
        """The `Untagged`, length-value (LV) encoding of this type."""
        f = Field
        links = [
            # TODO: Add support for long length 0x81
            Link(INITIAL, f("Length")),
            Link(f("Length"), f("Value"), size=Mul(Variable("Length"), Number(8))),
            Link(f("Value"), FINAL),
        ]
        fields = {
            f("Length"): ASN_LENGTH_TY,
            f("Value"): self.v_ty(skip_proof=skip_proof),
        }
        full_ident = strid(list(filter(None, [self.path, "Untagged_" + self.ident])))
        try:
            return (
                model.UnprovenMessage(full_ident, links, fields)
                .merged()
                .proven(skip_proof=skip_proof)
            )
        except Exception as e:
            raise Asn2RflxError(f"invalid message detected: `{self}`") from e

    @lru_cache
    def tlv_ty(self, skip_proof: bool = False) -> model.Type:
        """The tag-length-value (TLV) encoding of this type."""
        lv_ty = self.lv_ty(skip_proof=skip_proof)
        f = Field
        try:
            tag_match = self.tag.matches("Tag")
        except NotImplementedError:
            return self.v_ty(skip_proof=skip_proof)
        links = [
            Link(INITIAL, f("Tag")),
            # If the current tag is not what we want, then directly jump to FINAL.
            Link(f("Tag"), FINAL, condition=Not(tag_match)),
            Link(f("Tag"), f("Untagged"), condition=tag_match),
            Link(f("Untagged"), FINAL),
        ]
        fields = {f("Tag"): ASN_TAG_TY, f("Untagged"): lv_ty}
        try:
            res = model.UnprovenMessage(self.full_ident, links, fields)
            return res.merged().proven(skip_proof=skip_proof)
        except Exception as e:
            raise Asn2RflxError(f"invalid message detected: `{self.full_ident}`") from e

    @lru_cache
    def implicitly_tagged(
        self, tag: AsnTag, path: Optional[str]
    ) -> "ImplicitlyTaggedBerType":
        """
        The `IMPLICIT` variant of this type.
        Its tag-length-value (TLV) encoding is equivalent to
        its regular TLV encoding with a custom tag override.
        """
        return ImplicitlyTaggedBerType(
            self,
            AsnTag(num=tag.num, class_=tag.class_, form=self.tag.form),
            path or self.path,
        )

    @lru_cache
    def explicitly_tagged(self, tag: AsnTag, path: str) -> "ImplicitlyTaggedBerType":
        """
        The `EXPLICIT` tag-length-value (TLV) encoding of this type.
        It is equivalent to its regular TLV encoding nested in an implicitly-tagged,
        single-field `SEQUENCE` type.
        """
        return SequenceBerType(
            path,
            "Explicit_" + self.ident,
            frozendict({"Inner": self}),
        ).implicitly_tagged(tag, path)


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

    @lru_cache
    def v_ty(self, skip_proof: bool = False) -> model.Type:
        return self._v_ty

    @lru_cache
    def lv_ty(self, skip_proof: bool = False) -> model.Type:
        """The `Untagged`, length-value (LV) encoding of this type."""
        f = Field
        v_ty = self.v_ty(skip_proof=skip_proof)
        links = [Link(INITIAL, f("Length"))]
        fields = {f("Length"): cast(model.Type, ASN_LENGTH_TY)}
        is_null_v_ty = isinstance(v_ty, model.AbstractMessage) and (
            not v_ty.structure or not v_ty.types
        )
        if is_null_v_ty:
            # Special case for NULL, since its v_ty is `null message`.
            links.append(Link(f("Length"), FINAL))
        else:
            len_match = Equal(Size("Length"), Size(v_ty.full_name))
            links += [
                Link(f("Length"), FINAL, condition=-len_match),
                Link(f("Length"), f("Value"), condition=len_match),
                Link(f("Value"), FINAL),
            ]
            fields[f("Value")] = v_ty
        full_ident = strid(list(filter(None, [self.path, "Untagged_" + self.ident])))
        return model.Message(full_ident, links, fields, skip_proof=skip_proof)


@dataclass(frozen=True)
class SequenceBerType(BerType):
    _path: str

    @property
    def path(self) -> str:
        return self._path

    _ident: str

    @property
    def ident(self) -> str:
        return self._ident

    fields: Mapping[str, BerType]

    @lru_cache(1)
    def v_ty(self, skip_proof: bool = False) -> model.Type:
        return simple_message(
            strid(self.full_ident),
            {f: t.tlv_ty(skip_proof) for f, t in self.fields.items()},
            skip_proof=skip_proof,
        )

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

    @lru_cache
    def v_ty(self, skip_proof: bool = False) -> model.Type:
        return model.Sequence(
            strid(list(filter(None, [self.path, "Asn_Raw_" + self.ident]))),
            self.elem_tlv_ty,
        )


@dataclass(frozen=True)
class ChoiceBerType(BerType):
    _path: str

    @property
    def path(self) -> str:
        return self._path

    _ident: str

    @property
    def ident(self) -> str:
        return self._ident

    variants: Mapping[str, BerType]

    @lru_cache(1)
    def v_ty(self, skip_proof: bool = False) -> model.Type:
        variants: dict[str, tuple[AsnTag, model.Type]] = {}

        def populate_variants(f: str, t: BerType, prefix: str = "") -> None:
            pf = f"{prefix}_{f}" if prefix else f
            if isinstance(t, ChoiceBerType):
                # Workaround for nested choices: expose the variants
                # of inner choices to the outer choice.
                for f1, t1 in t.variants.items():
                    populate_variants(f1, t1, prefix=pf)
            else:
                variants[pf] = (
                    t.tag,
                    t.lv_ty(skip_proof=skip_proof),
                )

        try:
            for f, t in self.variants.items():
                populate_variants(f, t)
            return tagged_union_message(
                strid(self.full_ident), variants, skip_proof=skip_proof
            )
        except NotImplementedError as e:
            raise ValueError(
                "cannot construct CHOICE from untagged or invalid BerType"
            ) from e


@dataclass(frozen=True)
class ImplicitlyTaggedBerType(BerType):
    base: BerType

    _tag: AsnTag

    @property
    def tag(self) -> AsnTag:
        return self._tag

    _path: str

    @property
    def path(self) -> str:
        if self.tag.class_ == AsnTagClass.UNIVERSAL:
            return PRELUDE_NAME
        return self._path

    @property
    def ident(self) -> str:
        if self.tag.class_ == AsnTagClass.UNIVERSAL:
            return self.base.ident
        if self.tag.class_ == AsnTagClass.APPLICATION:
            prefix = "Appl"
        elif self.tag.class_ == AsnTagClass.CONTEXT_SPECIFIC:
            prefix = "Ctxt"
        elif self.tag.class_ == AsnTagClass.PRIVATE:
            prefix = "Priv"
        return f"{prefix}{self.tag.num:02}_{self.base.ident}"

    def v_ty(self, skip_proof: bool = False) -> model.Type:  # type: ignore [override]
        return self.base.v_ty(skip_proof=skip_proof)

    def lv_ty(self, skip_proof: bool = False) -> model.Type:  # type: ignore [override]
        return self.base.lv_ty(skip_proof=skip_proof)


def simple_message(
    ident: str, fields: dict[str, model.Type], skip_proof: bool = False
) -> model.Message:
    """
    Returns a simple RecordFlux message (record/struct) out of a mapping from field
    names to their respective types.
    """
    fields_ = {Field(f): t for f, t in fields.items()}
    links = [Link(*pair) for pair in windowed([INITIAL, *fields_.keys(), FINAL], 2)]

    try:
        res = model.UnprovenMessage(ident, links, fields_)
        return res.merged().proven(skip_proof=skip_proof)
    except Exception as e:
        raise Asn2RflxError(f"invalid message detected: `{ident}`") from e


def tagged_union_message(
    ident: str, variants: dict[str, tuple[AsnTag, model.Type]], skip_proof: bool = False
) -> model.Message:
    """
    Returns a RecordFlux message representing a tagged union out of a mapping from
    field names to a tuple containing the tag and the type for each variant.
    """
    fields = {Field("Tag"): ASN_TAG_TY} | {
        Field(f): t for f, (_, t) in variants.items()
    }
    matches = {Field(f): t.matches("Tag") for f, (t, _) in variants.items()}
    links = [
        Link(INITIAL, Field("Tag")),
        *flatten(
            [Link(Field("Tag"), f, condition=m), Link(f, FINAL)]
            for f, m in matches.items()
        ),
        Link(Field("Tag"), FINAL, condition=And(*map(Not, matches.values()))),
    ]

    try:
        res = model.UnprovenMessage(ident, links, fields)
        return res.merged().proven(skip_proof=skip_proof)
    except Exception as e:
        raise Asn2RflxError(f"invalid message detected: `{ident}`") from e


HELPER_TYPES = [
    ASN_TAG_CLASS_TY := model.RangeInteger(
        strid([PRELUDE_NAME, "Asn_Tag_Class"]),
        first=Number(0b00),
        last=Number(0b11),
        size=Number(2),
    ),
    ASN_TAG_FORM_TY := model.RangeInteger(
        strid([PRELUDE_NAME, "Asn_Tag_Form"]),
        first=Number(0b0),
        last=Number(0b1),
        size=Number(1),
    ),
    ASN_TAG_NUM_TY := model.RangeInteger(
        strid([PRELUDE_NAME, "Asn_Tag_Num"]),
        first=Number(0b00000),
        last=Number(0b11111),
        size=Number(5),
    ),
    ASN_TAG_TY := AsnTag.ty(),
    ASN_LENGTH_TY := model.RangeInteger(
        strid([PRELUDE_NAME, "Asn_Length"]),
        first=Number(0x00),
        last=Number(0x7F),
        size=Number(8),
    ),
    ASN_RAW_BOOLEAN_TY := model.Enumeration(
        strid([PRELUDE_NAME, "Asn_Raw_BOOLEAN"]),
        literals=[(i.name, Number(i.value)) for i in AsnRawBoolean],
        size=Number(8),
        always_valid=False,
    ),
    ASN_RAW_NULL_TY := model.Message(
        strid([PRELUDE_NAME, "Asn_Raw_NULL"]),
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


@lru_cache
def prelude_model(skip_proof: bool = False) -> model.Model:
    """Base prelude without any structured types."""
    return model.Model(
        types=HELPER_TYPES + [ty.tlv_ty(skip_proof=skip_proof) for ty in BER_TYPES]
    )
