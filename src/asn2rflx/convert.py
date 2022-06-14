from dataclasses import dataclass
from functools import singledispatchmethod
from typing import cast

import asn1tools as asn1
from asn1tools.codecs import ber
from frozendict import frozendict
from rflx import model
from rflx.identifier import ID

from asn2rflx import prelude
from asn2rflx.utils import from_asn1_name, strid


@dataclass
class AsnTypeConverter:
    """A converter from `asn1tools`' BER types to RecordFlux types."""

    base_path: str = ""
    skip_proof: bool = False

    def path(self, relpath: str) -> str:
        return strid(list(filter(None, [self.base_path, relpath])))

    # In Python 3.10+ this should be done with the `match-case` construct...
    @singledispatchmethod
    def convert(self, val, relpath: str = "") -> prelude.BerType:
        raise NotImplementedError(f"conversion not implemented for {val}")

    def __convert_implicit(
        self, base: prelude.BerType, val: ber.Type, relpath: str = ""
    ) -> prelude.BerType:
        if not val.tag_len:
            return base
        if val.tag_len > 1:
            raise prelude.AsnTag.LONG_TAG_UNSUPPORTED_ERROR
        tag = prelude.AsnTag.from_bytearray(val.tag)
        if tag == base.tag:
            return base
        return base.implicitly_tagged(tag, self.path(relpath))

    # ASN.1 Types

    @convert.register  # type: ignore [no-redef]
    def _(self, val: ber.Boolean, relpath: str = "") -> prelude.BerType:
        return self.__convert_implicit(prelude.BOOLEAN, val, relpath)

    @convert.register  # type: ignore [no-redef]
    def _(self, val: ber.Null, relpath: str = "") -> prelude.BerType:
        return self.__convert_implicit(prelude.NULL, val, relpath)

    @convert.register  # type: ignore [no-redef]
    def _(self, val: ber.Integer, relpath: str = "") -> prelude.BerType:
        return self.__convert_implicit(prelude.INTEGER, val, relpath)

    @convert.register  # type: ignore [no-redef]
    def _(self, val: ber.ObjectIdentifier, relpath: str = "") -> prelude.BerType:
        return self.__convert_implicit(prelude.OBJECT_IDENTIFIER, val, relpath)

    @convert.register  # type: ignore [no-redef]
    def _(self, val: ber.BitString, relpath: str = "") -> prelude.BerType:
        return self.__convert_implicit(prelude.BIT_STRING, val, relpath)

    @convert.register  # type: ignore [no-redef]
    def _(self, val: ber.OctetString, relpath: str = "") -> prelude.BerType:
        return self.__convert_implicit(prelude.OCTET_STRING, val, relpath)

    @convert.register  # type: ignore [no-redef]
    def _(self, val: ber.PrintableString, relpath: str = "") -> prelude.BerType:
        return self.__convert_implicit(prelude.PrintableString, val, relpath)

    @convert.register  # type: ignore [no-redef]
    def _(self, val: ber.IA5String, relpath: str = "") -> prelude.BerType:
        return self.__convert_implicit(prelude.IA5String, val, relpath)

    # ASN.1 type constructors

    @convert.register  # type: ignore [no-redef]
    def _(self, message: ber.Sequence, relpath: str = "") -> prelude.BerType:
        fields = cast(list[ber.Type], message.root_members)
        res = prelude.SequenceBerType(
            self.path(relpath),
            from_asn1_name(message.name or message.type_name),
            frozendict(
                {
                    from_asn1_name(field.name): self.convert(field, relpath)
                    for field in fields
                }
            ),
        )
        return self.__convert_implicit(res, message, relpath)

    @convert.register  # type: ignore [no-redef]
    def _(self, sequence: ber.SequenceOf, relpath: str = "") -> prelude.BerType:
        res = prelude.SequenceOfBerType(
            self.path(relpath),
            self.convert(sequence.element_type, relpath).tlv_ty(
                skip_proof=self.skip_proof
            ),
        )
        return self.__convert_implicit(res, sequence, relpath)

    @convert.register  # type: ignore [no-redef]
    def _(self, message: ber.Choice, relpath: str = "") -> prelude.BerType:
        fields = cast(list[ber.Type], message.members)
        res = prelude.ChoiceBerType(
            self.path(relpath),
            from_asn1_name(message.name or message.type_name),
            frozendict(
                {
                    from_asn1_name(field.name): self.convert(field, relpath)
                    for field in fields
                }
            ),
        )
        return self.__convert_implicit(res, message, relpath)

    @convert.register  # type: ignore [no-redef]
    def _(self, tagged: ber.ExplicitTag, relpath: str = "") -> prelude.BerType:
        tag = prelude.AsnTag.from_bytearray(tagged.tag)
        return self.convert(cast(ber.Type, tagged.inner), relpath).explicitly_tagged(
            tag, self.path(relpath)
        )

    def convert_spec(self, spec: asn1.compiler.Specification) -> dict[ID, model.Type]:
        """
        Converts an ASN.1 specification to a mapping from qualified RecordFlux
        identifiers to the corresponding RecordFlux type.
        """
        res: dict[ID, model.Type] = {}
        for path, tys in spec.modules.items():
            res |= {
                (
                    ty1 := self.convert(ty.type, from_asn1_name(path)).tlv_ty(
                        skip_proof=self.skip_proof
                    )
                ).qualified_identifier: ty1
                for ty in tys.values()
            }
        return res
