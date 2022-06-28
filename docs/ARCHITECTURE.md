# Architecture

## Contents

- [Architecture](#architecture)
  - [Contents](#contents)
  - [`prelude.py`](#preludepy)
  - [`convert.py`](#convertpy)

## `prelude.py`

Includes the basic elements to describe the ASN.1 prelude types (i.e. those with a `UNIVERSAL` tag) as well as types with other tags (with `ImplicitlyTaggedBerType`).

Several prelude types of the `PRIMITIVE` form are also defined in this module:

- `BOOLEAN`
- `NULL`
- `INTEGER`
- `OBJECT_IDENTIFIER`
- `*STRING`
  - `BIT_STRING`
  - `OCTET_STRING`
  - `PrintableString`
  - `IA5String`

```mermaid
classDiagram

class AsnTag {
    +num: AsnTagNum
    +class_: AsnTagClass
    +form: AsnTagForm
}

class BerType {
    +@property path: str
    +@property ident: str
    +@property full_ident: ID
    +v_ty()* Type
    +lv_ty()* Type
    +tlv_ty() Type
    +implicitly_tagged() ImplicitlyTaggedBerType
    +explicitly_tagged() ImplicitlyTaggedBerType
}
BerType "1" *-- "1" AsnTag: @property tag

class SimpleBerType {
    -_path: str
    -_ident: str
    -_tag: AsnTag
}
SimpleBerType --|> BerType

class DefiniteBerType {
    -_v_ty: Type
    +v_ty() Type
    +lv_ty() Type
}
DefiniteBerType --|> SimpleBerType

class SequenceBerType {
    -_path: str
    +elem_tlv_ty: Type
    +v_ty() Type
}
SequenceBerType --|> BerType

class ChoiceBerType {
    -_ident: str
    +variants: Mapping~str, BerType~
    +v_ty() Type
}
ChoiceBerType --|> BerType

class ImplicitlyTaggedBerType {
    +base: BerType
    -_tag: AsnTag
    -_path: str
    +v_ty() Type
    +lv_ty() Type
}
ImplicitlyTaggedBerType --|> BerType

class BOOLEAN { <<instance>> }
BOOLEAN .. DefiniteBerType

class NULL { <<instance>> }
NULL .. DefiniteBerType

class INTEGER { <<instance>> }
INTEGER .. SimpleBerType

class OBJECT_IDENTIFIER { <<instance>> }
OBJECT_IDENTIFIER .. SimpleBerType

class `*STRING` { <<instance>> }
`*STRING` .. SimpleBerType
```

## `convert.py`

The `AsnTypeConverter` class converts an instance of `asn1tools.compiler.Specification` to a collection of RecordFlux types `dict[rflx.identifier.ID, rflx.model.model.Type]`, so that they can be used to form a `rflx.model.Model`, and then exported to actual `.rflx` files.

```mermaid
classDiagram

class AsnTypeConverter {
    # import asn1tools.codecs.ber
    # from asn1tools.compiler import Specification
    +base_path: str
    +path(relpath: str) str
    +convert(val: ber.Type, relpath: str) BerType
    +convert_spec(spec: Specification) dict~ID, Type~
}
```
