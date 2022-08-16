from typing import Any, Sequence, Union

from rflx.identifier import ID


def pub_vars(obj: Any) -> dict[str, Any]:
    return {v: k for v, k in vars(obj).items() if not v.startswith("_")}


def strid(ident: Union[str, Sequence[str], ID]) -> str:
    return str(ID(ident)) if ident else ""


def from_asn1_name(ident: str) -> str:
    "Converts an ASN.1 identifier to an Ada one."
    return ident.replace("-", "_")
