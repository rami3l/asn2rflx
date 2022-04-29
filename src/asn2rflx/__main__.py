from asn2rflx.prelude import (
    ASN_LENGTH_TY,
    ASN_RAW_BOOLEAN_TY,
    ASN_TAG_TY,
    BOOLEAN,
    INTEGER,
)


def greeting() -> str:
    return "Hello from PDM!"


def main() -> None:
    print(ASN_TAG_TY)
    print(ASN_LENGTH_TY)
    print(ASN_RAW_BOOLEAN_TY)
    print(INTEGER.lv_ty())
    print(INTEGER.tlv_ty())
    print(BOOLEAN.lv_ty())
    print(BOOLEAN.tlv_ty())


if __name__ == "__main__":
    main()
