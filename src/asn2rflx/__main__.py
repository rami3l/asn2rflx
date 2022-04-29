from asn2rflx.prelude import INTEGER


def greeting() -> str:
    return "Hello from PDM!"


def main() -> None:
    print(INTEGER.tlv_ty())


if __name__ == "__main__":
    main()
