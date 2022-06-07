from asn2rflx import prelude


def test_asn_tag_bytearray() -> None:
    for byte in range(2**8):
        arr = bytearray([byte])
        assert prelude.AsnTag.from_bytearray(arr).as_bytearray == arr
