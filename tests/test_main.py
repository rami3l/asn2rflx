from asn2rflx.__main__ import greeting


def test_greeting():
    assert greeting() == "Hello from PDM!"
