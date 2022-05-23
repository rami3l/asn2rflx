# [WIP] Asn2Rflx

A transpiler from [ASN.1] to [RecordFlux].

It reads ASN.1 syntax and generates corresponding RecordFlux `Model`s in order to facilitate modeling process of ASN.1 based protocols' message handling logic.

## Quick Start

This project is managed with [`pdm`].

Several shortcuts have been set in [`pyproject.toml`](pyproject.toml):

- `pdm run main` to launch the app.
- `pdm run test` to launch tests.
- `pdm run fmt` to format all Python source files.

[asn.1]: https://en.wikipedia.org/wiki/ASN.1
[recordflux]: https://github.com/Componolit/RecordFlux
[`pdm`]: https://github.com/pdm-project/pdm
