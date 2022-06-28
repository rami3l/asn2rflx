# Asn2Rflx

[WIP] A transpiler from [ASN.1] to [RecordFlux].

It reads ASN.1 syntax and generates corresponding RecordFlux `Model`s in order to facilitate modeling process of ASN.1 based protocols' message handling logic.

---

## Contents

- [Asn2Rflx](#asn2rflx)
  - [Contents](#contents)
  - [Installation](#installation)
  - [Development](#development)
  - [Architecture](#architecture)

---

## Installation

You can easily install `asn2rflx` with installers like [`pipx`]:

```sh
pipx install git+https://github.com/rami3l/asn2rflx.git
```

## Development

This project is managed with [`pdm`].

Several shortcuts have been set in [`pyproject.toml`](pyproject.toml):

- `pdm run main` to launch the app.
- `pdm run test` to launch tests.
- `pdm run fmt` to format all Python source files.

## Architecture

See [`ARCHITECTURE.md`].

[asn.1]: https://en.wikipedia.org/wiki/ASN.1
[recordflux]: https://github.com/Componolit/RecordFlux
[`pdm`]: https://github.com/pdm-project/pdm
[`pipx`]: https://github.com/pypa/pipx
[`architecture.md`]: docs/ARCHITECTURE.md
