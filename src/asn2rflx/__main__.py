import logging
from pathlib import Path

import asn1tools as asn1
import coloredlogs
from rflx.model.model import Model

from asn2rflx import prelude
from asn2rflx.convert import AsnTypeConverter


def greeting() -> str:
    return "Hello from PDM!"


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    coloredlogs.install()

    outpath = Path("./build/rflx/specs/")
    logging.info(f"Writing specs to `{outpath.absolute()}`...")
    outpath.mkdir(parents=True, exist_ok=True)

    spec = asn1.compile_files(
        [
            "assets/rfc1155.asn",
            "assets/rfc1157.asn",
        ]
    )
    model = Model(
        types=[
            # TODO: Should we include all the prelude types in the resulting
            # Model? It's nice for writing, but not necessary for reading and
            # is costing us much time on message proving.
            # *prelude.MODEL.types,
            *AsnTypeConverter()
            .convert_spec(spec)
            .values(),
        ]
    )
    model.write_specification_files(outpath)
    logging.info("Writing specs done!")


if __name__ == "__main__":
    main()
