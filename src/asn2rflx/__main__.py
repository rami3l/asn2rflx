import logging
from pathlib import Path

import coloredlogs
from more_itertools import flatten

from asn2rflx.prelude import MODEL, OCTET_STRING, SequenceOfBerType
from rflx.model.model import Model


def greeting() -> str:
    return "Hello from PDM!"


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    coloredlogs.install()

    outpath = Path("./build/rflx/specs/")
    logging.info(f"Writing specs to `{outpath.absolute()}`...")
    outpath.mkdir(parents=True, exist_ok=True)
    sequence_of_types = [SequenceOfBerType("Test", OCTET_STRING.tlv_ty())]
    model = Model(
        types=[
            *MODEL.types[:],
            *flatten([ty.v_ty(), ty.lv_ty(), ty.tlv_ty()] for ty in sequence_of_types),
        ]
    )
    model.write_specification_files(outpath)
    logging.info("Writing specs done!")


if __name__ == "__main__":
    main()
