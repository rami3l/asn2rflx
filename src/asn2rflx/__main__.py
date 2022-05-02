import logging
from pathlib import Path

import coloredlogs

from asn2rflx.prelude import MODEL


def greeting() -> str:
    return "Hello from PDM!"


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    coloredlogs.install()

    outpath = Path("./build/rflx/specs/")
    logging.info(f"Writing specs to `{outpath.absolute()}`...")
    outpath.mkdir(parents=True, exist_ok=True)
    MODEL.write_specification_files(outpath)
    logging.info(f"Writing specs done!")


if __name__ == "__main__":
    main()
