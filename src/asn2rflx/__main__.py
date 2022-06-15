import argparse
import logging
import os
from distutils.util import strtobool
from pathlib import Path

import asn1tools as asn1
import coloredlogs
from rflx.model.model import Model

from asn2rflx.convert import AsnTypeConverter
from asn2rflx.prelude import prelude_model

SKIP_PROOF: bool = strtobool(os.environ.get("ASN2RFLX_SKIP_PROOF", "true"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-o", "--outputdir", default=".", help="the output directory of .rflx files"
    )
    parser.add_argument(
        "-v", "--verbosity", action="count", help="the logging verbosity"
    )
    parser.add_argument(
        "FILE", nargs="+", help="the .asn specification(s) to be converted"
    )
    opts = parser.parse_args()

    verbosity = {
        1: logging.ERROR,
        2: logging.WARNING,
        3: logging.INFO,
        4: logging.DEBUG,
    }.get(opts.verbosity, logging.INFO)
    logging.basicConfig(level=verbosity)
    coloredlogs.install()

    outputdir = Path(opts.outputdir)
    outputdir.mkdir(parents=True, exist_ok=True)
    logging.info(f".rflx specs will be written to `{outputdir.absolute()}`...")

    logging.info("Compiling .asn specs...")
    spec = asn1.compile_files(opts.FILE)

    logging.info(
        f"Converting .asn specs with proofs {'OFF' if SKIP_PROOF else 'ON'}..."
    )
    model = Model(
        types=[
            # TODO: Should we include all the prelude types in the resulting
            # Model? It's nice for writing, but not necessary for reading and
            # is costing us much time on message proving.
            *prelude_model(skip_proof=SKIP_PROOF).types,
            *AsnTypeConverter(skip_proof=SKIP_PROOF).convert_spec(spec).values(),
        ]
    )

    logging.info(f"Writing .rflx specs to `{outputdir.absolute()}`...")
    model.write_specification_files(outputdir)

    logging.info("Writing specs done!")


if __name__ == "__main__":
    main()
