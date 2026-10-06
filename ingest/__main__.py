"""Load GreyNoise or TAXII into ArcadeDB: python -m ingest"""

from __future__ import annotations

import argparse
import json
import time

from ingest.load import run_import


def main() -> None:
    parser = argparse.ArgumentParser(description="Import GreyNoise or TAXII 2.1 into ArcadeDB")
    parser.add_argument("--source", choices=["greynoise", "taxii"], default="greynoise")
    parser.add_argument("--mode", choices=["file", "api"], default="file")
    parser.add_argument("--path")
    parser.add_argument("--query")
    parser.add_argument("--added-after", dest="added_after")
    parser.add_argument("--precursor", action="store_true")
    parser.add_argument("--interval", type=int, default=0, help="seconds between runs; 0 imports once")
    args = parser.parse_args()
    while True:
        result = run_import(
            source=args.source,
            mode=args.mode,
            path=args.path,
            query=args.query,
            added_after=args.added_after,
            precursor=args.precursor,
        )
        print(json.dumps({key: result[key] for key in result if key != "data"}))
        if args.interval <= 0:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
