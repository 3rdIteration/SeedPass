#!/usr/bin/env python3
"""Derive a deterministic PGP fingerprint from a BIP39 mnemonic."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = REPO_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from bip_utils import Bip39SeedGenerator  # noqa: E402

from local_bip85.bip85 import BIP85  # noqa: E402
from seedpass.core.password_generation import derive_pgp_key  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Derive a deterministic OpenPGP fingerprint using the BIP-85 PGP"
            " derivation paths."
        )
    )
    parser.add_argument(
        "mnemonic",
        help="BIP39 mnemonic that seeds the derivation.",
    )
    parser.add_argument(
        "-i",
        "--index",
        type=int,
        default=0,
        help="Derivation index to use (defaults to 0).",
    )
    parser.add_argument(
        "-t",
        "--key-type",
        default="ed25519",
        help=(
            "PGP key type to derive (e.g. 'ed25519', 'curve25519', 'rsa',"
            " 'rsa-4096')."
        ),
    )
    parser.add_argument(
        "-u",
        "--user-id",
        default="",
        help="Optional user ID to attach to the generated key.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    try:
        seed_bytes = Bip39SeedGenerator(args.mnemonic).Generate()
        bip85 = BIP85(seed_bytes)
        _, fingerprint = derive_pgp_key(
            bip85,
            args.index,
            key_type=args.key_type,
            user_id=args.user_id,
        )
    except Exception as exc:  # pragma: no cover - CLI convenience
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    print(fingerprint)


if __name__ == "__main__":
    main()
