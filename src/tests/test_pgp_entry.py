import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.entry_management import EntryManager
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager


@pytest.mark.parametrize(
    ("key_type", "expected_fingerprint"),
    [
        ("ed25519", "9837B7E85F711F478DBE22EB641301EA97DA37C5"),
        ("curve25519", "9837B7E85F711F478DBE22EB641301EA97DA37C5"),
        ("rsa", "ECC1557BE1B91255FAC1BB370ABFE55998DF2870"),
        ("rsa-4096", "6784BC8345BAEF74ED426F55903131B578BB929C"),
    ],
)
def test_pgp_derivation_vectors(key_type: str, expected_fingerprint: str) -> None:
    from bip_utils import Bip39SeedGenerator

    from local_bip85.bip85 import BIP85
    from seedpass.core.password_generation import derive_pgp_key
    from pgpy import PGPKey

    seed_bytes = Bip39SeedGenerator(TEST_SEED).Generate()
    bip85 = BIP85(seed_bytes)

    armored_key, fingerprint = derive_pgp_key(
        bip85, 0, key_type=key_type, user_id="Vector Test"
    )

    assert fingerprint == expected_fingerprint

    parsed_key, _ = PGPKey.from_blob(armored_key)
    assert parsed_key.fingerprint == expected_fingerprint


def test_pgp_key_determinism():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, tmp_path)
        backup_mgr = BackupManager(tmp_path, cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        idx = entry_mgr.add_pgp_key(
            "pgp", TEST_SEED, key_type="ed25519", user_id="Test"
        )
        key1, fp1 = entry_mgr.get_pgp_key(idx, TEST_SEED)
        key2, fp2 = entry_mgr.get_pgp_key(idx, TEST_SEED)

        assert fp1 == fp2
        assert key1 == key2
        assert fp1 == "9837B7E85F711F478DBE22EB641301EA97DA37C5"

        # parse returned armored key and verify fingerprint
        from pgpy import PGPKey

        parsed_key, _ = PGPKey.from_blob(key1)
        assert parsed_key.fingerprint == fp1

        # ensure the index file stores key_type and user_id
        data = enc_mgr.load_json_data(entry_mgr.index_file)
        entry = data["entries"][str(idx)]
        assert entry["key_type"] == "ed25519"
        assert entry["user_id"] == "Test"


def test_pgp_rsa_key_determinism():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, tmp_path)
        backup_mgr = BackupManager(tmp_path, cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        idx = entry_mgr.add_pgp_key(
            "pgp-rsa", TEST_SEED, key_type="rsa", user_id="RSA Test"
        )
        key1, fp1 = entry_mgr.get_pgp_key(idx, TEST_SEED)
        key2, fp2 = entry_mgr.get_pgp_key(idx, TEST_SEED)

        assert fp1 == fp2
        assert key1 == key2
        assert fp1 == "ECC1557BE1B91255FAC1BB370ABFE55998DF2870"

        from pgpy import PGPKey

        parsed_key, _ = PGPKey.from_blob(key1)
        assert parsed_key.fingerprint == fp1
