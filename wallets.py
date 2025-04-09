from mnemonic import Mnemonic
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
import hashlib

def mnemonic_to_sui_address(mnemonic: str) -> str:
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    bip44_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.SUI)
    pub_key_bytes = bip44_ctx.PublicKey().RawCompressed().ToBytes()

    # Sui uses Blake2b-256 hash of public key
    hash_digest = hashlib.blake2b(pub_key_bytes, digest_size=32).digest()
    return "0x" + hash_digest.hex()

def load_mnemonics(filename: str):
    with open(filename, "r") as f:
        return [line.strip() for line in f if line.strip()]

def save_addresses_to_file(addresses, filename: str):
    with open(filename, "w") as f:
        for address in addresses:
            f.write(f"{address}\n")
    print(f"{len(addresses)} addresses saved to {filename}")

if __name__ == "__main__":
    mnemonics = load_mnemonics("keys.txt")
    addresses = [mnemonic_to_sui_address(m) for m in mnemonics]
    save_addresses_to_file(addresses, "wallets.txt")
