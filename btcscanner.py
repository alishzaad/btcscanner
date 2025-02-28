import os
import hashlib
import ecdsa
import base58
import bech32
import requests
import sys
from concurrent.futures import ThreadPoolExecutor

# --- توابع تولید آدرس‌ها ---
def generate_private_key():
    return os.urandom(32).hex()

def private_to_wif(private_hex):
    extended = "80" + private_hex
    first_sha = hashlib.sha256(bytes.fromhex(extended)).digest()
    checksum = hashlib.sha256(first_sha).digest()[:4]
    return base58.b58encode(bytes.fromhex(extended + checksum.hex())).decode()

def generate_all_addresses(private_hex):
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_hex), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    pub_key = b'\x04' + vk.to_string()
    
    # 1. P2PKH (شروع با 1)
    sha_pub = hashlib.sha256(pub_key).digest()
    ripemd = hashlib.new('ripemd160', sha_pub).digest()
    p2pkh = base58.b58encode(b'\x00' + ripemd + hashlib.sha256(hashlib.sha256(b'\x00' + ripemd).digest()).digest()[:4]).decode()
    
    # 2. P2SH (شروع با 3)
    redeem_script = b'\x00\x14' + hashlib.new('ripemd160', hashlib.sha256(b'\x00\x14' + ripemd).digest()).digest()
    p2sh_hash = hashlib.new('ripemd160', hashlib.sha256(redeem_script).digest()).digest()
    p2sh = base58.b58encode(b'\x05' + p2sh_hash + hashlib.sha256(hashlib.sha256(b'\x05' + p2sh_hash).digest()).digest()[:4]).decode()
    
    # 3. SegWit (Bech32)
    witness_program = hashlib.new('ripemd160', hashlib.sha256(pub_key).digest()).digest()
    segwit = bech32.encode('bc', 0, witness_program)
    
    # 4. Compressed P2PKH
    y_parity = pub_key[33] % 2
    compressed_pub = bytes([0x02 + y_parity]) + pub_key[1:33]
    compressed_hash = hashlib.new('ripemd160', hashlib.sha256(compressed_pub).digest()).digest()
    compressed_addr = base58.b58encode(b'\x00' + compressed_hash + hashlib.sha256(hashlib.sha256(b'\x00' + compressed_hash).digest()).digest()[:4]).decode()
    
    return {
        'P2PKH': p2pkh,
        'P2SH': p2sh,
        'SegWit': segwit,
        'Compressed': compressed_addr
    }

# --- بررسی موجودی با ThreadPool ---
def check_balance(address):
    try:
        response = requests.get(
            f"https://blockchain.info/balance?active={address}",
            timeout=10,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        return int(response.json().get(address, {}).get('final_balance', 0))
    except:
        return 0

def check_addresses(addresses):
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {addr_type: executor.submit(check_balance, addr) for addr_type, addr in addresses.items()}
        return {addr_type: future.result() for addr_type, future in futures.items()}

# --- اجرای اصلی ---
def main():
    try:
        while True:
            private_hex = generate_private_key()
            wif = private_to_wif(private_hex)
            addresses = generate_all_addresses(private_hex)
            
            # نمایش WIF Key در حین اسکن
            sys.stdout.write("\033[K")  # پاک کردن خط قبلی
            print(f"\rWIF Key: {wif}", end="", flush=True)
            
            balances = check_addresses(addresses)
            
            # بررسی موجودی
            for addr_type, balance in balances.items():
                if balance > 0:
                    print("\n\n!!! موجودی یافت شد !!!")
                    print(f"کلید خصوصی (WIF): {wif}")
                    print(f"نوع آدرس: {addr_type}")
                    print(f"آدرس: {addresses[addr_type]}")
                    print(f"موجودی: {balance} ساتوشی")
                    
                    # ذخیره اطلاعات در فایل
                    with open('found.txt', 'a') as f:
                        f.write(f"WIF Key: {wif}\n")
                        f.write(f"Address Type: {addr_type}\n")
                        f.write(f"Address: {addresses[addr_type]}\n")
                        f.write(f"Balance: {balance} satoshi\n\n")
                    sys.exit(0)
                    
    except KeyboardInterrupt:
        print("\n\nعملیات توسط کاربر لغو شد.")

if __name__ == "__main__":
    print("""
    ░█████╗░░█████╗░██╗░░░██╗██████╗░███████╗
    ██╔══██╗██╔══██╗██║░░░██║██╔══██╗██╔════╝
    ██║░░╚═╝██║░░██║██║░░░██║██████╦╝█████╗░░
    ██║░░██╗██║░░██║██║░░░██║██╔══██╗██╔══╝░░
    ╚█████╔╝╚█████╔╝╚██████╔╝██████╦╝███████╗
    ░╚════╝░░╚════╝░░╚═════╝░╚═════╝░╚══════╝
    """)
    main()
