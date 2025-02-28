import os
import hashlib
import ecdsa
import base58
import bech32
import requests
import sys
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init

# Initialize colorama
init()

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
    # تولید کلید عمومی غیر فشرده
    pub_key_uncompressed = b'\x04' + vk.to_string()
    
    # 1. آدرس P2PKH غیر فشرده (Uncompressed - شروع با 1)
    sha_pub = hashlib.sha256(pub_key_uncompressed).digest()
    ripemd = hashlib.new('ripemd160', sha_pub).digest()
    uncompressed_addr = base58.b58encode(b'\x00' + ripemd +
                                          hashlib.sha256(hashlib.sha256(b'\x00' + ripemd).digest()).digest()[:4]).decode()
    
    # 2. آدرس P2PKH فشرده (Compressed - شروع با 1)
    y_parity = pub_key_uncompressed[33] % 2
    pub_key_compressed = bytes([0x02 + y_parity]) + pub_key_uncompressed[1:33]
    sha_pub_compressed = hashlib.sha256(pub_key_compressed).digest()
    ripemd_compressed = hashlib.new('ripemd160', sha_pub_compressed).digest()
    compressed_addr = base58.b58encode(b'\x00' + ripemd_compressed +
                                        hashlib.sha256(hashlib.sha256(b'\x00' + ripemd_compressed).digest()).digest()[:4]).decode()
    
    # 3. آدرس P2SH (شروع با 3)
    redeem_script = b'\x00\x14' + hashlib.new('ripemd160', hashlib.sha256(b'\x00\x14' + ripemd).digest()).digest()
    p2sh_hash = hashlib.new('ripemd160', hashlib.sha256(redeem_script).digest()).digest()
    p2sh_addr = base58.b58encode(b'\x05' + p2sh_hash +
                                 hashlib.sha256(hashlib.sha256(b'\x05' + p2sh_hash).digest()).digest()[:4]).decode()
    
    # 4. آدرس SegWit (Bech32 - شروع با bc1)
    witness_program = hashlib.new('ripemd160', hashlib.sha256(pub_key_uncompressed).digest()).digest()
    segwit_addr = bech32.encode('bc', 0, witness_program)
    
    return {
        'Uncompressed': uncompressed_addr,
        'Compressed': compressed_addr,
        'P2SH': p2sh_addr,
        'SegWit': segwit_addr
    }

# --- بررسی موجودی با ThreadPool ---
def check_balance(address):
    try:
        response = requests.get(
            f"https://blockchain.info/balance?active={address}",
            timeout=10,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        response.raise_for_status()  # بررسی خطاهای HTTP
        return int(response.json().get(address, {}).get('final_balance', 0))
    except requests.exceptions.RequestException as e:
        return f"{Fore.RED}Error: {e}{Style.RESET_ALL}"  # نمایش خطا با رنگ قرمز

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
            
            # بررسی موجودی برای همه آدرس‌ها
            balances = check_addresses(addresses)
            
            # نمایش اطلاعات در ترمینال
            sys.stdout.write("\033[K")  # پاک کردن خط قبلی
            status_parts = [f"WIF: {wif[:6]}..."]
            for addr_type, addr in addresses.items():
                balance = balances.get(addr_type, 0)
                status_parts.append(f"{addr_type}: {addr[:6]}... ({balance if isinstance(balance, int) else balance})")
            status = " | ".join(status_parts)
            print(f"\r{status}", end="", flush=True)
            
            # بررسی موجودی و خطاها
            for addr_type, balance in balances.items():
                if isinstance(balance, int) and balance > 0:
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
                elif isinstance(balance, str):  # نمایش خطاها
                    print(f"\n\n!!! خطا !!!")
                    print(f"نوع آدرس: {addr_type}")
                    print(f"آدرس: {addresses[addr_type]}")
                    print(f"خطا: {balance}")
                    
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
