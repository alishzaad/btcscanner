import os
import hashlib
import ecdsa
import base58
import bech32
import requests
import sys
import time
import random
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
    pub_key_uncompressed = b'\x04' + vk.to_string()
    
    sha_pub = hashlib.sha256(pub_key_uncompressed).digest()
    ripemd = hashlib.new('ripemd160', sha_pub).digest()
    uncompressed_addr = base58.b58encode(
        b'\x00' + ripemd +
        hashlib.sha256(hashlib.sha256(b'\x00' + ripemd).digest()).digest()[:4]
    ).decode()
    
    y_parity = pub_key_uncompressed[33] % 2
    pub_key_compressed = bytes([0x02 + y_parity]) + pub_key_uncompressed[1:33]
    sha_pub_compressed = hashlib.sha256(pub_key_compressed).digest()
    ripemd_compressed = hashlib.new('ripemd160', sha_pub_compressed).digest()
    compressed_addr = base58.b58encode(
        b'\x00' + ripemd_compressed +
        hashlib.sha256(hashlib.sha256(b'\x00' + ripemd_compressed).digest()).digest()[:4]
    ).decode()
    
    redeem_script = b'\x00\x14' + hashlib.new('ripemd160', hashlib.sha256(b'\x00\x14' + ripemd).digest()).digest()
    p2sh_hash = hashlib.new('ripemd160', hashlib.sha256(redeem_script).digest()).digest()
    p2sh_addr = base58.b58encode(
        b'\x05' + p2sh_hash +
        hashlib.sha256(hashlib.sha256(b'\x05' + p2sh_hash).digest()).digest()[:4]
    ).decode()
    
    witness_program = hashlib.new('ripemd160', hashlib.sha256(pub_key_uncompressed).digest()).digest()
    segwit_addr = bech32.encode('bc', 0, witness_program)
    
    return {
        'Uncompressed': uncompressed_addr,
        'Compressed': compressed_addr,
        'P2SH': p2sh_addr,
        'SegWit': segwit_addr
    }

# --- بررسی موجودی با تلاش مجدد و تأخیر تصادفی ---
def check_balance(address, retries=3):
    for i in range(retries):
        try:
            response = requests.get(
                f"https://blockchain.info/balance?active={address}",
                timeout=10,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            response.raise_for_status()
            return int(response.json().get(address, {}).get('final_balance', 0))
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}Attempt {i+1} failed for {address}: {e}{Style.RESET_ALL}")
            if i < retries - 1:
                time.sleep(random.uniform(0.1, 0.2))
    # در صورت خطا، به جای خروج مقدار 0 برگردانده می‌شود تا اسکن ادامه یابد.
    return 0

def check_addresses(addresses):
    # بررسی آدرس‌ها به صورت همزمان (در مجموع ۴ آدرس برای هر کلید => ۱۲ کیف پول در هر چرخه)
    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = {addr_type: executor.submit(check_balance, addr) for addr_type, addr in addresses.items()}
        results = {}
        for addr_type, future in futures.items():
            try:
                results[addr_type] = future.result()
            except Exception as e:
                print(f"{Fore.RED}Error checking {addr_type}: {e}{Style.RESET_ALL}")
                results[addr_type] = 0
        return results

# --- پردازش کلید خصوصی ---
def process_key():
    try:
        private_hex = generate_private_key()
        wif = private_to_wif(private_hex)
        addresses = generate_all_addresses(private_hex)
        balances = check_addresses(addresses)
        return wif, addresses, balances
    except Exception as e:
        print(f"{Fore.RED}Error in process_key: {e}{Style.RESET_ALL}")
        return None

# --- اجرای اصلی ---
def main():
    print("""
    ░█████╗░░█████╗░██╗░░░██╗██████╗░███████╗
    ██╔══██╗██╔══██╗██║░░░██║██╔══██╗██╔════╝
    ██║░░╚═╝██║░░██║██║░░░██║██████╦╝█████╗░░
    ██║░░██╗██║░░██║██║░░░██║██╔══██╗██╔══╝░░
    ╚█████╔╝╚█████╔╝╚██████╔╝██████╦╝███████╗
    ░╚════╝░░╚════╝░░╚═════╝░╚═════╝░╚══════╝
    """)
    
    total_keys = 0
    # استفاده از ThreadPoolExecutor با ۳ worker برای تولید ۳ کلید در هر چرخه
    with ThreadPoolExecutor(max_workers=3) as executor:
        while True:
            start_time = time.time()
            futures = [executor.submit(process_key) for _ in range(3)]
            results = []
            for future in futures:
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    print(f"{Fore.RED}Error in key processing: {e}{Style.RESET_ALL}")
            
            total_keys += len(results)
            print(f"\nTotal Keys Processed: {total_keys} | Total Addresses Checked: {total_keys * 4}")
            print("-" * 80)
            
            for res in results:
                if res:
                    wif, addresses, balances = res
                    summary = [f"WIF: {wif[:6]}..."] + [f"{addr_type[:4]}: {addr[:6]}... ({balances.get(addr_type, 0)})" for addr_type, addr in addresses.items()]
                    print(" | ".join(summary))
                    
                    for addr_type, balance in balances.items():
                        if isinstance(balance, int) and balance > 0:
                            print(f"\n\n{Fore.RED}!!! موجودی یافت شد !!!{Style.RESET_ALL}")
                            print(f"کلید خصوصی (WIF): {wif}")
                            print(f"نوع آدرس: {addr_type}")
                            print(f"آدرس: {addresses[addr_type]}")
                            print(f"موجودی: {balance} ساتوشی")
                            with open('found.txt', 'a') as f:
                                f.write(f"WIF Key: {wif}\nAddress Type: {addr_type}\nAddress: {addresses[addr_type]}\nBalance: {balance} satoshi\n\n")
                            sys.exit(0)
            
            elapsed = time.time() - start_time
            if elapsed < 1:
                time.sleep(1 - elapsed)

if __name__ == "__main__":
    main()
