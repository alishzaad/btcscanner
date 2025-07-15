import hmac
import hashlib

client_seed = '798c31cdd9b9fb95'
server_seed = 'f39263f6981d17e8c54cd76c75ac2bc7c7c2286a9561f48fed89a35a24ea9ad0'

# ساخت هش با HMAC-SHA512
hash_bytes = hmac.new(
    key=server_seed.encode(),
    msg=client_seed.encode(),
    digestmod=hashlib.sha512
).hexdigest()

# گرفتن 10 رقم اول هش (در مبنای 16)، تبدیل به عدد، و گرفتن % 100
first_10_hex = hash_bytes[:10]
result_number = int(first_10_hex, 16)
lucky_number = result_number % 100

print(f"Lucky Number: {lucky_number}")
