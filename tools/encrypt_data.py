# tools/encrypt_data.py
import os, base64, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets

DATA_DIR = "../backend/data"   # 你的原始 data 文件夹（根据实际调整）
OUT_DIR = "../data_encrypted"  # 输出加密文件位置（根据实际调整）
ITERATIONS = 200_000          # PBKDF2 迭代次数（可调整，越高越安全/越慢）
SALT_LEN = 16
IV_LEN = 12
AES_KEY_LEN = 32  # 256-bit

def derive_key(password: str, salt: bytes) -> bytes:
    pw = password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_LEN,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(pw)

def encrypt_file(in_path: str, out_path: str, password: str):
    with open(in_path, "rb") as f:
        plaintext = f.read()
    salt = secrets.token_bytes(SALT_LEN)
    iv = secrets.token_bytes(IV_LEN)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(iv, plaintext, None)  # associated data = None
    payload = salt + iv + ct
    b64 = base64.b64encode(payload)
    with open(out_path, "wb") as f:
        f.write(b64)
    print(f"Encrypted {in_path} -> {out_path}")

def main():
    password = input("输入用于加密的密码（将用于用户登录密码）：").strip()
    if not password:
        print("取消：没有输入密码")
        return
    if not os.path.exists(OUT_DIR):
        os.makedirs(OUT_DIR)
    # 要加密的文件列表（把你想公开托管的 data 文件放这里）
    files = [
        ("char_freq.json", "char_freq.json.enc"),
        ("char_cohesion.json", "char_cohesion.json.enc"),
        ("char_summary.json", "char_summary.json.enc"),
        ("char_network.json", "char_network.json.enc"),
        ("test.txt", "raw_text.txt.enc"),
    ]
    for src, dst in files:
        in_path = os.path.join(DATA_DIR, src)
        if not os.path.exists(in_path):
            print("跳过，文件不存在:", in_path)
            continue
        out_path = os.path.join(OUT_DIR, dst)
        encrypt_file(in_path, out_path, password)
    print("全部加密完成。请将 data_encrypted/ 上传到 GitHub（frontend 同级或子目录皆可）。")

if __name__ == "__main__":
    main()
