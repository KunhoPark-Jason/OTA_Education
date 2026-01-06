#!/usr/bin/env python3
"""
generate_pqc.py
- libpqc_sig.so의 pqc_init() 기능을 이용해 PQC 키 파일을 "한 번만" 생성하는 유틸리티.
- publish/subscribe 코드에서는 더 이상 키 생성을 하지 않도록 수정되어 있으므로,
  먼저 이 스크립트를 실행해 키를 준비한 뒤 OTA를 실행하십시오.

주의:
- pqc_init()가 "키 파일이 없으면 생성"하는 동작을 한다는 가정에 기반합니다.
"""

import os
import ctypes
from ctypes import c_char_p, c_int

# ======= 프로젝트 경로 규칙을 publish/subscribe와 동일하게 맞춤 =======
base_dir = os.path.dirname(os.path.abspath(__file__))  # /home/sea/OTA/OTA_Education/file (예상)
certs_root_dir = os.path.abspath(os.path.join(base_dir, os.pardir, "certs"))
certs_pqc_dir = os.path.join(certs_root_dir, "pqc")
os.makedirs(certs_pqc_dir, exist_ok=True)

PQC_PRIVKEY_PATH = os.path.join(certs_pqc_dir, "pqc_private_d65.key")
PQC_PUBKEY_PATH  = os.path.join(certs_pqc_dir, "pqc_public_d65.key")

# ======= lib 설정 =======
PQC_LIB_NAME = "libpqc_sig.so"
PQC_ALG_NAME = b"ML-DSA-65"


def generate_pqc(overwrite: bool = False) -> None:
    """
    PQC 키 파일을 생성한다.
    - overwrite=False(기본): 키가 이미 있으면 생성하지 않고 종료.
    - overwrite=True: 기존 키를 삭제하고 다시 생성.
    """
    if not overwrite and os.path.exists(PQC_PRIVKEY_PATH) and os.path.exists(PQC_PUBKEY_PATH):
        print("[OK] PQC key files already exist. (no-op)")
        print(f"  - priv: {PQC_PRIVKEY_PATH}")
        print(f"  - pub : {PQC_PUBKEY_PATH}")
        return

    if overwrite:
        for p in (PQC_PRIVKEY_PATH, PQC_PUBKEY_PATH):
            try:
                os.remove(p)
            except FileNotFoundError:
                pass

    lib = ctypes.CDLL(PQC_LIB_NAME)

    lib.pqc_init.argtypes = [c_char_p, c_char_p, c_char_p]
    lib.pqc_init.restype = c_int

    priv_path = PQC_PRIVKEY_PATH.encode("utf-8")
    pub_path = PQC_PUBKEY_PATH.encode("utf-8")

    rc = lib.pqc_init(PQC_ALG_NAME, priv_path, pub_path)
    if rc != 0:
        raise RuntimeError(f"pqc_init failed with code {rc}")

    print("[SUCCESS] PQC key files generated.")
    print(f"  - priv: {PQC_PRIVKEY_PATH}")
    print(f"  - pub : {PQC_PUBKEY_PATH}")

    if hasattr(lib, "pqc_cleanup"):
        try:
            lib.pqc_cleanup()
        except Exception:
            pass


if __name__ == "__main__":
    # 필요하면 overwrite=True로 재생성 가능
    generate_pqc(overwrite=False)
