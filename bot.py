import os
import sys
from typing import List

import login_tool


def _build_base_args(accounts_path: str) -> List[str]:
    return ["login_tool.py", "--input", accounts_path]


def _run_with_args(args: List[str]) -> None:
    sys.argv = args
    login_tool.main()


def main() -> None:
    accounts_path = input("Accounts file path [accounts.txt]: ").strip() or "accounts.txt"
    print("\nChọn chế độ:")
    print("1. Hiển thị info + claim airdrop")
    print("2. Chỉ hiển thị info airdrop (không claim)")
    print("3. Gửi phí (BNB) tới nhiều account")
    choice = input("Nhập lựa chọn (1/2/3): ").strip()

    if choice == "1":
        args = _build_base_args(accounts_path)
        claim_stage = input("Claim stage (ví dụ 1): ").strip()
        if not claim_stage:
            print("Bạn cần nhập claim stage.")
            return
        args += ["--claim-stage", claim_stage, "--auto-claim", "--send-gaix"]

        captcha_token = input("Captcha token (Enter để dùng 2captcha): ").strip()
        if captcha_token:
            args += ["--captcha-token", captcha_token]
        else:
            twocaptcha_key = os.getenv("TWOCAPTCHA_KEY") or input("2captcha key: ").strip()
            if not twocaptcha_key:
                print("Thiếu captcha token hoặc 2captcha key.")
                return
            args += ["--2captcha-key", twocaptcha_key]

        _run_with_args(args)
        return

    if choice == "2":
        _run_with_args(_build_base_args(accounts_path))
        return

    if choice == "3":
        fee_file = input("Fee recipients file [fee_recipients.txt]: ").strip() or "fee_recipients.txt"
        args = _build_base_args(accounts_path) + ["--send-fee", "--fee-recipients", fee_file]
        _run_with_args(args)
        return

    print("Lựa chọn không hợp lệ.")


if __name__ == "__main__":
    main()
