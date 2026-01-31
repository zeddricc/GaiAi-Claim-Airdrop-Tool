import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Dict, Any

import requests
from eth_account import Account
from eth_account.messages import encode_defunct
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from web3 import Web3

BASE_URL = "https://api.metagaia.io"
ORIGIN = "https://www.gaiai.io"
REFERER = "https://www.gaiai.io/"
AIRDROP_CONFIG_URL = f"{BASE_URL}/api/v1/gaiai-airdrop/gaiai-airdrop-config"
AIRDROP_USER_INFO_URL = f"{BASE_URL}/api/v1/gaiai-airdrop/gaiai-airdrop-user-info"
AIRDROP_STAGE_INFO_URL = f"{BASE_URL}/api/v1/gaiai-airdrop/gaiai-airdrop-user-stage-info"
AIRDROP_SIGN_URL = f"{BASE_URL}/api/v1/gaiai-airdrop/sign"
AIRDROP_CALLBACK_URL = f"{BASE_URL}/api/v1/gaiai-airdrop/callback"
GAIX_TOKEN_ADDRESS = "0xc12eFb9e4A1A753e7f6523482C569793C2271dbB"
TWOCAPTCHA_IN_URL = "http://2captcha.com/in.php"
TWOCAPTCHA_RES_URL = "http://2captcha.com/res.php"

load_dotenv()
console = Console()


@dataclass
class AccountInput:
    private_key: str
    captcha_token: str | None = None
    claim_stage: int | None = None
    claim_tx_hash: str | None = None
    claim_block_number: int | None = None
    claim_amount: float | None = None
    rpc_url: str | None = None


@dataclass
class FeeRecipient:
    address: str
    amount_bnb: float


def load_accounts(path: str) -> List[AccountInput]:
    if path.lower().endswith(".txt"):
        with open(path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f.readlines()]
        keys = [line for line in lines if line and not line.startswith("#")]
        return [AccountInput(private_key=key) for key in keys]
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return [AccountInput(**item) for item in raw]


def load_fee_recipients(path: str) -> List[FeeRecipient]:
    if path.lower().endswith(".txt"):
        recipients: List[FeeRecipient] = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                raw_line = line.strip()
                if not raw_line or raw_line.startswith("#"):
                    continue
                parts = [part.strip() for part in raw_line.split(",")]
                if len(parts) != 2:
                    raise ValueError(f"Invalid fee recipient line: {raw_line}")
                address, amount_raw = parts
                recipients.append(FeeRecipient(address=address, amount_bnb=float(amount_raw)))
        return recipients
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return [FeeRecipient(**item) for item in raw]


def build_message(address: str, nonce: str, mode: str) -> str:
    if mode == "nonce":
        return nonce
    timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return (
        "GaiAI Login\n"
        f"Address: {address}\n"
        f"Nonce: {nonce}\n"
        f"Time: {timestamp}"
    )


def sign_message(private_key: str, message: str) -> str:
    encoded = encode_defunct(text=message)
    signed = Account.sign_message(encoded, private_key=private_key)
    return "0x" + signed.signature.hex()


def login_one(session: requests.Session, address: str, private_key: str, message_mode: str) -> Dict[str, Any]:
    nonce_url = f"{BASE_URL}/api/v2/gaiai-login/wallet-nonce"
    signature_header = str(int(time.time() * 1000))
    session.headers.update({"signature": signature_header, "token": ""})
    resp = session.get(nonce_url, params={"address": address})
    if not resp.ok:
        raise RuntimeError(
            f"Nonce request failed ({resp.status_code}): {resp.text.strip()}"
        )
    nonce_data = resp.json()
    nonce = nonce_data["data"]["nonce"]

    message = build_message(address, nonce, message_mode)
    signature = sign_message(private_key, message)

    payload = {
        "address": address,
        "signature": signature,
        "message": message,
        "name": "metamask",
        "inviteCode": "",
    }

    login_url = f"{BASE_URL}/api/v2/gaiai-login/wallet"
    signature_header = str(int(time.time() * 1000))
    session.headers.update({"signature": signature_header, "token": ""})
    if session.cookies.get("_csrf"):
        session.headers.update({"cookie": f"_csrf={session.cookies.get('_csrf')}"})
    resp = session.post(login_url, json=payload)
    if not resp.ok:
        raise RuntimeError(
            f"Login request failed ({resp.status_code}): {resp.text.strip()}"
        )
    data = resp.json()
    if data.get("code") != 0:
        raise RuntimeError(f"Login rejected: {data}")
    return data


def submit_claim_callback(
    session: requests.Session,
    token: str,
    account: str,
    amount: float,
    stage: int,
    tx_hash: str,
    block_number: int,
) -> Dict[str, Any]:
    payload = {
        "account": account,
        "amount": amount,
        "stage": stage,
        "txHash": tx_hash,
        "blockNumber": block_number,
    }
    return api_post(session, AIRDROP_CALLBACK_URL, token, payload)


def submit_onchain_claim(
    rpc_url: str,
    private_key: str,
    contract_address: str,
    amount: int,
    stage: int,
    deadline: int,
    v: int,
    r: str,
    s: str,
    chain_id: int = 56,
) -> Dict[str, Any]:
    web3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 30}))
    if not web3.is_connected():
        raise RuntimeError("Failed to connect to RPC")
    acct = web3.eth.account.from_key(private_key)
    abi = [
        {
            "inputs": [
                {"internalType": "uint256", "name": "amount", "type": "uint256"},
                {"internalType": "uint256", "name": "stage", "type": "uint256"},
                {"internalType": "uint256", "name": "deadline", "type": "uint256"},
                {"internalType": "uint8", "name": "v", "type": "uint8"},
                {"internalType": "bytes32", "name": "r", "type": "bytes32"},
                {"internalType": "bytes32", "name": "s", "type": "bytes32"},
            ],
            "name": "claim",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function",
        }
    ]
    contract = web3.eth.contract(address=web3.to_checksum_address(contract_address), abi=abi)
    nonce = web3.eth.get_transaction_count(acct.address)
    gas_price = web3.eth.gas_price
    tx = contract.functions.claim(amount, stage, deadline, v, r, s).build_transaction(
        {
            "from": acct.address,
            "nonce": nonce,
            "gasPrice": gas_price,
            "chainId": chain_id,
        }
    )
    gas_estimate = web3.eth.estimate_gas(tx)
    tx["gas"] = int(gas_estimate * 1.2)
    signed = web3.eth.account.sign_transaction(tx, private_key)
    tx_hash = web3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
    return {
        "tx_hash": tx_hash.hex(),
        "block_number": receipt.blockNumber,
        "status": receipt.status,
    }


def get_erc20_contract(web3: Web3, token_address: str) -> Any:
    abi = [
        {
            "constant": True,
            "inputs": [{"name": "owner", "type": "address"}],
            "name": "balanceOf",
            "outputs": [{"name": "", "type": "uint256"}],
            "type": "function",
        },
        {
            "constant": True,
            "inputs": [],
            "name": "decimals",
            "outputs": [{"name": "", "type": "uint8"}],
            "type": "function",
        },
        {
            "constant": False,
            "inputs": [
                {"name": "to", "type": "address"},
                {"name": "value", "type": "uint256"},
            ],
            "name": "transfer",
            "outputs": [{"name": "", "type": "bool"}],
            "type": "function",
        },
    ]
    return web3.eth.contract(address=web3.to_checksum_address(token_address), abi=abi)


def get_gaix_balance(web3: Web3, address: str) -> Dict[str, Any]:
    contract = get_erc20_contract(web3, GAIX_TOKEN_ADDRESS)
    decimals = contract.functions.decimals().call()
    balance = contract.functions.balanceOf(web3.to_checksum_address(address)).call()
    return {"balance": balance, "decimals": decimals}


def transfer_gaix(
    web3: Web3,
    private_key: str,
    to_address: str,
    amount: int,
    chain_id: int = 56,
) -> Dict[str, Any]:
    acct = web3.eth.account.from_key(private_key)
    contract = get_erc20_contract(web3, GAIX_TOKEN_ADDRESS)
    nonce = web3.eth.get_transaction_count(acct.address)
    gas_price = web3.eth.gas_price
    tx = contract.functions.transfer(
        web3.to_checksum_address(to_address),
        amount,
    ).build_transaction(
        {
            "from": acct.address,
            "nonce": nonce,
            "gasPrice": gas_price,
            "chainId": chain_id,
        }
    )
    gas_estimate = web3.eth.estimate_gas(tx)
    tx["gas"] = int(gas_estimate * 1.2)
    signed = web3.eth.account.sign_transaction(tx, private_key)
    tx_hash = web3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
    return {"tx_hash": tx_hash.hex(), "block_number": receipt.blockNumber, "status": receipt.status}


def send_native_bnb(
    web3: Web3,
    private_key: str,
    to_address: str,
    amount_bnb: float,
    chain_id: int = 56,
) -> Dict[str, Any]:
    acct = web3.eth.account.from_key(private_key)
    nonce = web3.eth.get_transaction_count(acct.address)
    gas_price = web3.eth.gas_price
    value = web3.to_wei(amount_bnb, "ether")
    tx = {
        "from": acct.address,
        "to": web3.to_checksum_address(to_address),
        "value": value,
        "nonce": nonce,
        "gasPrice": gas_price,
        "chainId": chain_id,
    }
    gas_estimate = web3.eth.estimate_gas(tx)
    tx["gas"] = int(gas_estimate * 1.2)
    signed = web3.eth.account.sign_transaction(tx, private_key)
    tx_hash = web3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
    return {"tx_hash": tx_hash.hex(), "block_number": receipt.blockNumber, "status": receipt.status}


def api_post(session: requests.Session, url: str, token: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    signature_header = str(int(time.time() * 1000))
    session.headers.update({"signature": signature_header, "token": token})
    resp = session.post(url, json=payload)
    if not resp.ok:
        raise RuntimeError(f"API request failed ({resp.status_code}): {resp.text.strip()}")
    data = resp.json()
    if data.get("code") != 0:
        raise RuntimeError(f"API rejected: {data}")
    return data


def create_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "accept": "application/json, text/plain, */*",
            "accept-language": "en-US,en;q=0.9,vi;q=0.8",
            "content-type": "application/json",
            "connection": "keep-alive",
            "origin": ORIGIN,
            "referer": REFERER,
            "lang": "en-US",
            "sec-ch-ua": '"Not(A:Brand";v="8", "Chromium";v="144", "Microsoft Edge";v="144"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"macOS"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "cross-site",
            "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        }
    )
    return session


def api_get(session: requests.Session, url: str, token: str) -> Dict[str, Any]:
    signature_header = str(int(time.time() * 1000))
    session.headers.update({"signature": signature_header, "token": token})
    resp = session.get(url)
    if not resp.ok:
        raise RuntimeError(f"API request failed ({resp.status_code}): {resp.text.strip()}")
    data = resp.json()
    if data.get("code") != 0:
        raise RuntimeError(f"API rejected: {data}")
    return data


def fetch_airdrop_data(session: requests.Session, token: str) -> Dict[str, Any]:
    config = api_get(session, AIRDROP_CONFIG_URL, token)
    user_info = api_get(session, AIRDROP_USER_INFO_URL, token)
    stage_info = api_get(session, AIRDROP_STAGE_INFO_URL, token)
    return {
        "config": config.get("data", {}),
        "user_info": user_info.get("data", {}),
        "stage_info": stage_info.get("data", {}),
    }


def request_claim_signature(
    session: requests.Session,
    token: str,
    stage: int,
    captcha_token: str,
) -> Dict[str, Any]:
    signature_header = str(int(time.time() * 1000))
    session.headers.update({"signature": signature_header, "token": token})
    resp = session.get(
        AIRDROP_SIGN_URL,
        params={"stage": stage, "captchaToken": captcha_token},
    )
    if not resp.ok:
        raise RuntimeError(f"API request failed ({resp.status_code}): {resp.text.strip()}")
    data = resp.json()
    if data.get("code") != 0:
        raise RuntimeError(f"API rejected: {data}")
    return data


def solve_recaptcha_v2(
    api_key: str,
    site_key: str,
    page_url: str,
    poll_interval: int = 5,
    timeout: int = 120,
) -> str:
    submit_params = {
        "key": api_key,
        "method": "userrecaptcha",
        "googlekey": site_key,
        "pageurl": page_url,
        "json": 1,
    }
    submit_resp = requests.get(TWOCAPTCHA_IN_URL, params=submit_params, timeout=30)
    submit_data = submit_resp.json()
    if submit_data.get("status") != 1:
        raise RuntimeError(f"2captcha submit failed: {submit_data}")
    captcha_id = submit_data.get("request")

    start = time.time()
    while time.time() - start < timeout:
        time.sleep(poll_interval)
        res_params = {"key": api_key, "action": "get", "id": captcha_id, "json": 1}
        res_resp = requests.get(TWOCAPTCHA_RES_URL, params=res_params, timeout=30)
        res_data = res_resp.json()
        if res_data.get("status") == 1:
            return res_data.get("request")
        if res_data.get("request") not in {"CAPCHA_NOT_READY"}:
            raise RuntimeError(f"2captcha solve failed: {res_data}")
    raise TimeoutError("2captcha solve timeout")


def summarize_airdrop(airdrop: Dict[str, Any]) -> Dict[str, Any]:
    user_info = airdrop.get("user_info", {})
    stage_info = airdrop.get("stage_info", {})
    stages = stage_info.get("claim_stage", [])

    unclaimed = [s for s in stages if s.get("claim_status") in {0, 3}]
    unclaimed_amount = sum(float(s.get("amount", 0)) for s in unclaimed)
    unclaimed_amount_usdt = sum(float(s.get("amount_usdt", 0)) for s in unclaimed)
    return {
        "total_reward": user_info.get("total_reward"),
        "total_reward_usdt": user_info.get("total_reward_usdt"),
        "claim_status": user_info.get("claim_status"),
        "g_points": user_info.get("g_points"),
        "tier": user_info.get("tier"),
        "unclaimed_count": len(unclaimed),
        "unclaimed_amount": unclaimed_amount,
        "unclaimed_amount_usdt": unclaimed_amount_usdt,
        "unclaimed_stages": [
            {
                "stage": s.get("stage"),
                "status": s.get("claim_status"),
                "amount": s.get("amount"),
                "amount_usdt": s.get("amount_usdt"),
                "start": s.get("start"),
            }
            for s in unclaimed
        ],
    }


def login_with_retry(account: AccountInput, retries: int, delay: int, message_mode: str) -> Dict[str, Any]:
    address = Account.from_key(account.private_key).address.lower()
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            session = create_session()
            return login_one(session, address, account.private_key, message_mode)
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            print(f"  Attempt {attempt} failed: {exc}")
            if attempt < retries:
                time.sleep(delay)
    raise RuntimeError(f"Login failed for {address}") from last_error


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="GaiAI login tool")
    parser.add_argument("--input", required=True, help="Path to accounts JSON")
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--delay", type=int, default=10)
    parser.add_argument(
        "--message-mode",
        choices=["template", "nonce"],
        default="nonce",
        help="Message format to sign",
    )
    parser.add_argument("--claim-stage", type=int, default=None)
    parser.add_argument("--captcha-token", type=str, default=None)
    parser.add_argument("--claim-tx-hash", type=str, default=None)
    parser.add_argument("--claim-block-number", type=int, default=None)
    parser.add_argument("--claim-amount", type=float, default=None)
    parser.add_argument("--rpc-url", type=str, default="https://bsc-dataseed.bnbchain.org")
    parser.add_argument("--contract-address", type=str, default="0xd7AA02BE0cD0Ba05cb3b82be6650b834fe9692E1")
    parser.add_argument("--auto-claim", action="store_true")
    parser.add_argument("--send-gaix", action="store_true")
    parser.add_argument("--send-to", type=str, default="0xA7af0614EB124Df73b94507C736Bf3Ce0691E4ed")
    parser.add_argument("--send-fee", action="store_true")
    parser.add_argument("--fee-recipients", type=str, default="fee_recipients.json")
    parser.add_argument("--2captcha-key", dest="twocaptcha_key", default=os.getenv("TWOCAPTCHA_KEY"))
    parser.add_argument("--site-key", dest="site_key", default="6LfAIPQrAAAAAAnXBOokHpmgFw-X8zXQ6gyY7msR")
    parser.add_argument("--page-url", dest="page_url", default="https://www.gaiai.io/stage/airdrop")
    args = parser.parse_args()

    accounts = load_accounts(args.input)
    for idx, account in enumerate(accounts, start=1):
        if args.send_fee and idx > 1:
            continue
        address = Account.from_key(account.private_key).address
        console.print(f"[bold cyan][{idx}/{len(accounts)}][/bold cyan] Login [yellow]{address}[/yellow]...")
        try:
            result = login_with_retry(
                account,
                retries=args.retries,
                delay=args.delay,
                message_mode=args.message_mode,
            )
            token = result.get("data", {}).get("token")
            console.print("  [green]Success[/green]. Token received.")
            if token:
                session = create_session()
                airdrop = fetch_airdrop_data(session, token)
                summary = summarize_airdrop(airdrop)
                header = (
                    f"G-Points: {summary['g_points']} | Tier: {summary['tier']}\n"
                    f"Total Reward: {summary['total_reward']} (~{summary['total_reward_usdt']:.6f} USDT)\n"
                    f"Claim Status: {summary['claim_status']} (1=claimed,0=unclaimed,3=scheduled)\n"
                    f"Unclaimed: {summary['unclaimed_count']} stages | "
                    f"{summary['unclaimed_amount']:.6f} (~{summary['unclaimed_amount_usdt']:.6f} USDT)"
                )
                console.print(Panel(header, title="Airdrop Summary", border_style="bright_blue"))

                if summary["unclaimed_stages"]:
                    table = Table(title="Pending Stages", show_lines=True)
                    table.add_column("Stage", style="cyan", no_wrap=True)
                    table.add_column("Status", style="magenta")
                    table.add_column("Amount", style="green")
                    table.add_column("~USDT", style="green")
                    table.add_column("Start", style="white")
                    for stage in summary["unclaimed_stages"]:
                        table.add_row(
                            str(stage["stage"]),
                            str(stage["status"]),
                            str(stage["amount"]),
                            f"{float(stage.get('amount_usdt') or 0):.6f}",
                            str(stage["start"]),
                        )
                    console.print(table)

                claim_stage = account.claim_stage or args.claim_stage
                captcha_token = account.captcha_token or args.captcha_token
                claim_tx_hash = account.claim_tx_hash or args.claim_tx_hash
                claim_block_number = account.claim_block_number or args.claim_block_number
                claim_amount = account.claim_amount or args.claim_amount
                rpc_url = account.rpc_url or args.rpc_url
                web3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 30}))
                if not web3.is_connected():
                    raise RuntimeError("Failed to connect to RPC")
                if claim_stage and captcha_token:
                    console.print("  [bold]Requesting claim signature...[/bold]")
                    signature_data = request_claim_signature(
                        session,
                        token,
                        claim_stage,
                        captcha_token,
                    )
                    console.print(
                        Panel(
                            str(signature_data.get("data", {})),
                            title="Claim Signature",
                            border_style="green",
                        )
                    )
                    if args.auto_claim:
                        claim_payload = signature_data.get("data", {})
                        console.print("  [bold]Submitting on-chain claim...[/bold]")
                        receipt_info = submit_onchain_claim(
                            rpc_url,
                            account.private_key,
                            args.contract_address,
                            int(claim_payload.get("amount")),
                            int(claim_payload.get("stage")),
                            int(claim_payload.get("deadline")),
                            int(claim_payload.get("v")),
                            claim_payload.get("r"),
                            claim_payload.get("s"),
                        )
                        console.print(
                            Panel(
                                str(receipt_info),
                                title="Claim Tx Receipt",
                                border_style="yellow",
                            )
                        )
                        claim_tx_hash = receipt_info.get("tx_hash")
                        claim_block_number = receipt_info.get("block_number")
                        claim_amount = float(claim_payload.get("amount")) / 1e18
                    if claim_tx_hash and claim_block_number and claim_amount is not None:
                        console.print("  [bold]Submitting claim callback...[/bold]")
                        callback = submit_claim_callback(
                            session,
                            token,
                            account=address.lower(),
                            amount=claim_amount,
                            stage=claim_stage,
                            tx_hash=claim_tx_hash,
                            block_number=claim_block_number,
                        )
                        console.print(
                            Panel(
                                str(callback.get("data", {})),
                                title="Claim Callback",
                                border_style="cyan",
                            )
                        )
                elif claim_stage and args.twocaptcha_key:
                    console.print("  [bold]Solving captcha via 2captcha...[/bold]")
                    captcha_token = solve_recaptcha_v2(
                        args.twocaptcha_key,
                        args.site_key,
                        args.page_url,
                    )
                    console.print("  [green]Captcha solved[/green]. Requesting claim signature...")
                    signature_data = request_claim_signature(
                        session,
                        token,
                        claim_stage,
                        captcha_token,
                    )
                    console.print(
                        Panel(
                            str(signature_data.get("data", {})),
                            title="Claim Signature",
                            border_style="green",
                        )
                    )
                    if args.auto_claim:
                        claim_payload = signature_data.get("data", {})
                        console.print("  [bold]Submitting on-chain claim...[/bold]")
                        receipt_info = submit_onchain_claim(
                            rpc_url,
                            account.private_key,
                            args.contract_address,
                            int(claim_payload.get("amount")),
                            int(claim_payload.get("stage")),
                            int(claim_payload.get("deadline")),
                            int(claim_payload.get("v")),
                            claim_payload.get("r"),
                            claim_payload.get("s"),
                        )
                        console.print(
                            Panel(
                                str(receipt_info),
                                title="Claim Tx Receipt",
                                border_style="yellow",
                            )
                        )
                        claim_tx_hash = receipt_info.get("tx_hash")
                        claim_block_number = receipt_info.get("block_number")
                        claim_amount = float(claim_payload.get("amount")) / 1e18
                    if claim_tx_hash and claim_block_number and claim_amount is not None:
                        console.print("  [bold]Submitting claim callback...[/bold]")
                        callback = submit_claim_callback(
                            session,
                            token,
                            account=address.lower(),
                            amount=claim_amount,
                            stage=claim_stage,
                            tx_hash=claim_tx_hash,
                            block_number=claim_block_number,
                        )
                        console.print(
                            Panel(
                                str(callback.get("data", {})),
                                title="Claim Callback",
                                border_style="cyan",
                            )
                        )
                elif claim_stage or captcha_token:
                    console.print(
                        "  [yellow]Claim skipped[/yellow]: provide both --claim-stage and --captcha-token "
                        "(or in accounts.json)."
                    )

                if args.send_gaix:
                    balance_info = get_gaix_balance(web3, address)
                    balance = balance_info["balance"]
                    decimals = balance_info["decimals"]
                    human_balance = balance / (10 ** decimals) if decimals else balance
                    console.print(f"  GAIX balance: {human_balance:.6f}")
                    if balance > 0:
                        console.print("  [bold]Sending GAIX...[/bold]")
                        transfer_info = transfer_gaix(
                            web3,
                            account.private_key,
                            args.send_to,
                            balance,
                        )
                        console.print(
                            Panel(
                                str(transfer_info),
                                title="GAIX Transfer",
                                border_style="magenta",
                            )
                        )

                if args.send_fee:
                    recipients = load_fee_recipients(args.fee_recipients)
                    console.print(f"  [bold]Sending fee to {len(recipients)} recipients...[/bold]")
                    for recipient in recipients:
                        fee_info = send_native_bnb(
                            web3,
                            account.private_key,
                            recipient.address,
                            recipient.amount_bnb,
                        )
                        console.print(
                            Panel(
                                str({"to": recipient.address, "amount_bnb": recipient.amount_bnb, **fee_info}),
                                title="Fee Transfer",
                                border_style="yellow",
                            )
                        )
        except Exception as exc:  # noqa: BLE001
            console.print(f"  [red]Failed[/red]: {exc}")
        time.sleep(args.delay)


if __name__ == "__main__":
    main()
