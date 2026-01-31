# GaiAI Airdrop Tool

Batch tool to login, view airdrop info, claim stages, transfer GAIX, and send BNB fees to multiple recipients on BSC.

## Requirements
- Python 3.10+
- BSC RPC (default uses public endpoint)

Install dependencies:
```bash
pip install -r requirements.txt
```

## Files
- `accounts.txt`: one private key per line (do **not** commit)
- `fee_recipients.txt`: `address,amount_bnb` per line (do **not** commit)
- `.env`: optional environment variables (do **not** commit)

Example `accounts.txt`:
```
0xYOUR_PRIVATE_KEY_1
0xYOUR_PRIVATE_KEY_2
```

Example `fee_recipients.txt`:
```
0xRecipient1,0.00003
0xRecipient2,0.00003
```

## Quick Start (menu)
```bash
python3 bot.py
```
Menu options:
1. Show info + claim airdrop (auto-claim) + send GAIX
2. Show info only
3. Send fee (BNB) to multiple accounts (uses only the **first** account in `accounts.txt`)

## Advanced CLI
You can also run the core tool directly:
```bash
python3 login_tool.py --input accounts.txt
```

Optional flags:
- `--claim-stage <n>`
- `--auto-claim`
- `--captcha-token <token>`
- `--2captcha-key <key>` (or set `TWOCAPTCHA_KEY` in `.env`)
- `--send-gaix` (sends GAIX to default address)
- `--send-to <address>`
- `--send-fee --fee-recipients fee_recipients.txt`

## Security Notes
- **Never commit** private keys, `.env`, or recipient lists.
- Use a dedicated wallet for automation.
- Review all transactions and gas costs.

## .gitignore
This repo includes a `.gitignore` to keep secrets out of git:
- `.env`
- `accounts.txt`
- `fee_recipients.txt`

## Disclaimer
Use at your own risk. This tool signs transactions locally.
