#!/usr/bin/env python3
"""
Sign and send signin request to Espresso Foundation API
Reads wallet/private key from key.csv, signs message, and sends signin request
"""

import json
import csv
import time
import random
from datetime import datetime, timezone
import requests
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import to_checksum_address

API_BASE = "https://portal-api.magna.so/api/v2/bbe62884-b0e3-4328-a20c-0544351402b5"
CLAIM_URL = "https://claim.espresso.foundation"

HEADERS = {
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'content-type': 'application/json',
    'origin': CLAIM_URL,
    'priority': 'u=1, i',
    'referer': CLAIM_URL + '/',
    'sec-ch-ua': '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Linux"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'cross-site',
    'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
}

def get_nonce(wallet):
    """Fetch nonce from API"""
    session = requests.Session()
    session.headers.update(HEADERS)
    session.headers['accept-encoding'] = 'gzip, deflate'
    
    nonce_url = f"{API_BASE}/auth/nonce?wallet={wallet}"
    try:
        resp = session.get(nonce_url, timeout=15)
        if resp.status_code == 200:
            return resp.json().get('nonce')
        else:
            print(f"Error fetching nonce: {resp.status_code}")
            return None
    except Exception as e:
        print(f"Error fetching nonce: {e}")
        return None

def get_issued_at():
    """Get current UTC timestamp in ISO format with milliseconds"""
    iso_str = datetime.now(timezone.utc).isoformat(timespec='milliseconds')
    # Replace +00:00 with Z
    return iso_str.replace('+00:00', 'Z')

def sign_message(wallet_checksummed, nonce, issued_at, private_key):
    """Build and sign SIWE message"""
    
    message_text = (
        f"claim.espresso.foundation wants you to sign in with your Ethereum account:\n"
        f"{wallet_checksummed}\n"
        f"\n"
        f"Espresso\n"
        f"\n"
        f"URI: {CLAIM_URL}\n"
        f"Version: 1\n"
        f"Chain ID: 1\n"
        f"Nonce: {nonce}\n"
        f"Issued At: {issued_at}"
    )
    
    # Clean private key
    pk = private_key.strip()
    if pk.startswith('0x'):
        pk = pk[2:]
    
    # Sign message
    account = Account.from_key(pk)
    encoded_message = encode_defunct(text=message_text)
    signed_message = account.sign_message(encoded_message)
    signature = '0x' + signed_message.signature.hex()
    
    return message_text, signature

def send_signin(wallet, message, signature):
    """Send signin request and return response"""
    session = requests.Session()
    session.headers.update(HEADERS)
    session.headers['accept-encoding'] = 'gzip, deflate'
    
    signin_url = f"{API_BASE}/auth/signin"
    payload = {
        "wallet": wallet,
        "platform": "EVM",
        "message": message,
        "signature": signature
    }
    
    for attempt in range(3):
        try:
            resp = session.post(signin_url, json=payload, timeout=15)
            
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code in [500, 502, 503, 504]:
                print(f"  Server error {resp.status_code}, retrying in {2**attempt}s...")
                time.sleep(2 ** attempt)
                continue
            else:
                print(f"Error signing in: {resp.status_code}")
                print(f"  Response: {resp.text[:200]}")
                return None
        except Exception as e:
            print(f"  Request error: {e}")
            if attempt < 2:
                time.sleep(2 ** attempt)
    
    return None

# Auto-fetch nonce and issued_at
print("=== ESPRESSO SIGNIN ===\n")
results = []

with open('key.csv', newline='') as f:
    reader = csv.DictReader(f)
    for row in reader:
        wallet = row['wallet'].strip()
        private_key = row['prvkey']
        
        print(f"Processing {wallet}...")
        
        # Convert to checksummed address
        wallet_checksummed = to_checksum_address(wallet)
        
        # Fetch nonce
        print(f"  Fetching nonce...")
        nonce = get_nonce(wallet_checksummed)
        if not nonce:
            print(f"  Failed to get nonce")
            continue
        
        print(f"  Nonce: {nonce[:50]}...")
        
        # Get current timestamp
        issued_at = get_issued_at()
        print(f"  Issued At: {issued_at}")
        
        # Sign message
        print(f"  Signing message...")
        message, signature = sign_message(wallet_checksummed, nonce, issued_at, private_key)
        print(f"  Signature: {signature[:20]}...")
        
        # Send signin request
        print(f"  Sending signin request...")
        response = send_signin(wallet_checksummed, message, signature)
        if not response:
            print(f"  Failed to sign in")
            continue
        
        print(f"  Response status: Success")
        
        # Extract results
        access_token = response.get('accessToken', '')
        accounts = response.get('submissionInfo', {}).get('accounts', [])
        is_eligible = False
        
        if accounts:
            acct_value = accounts[0].get('value', '')
            if acct_value.lower() == wallet_checksummed.lower():
                is_eligible = accounts[0].get('isEligible', False)
        
        result = {
            'wallet': wallet_checksummed,
            'isEligible': is_eligible,
            'accessToken': access_token
        }
        results.append(result)
        status = "ELIGIBLE ✓" if is_eligible else "Not eligible"
        print(f"  → {status}\n")
        
        # Random delay 2-3 seconds before next request
        delay = random.uniform(2, 3)
        print(f"Waiting {delay:.2f}s before next request...\n")
        time.sleep(delay)
print("\n=== RESULTS ===")
print("wallet,isEligible,accessToken")
for r in results:
    print(f"{r['wallet']},{r['isEligible']},{r['accessToken']}")

# Save to CSV
with open('signin_results.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['wallet', 'isEligible', 'accessToken'])
    for r in results:
        writer.writerow([r['wallet'], r['isEligible'], r['accessToken']])

print(f"\nResults saved to signin_results.csv")
