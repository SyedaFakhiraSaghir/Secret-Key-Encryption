#!/usr/bin/env python3
"""
attack_task6_3.py

Automatically perform the chosen-plaintext attack on the SEED Lab oracle
(10.9.0.80:3000) that uses AES-128-CBC with predictable IVs.

Usage:
    python3 attack_task6_3.py
"""

import socket
from binascii import hexlify, unhexlify

HOST = "10.9.0.80"
PORT = 3000
RECV_TIMEOUT = 5.0  # seconds

def recv_all_until(sock, stop_marker, timeout=RECV_TIMEOUT):
    """Receive from socket until stop_marker appears (in decoded text)."""
    sock.settimeout(timeout)
    data = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
        try:
            text = data.decode(errors="ignore")
        except:
            text = ""
        if stop_marker in text:
            return text
    return data.decode(errors="ignore")

def xor_bytes(a: bytes, b: bytes) -> bytes:
    length = min(len(a), len(b))
    return bytes(x ^ y for x, y in zip(a[:length], b[:length]))

def pad_to_block(b: bytes, block_size=16) -> bytes:
    """Pad by zero bytes on the right up to block_size (as used in this task)."""
    if len(b) >= block_size:
        return b[:block_size]
    return b.ljust(block_size, b'\x00')

def parse_banner(banner_text):
    """
    Parse banner to extract:
      - Bob_cipher (hex)
      - Bob_IV (hex)
      - Next_IV (hex)
    Returns (bob_cipher_hex, bob_iv_hex, next_iv_hex)
    """
    lines = [line.strip() for line in banner_text.splitlines() if line.strip()]
    bob_cipher = None
    bob_iv = None
    next_iv = None

    # Try to find lines containing "Bob" or "ciphertex"/"ciphertext" or "IV used" or "Next IV"
    for l in lines:
        low = l.lower()
        if "bob" in low and ("cipher" in low):
            # format like: Bob’s ciphertex: 54601f27...
            parts = l.split()
            # find the first token that looks like hex (length even)
            for tok in parts[::-1]:
                tok = tok.strip()
                if all(c in "0123456789abcdefABCDEF" for c in tok) and len(tok) % 2 == 0:
                    bob_cipher = tok.lower()
                    break
        if ("iv used" in low) or ("the iv used" in low) or ("iv used :" in low) or ("iv used:" in low):
            # extract hex
            parts = l.split()
            for tok in parts[::-1]:
                tok = tok.strip()
                if all(c in "0123456789abcdefABCDEF" for c in tok) and len(tok) % 2 == 0:
                    bob_iv = tok.lower()
                    break
        if "next iv" in low or "next iv :" in low or "next iv:" in low:
            parts = l.split()
            for tok in parts[::-1]:
                tok = tok.strip()
                if all(c in "0123456789abcdefABCDEF" for c in tok) and len(tok) % 2 == 0:
                    next_iv = tok.lower()
                    break

    return bob_cipher, bob_iv, next_iv

def craft_plaintext_hex(guess_str: str, bob_iv_hex: str, next_iv_hex: str) -> str:
    """Return hex string to send to oracle for a given guess ('Yes' or 'No')."""
    bob_iv = unhexlify(bob_iv_hex)
    next_iv = unhexlify(next_iv_hex)
    guess = pad_to_block(guess_str.encode(), 16)
    # P_chosen = guess ⊕ IV_B ⊕ IV_next
    tmp = xor_bytes(guess, bob_iv)
    p_chosen = xor_bytes(tmp, next_iv)
    return hexlify(p_chosen).decode()

def interact_and_get_cipher(sock, plaintext_hex):
    """Send plaintext_hex + newline, read response until next prompt or until timeout; return the ciphertext hex returned by oracle (if any)."""
    if not plaintext_hex.endswith("\n"):
        plaintext_hex = plaintext_hex + "\n"
    sock.sendall(plaintext_hex.encode())
    # read until either "Your plaintext" or until we receive a line with 'ciphertext' or 32-hex block
    resp = recv_all_until(sock, "Your plaintext :")
    # Try to extract the ciphertext hex from resp
    # Look for 16-byte hex strings (32 hex chars)
    for tok in resp.split():
        tok = tok.strip()
        if all(c in "0123456789abcdefABCDEF" for c in tok) and len(tok) == 32:
            return tok.lower(), resp
    return None, resp

def main():
    print("[*] Connecting to oracle {}:{} ...".format(HOST, PORT))
    with socket.create_connection((HOST, PORT), timeout=10) as s:
        # read initial banner until it asks "Your plaintext :"
        banner = recv_all_until(s, "Your plaintext :")
        print("[*] Banner received:")
        print(banner)
        bob_cipher, bob_iv, next_iv = parse_banner(banner)
        if not (bob_cipher and bob_iv and next_iv):
            print("[!] Could not parse banner properly. Parsed values:")
            print("bob_cipher:", bob_cipher)
            print("bob_iv:", bob_iv)
            print("next_iv:", next_iv)
            print("[!] Exiting.")
            return

        print("[*] Parsed:")
        print("  Bob ciphertext:", bob_cipher)
        print("  Bob IV:", bob_iv)
        print("  Next IV (to be used for your input):", next_iv)

        # craft for both guesses
        candidate_yes = craft_plaintext_hex("Yes", bob_iv, next_iv)
        candidate_no  = craft_plaintext_hex("No",  bob_iv, next_iv)
        print("\n[*] Candidate plaintext hex for guess 'Yes':", candidate_yes)
        print("[*] Candidate plaintext hex for guess 'No' :   ", candidate_no)

        # try 'Yes' first
        print("\n[*] Sending candidate for 'Yes' ...")
        ret_cipher, resp_text = interact_and_get_cipher(s, candidate_yes)
        if ret_cipher:
            print("[*] Oracle returned ciphertext:", ret_cipher)
            if ret_cipher == bob_cipher:
                print("\n[+] SUCCESS: Bob's secret is 'Yes'")
                return
            else:
                print("[-] Not a match for 'Yes'. Trying 'No' ...")
        else:
            print("[!] Could not extract ciphertext after sending 'Yes' candidate. The server response:")
            print(resp_text)
            print("[!] Will still try 'No' candidate next.")

        # The server will have printed a new "Next IV" after the first query.
        # To follow the correct protocol we should re-parse the new banner chunk for the new next IV.
        # So read the remaining banner chunk to find the new "Next IV".
        # (We already read until 'Your plaintext :' in interact_and_get_cipher).
        # Now read until the next prompt to get the printed Next IV.
        # But easiest approach: the server returned resp_text; attempt to parse next IV from it.
        _, _, new_next_iv = parse_banner(resp_text)
        if not new_next_iv:
            # If not found, try to read more until prompt then parse
            more = recv_all_until(s, "Your plaintext :")
            _, _, new_next_iv = parse_banner(more)
        if not new_next_iv:
            print("[!] Could not determine the new next IV after first attempt. Exiting.")
            return

        print("[*] New Next IV (for second attempt):", new_next_iv)
        candidate_no = craft_plaintext_hex("No", bob_iv, new_next_iv)
        print("[*] Sending candidate for 'No' ...")
        ret_cipher2, resp_text2 = interact_and_get_cipher(s, candidate_no)
        if ret_cipher2:
            print("[*] Oracle returned ciphertext:", ret_cipher2)
            if ret_cipher2 == bob_cipher:
                print("\n[+] SUCCESS: Bob's secret is 'No'")
                return
            else:
                print("\n[-] Neither candidate matched Bob's ciphertext. Something unexpected happened.")
                print("Server response 1 (after Yes):")
                print(resp_text)
                print("Server response 2 (after No):")
                print(resp_text2)
                return
        else:
            print("[!] Could not extract ciphertext after sending 'No' candidate. Server response:")
            print(resp_text2)
            return

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("[!] Exception:", e)
