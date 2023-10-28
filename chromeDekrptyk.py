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

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Retrieve Encrypted Chrome Cookie Details.")
    parser.add_argument("-f", "--file", required=True, help="Path to the Chrome Cookies database.")
    parser.add_argument("-k", "--key", required=True, help="Path to the master key file.")
    args = parser.parse_args()

    with open(args.key, 'rb') as f:
        master_key = f.read()

    temp_db = "CookiesTemp.db"
    shutil.copy2(args.file, temp_db)

    grouped_data = {}
    
    with sqlite3.connect(temp_db) as conn:
        cursor = conn.cursor()
        for row in cursor.execute("SELECT host_key, name, encrypted_value, creation_utc, last_access_utc, expires_utc FROM cookies"):
            host_key = row[0]
            data = {
                'name': row[1],
                'decrypted_value': decrypt_value(row[2], master_key),
                'creation_utc': chrome_time_conversion(row[3]),
                'last_access_utc': chrome_time_conversion(row[4]),
                'expires_utc': chrome_time_conversion(row[5])
            }
            
            if host_key not in grouped_data:
                grouped_data[host_key] = []
            grouped_data[host_key].append(data)
    
    for host, cookies in grouped_data.items():
        print("=" * 70)
        print(f"Host: {host}")
        for cookie in cookies:
            print("\n")
            for key, val in cookie.items():
                print(f"{key.title().replace('_', ' ')}: {val}")
        print("=" * 70, "\n")

    os.remove(temp_db)
