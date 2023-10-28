<h1> Chrome Data Decryptor </h1>

A utility to decrypt and retrieve encrypted data (either cookies or login credentials) from Google Chrome's SQLite databases. This tool can be helpful for various legitimate purposes, like incident response, forensics, or data recovery.

For the full deatiled write up and step by step process:

<a href="https://krptyk.com/2023/10/15/decrypting-chrome-credentials/">Decrypting Chrome Credentials</a>
<a href="https://krptyk.com/2023/10/28/decrypting-chrome-cookies/">Decrypting Chrome Cookies</a>

Pre-requisites

    Python 3.x
    Libraries: os, sqlite3, shutil, Crypto.Cipher, argparse, datetime

How to Use

First, you need to extract the necessary Chrome SQLite databases and the encryption key for decryption.
        For cookies: Retrieve the Cookies file.
        For login credentials: Retrieve the Login Data file.

These files are typically located at:

    C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data\Default

The master encryption key is required to decrypt the data. This key can be found within Chrome's User Data directory in a file named Local State. You will need to extract the key value from this file.

I have uploaded two variations to get this key within this repository

Run the tool using the following command:

For cookies:

    chromeDekrypt.py -f path_to_cookies_db -k path_to_master_key -t cookies

For login credentials:

    chromeDekrypt.py -f path_to_login_data_db -k path_to_master_key -t login

Command Line Arguments:

    -f or --file: Path to the Chrome SQLite database.
        For cookies, provide the path to the Cookies database.
        For login data, provide the path to the Login Data database.

    -k or --key: Path to the master encryption key file. This key is crucial for decrypting the database content.

    -t or --type: Type of data to retrieve. Options are:
        cookies: To retrieve encrypted cookies data.
        login: To retrieve saved login credentials.

Disclaimer

I take no responsibility for your use of this code. The provided utility is for educational and legitimate purposes only. Misuse of this tool against unauthorized databases, or with malicious intent, could be illegal and unethical. Always seek appropriate permissions and abide by all applicable laws and guidelines.
