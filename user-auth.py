#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hashlib
import os
import sqlite3
import pyotp
import sys

from config import DB_PATH, HASH_ALGORITHM, HOTPBACK, HOTP


hash_func = getattr(hashlib, HASH_ALGORITHM)
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

passwordInput = os.environ['password'][:-6]
otp = os.environ['password'][-6:]

cursor.execute('SELECT * FROM users WHERE username = ?;', (os.environ['username'],))
result = cursor.fetchone()
if result is None:
    sys.exit(1)
username, password, otpbase32key, otpcounter = result
if hash_func(passwordInput.encode("utf-8")).hexdigest() != password:
    sys.exit(1)

if HOTP:
    hotp = pyotp.HOTP(otpbase32key)

    hotp_ok = False
    for i in range(HOTPBACK):
        if hotp.verify(otp, otpcounter):
            hotp_ok = True
            break
        otpcounter = otpcounter + 1

    if not hotp_ok:
        sys.exit(1)

    cursor.execute('UPDATE users SET otpcounter = ? WHERE username = ?;', (otpcounter+1, os.environ['username']))
    conn.commit()

sys.exit(0)
