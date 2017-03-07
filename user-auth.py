#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hashlib
import os
import sqlite3
import pyotp
import sys

from config import DB_PATH, HASH_ALGORITHM


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
if hash_func(os.environ['password'].encode("utf-8")).hexdigest() != password:
    sys.exit(1)

hotp = pyotp.HOTP(otpbase32key)
if not hotp.verify(otp, otpcounter):
    sys.exit(1)

conn.execute('UPDATE users SET otpcounter = ? WHERE username = ?;', (otpcounter+1, os.environ['username']))

sys.exit(0)
