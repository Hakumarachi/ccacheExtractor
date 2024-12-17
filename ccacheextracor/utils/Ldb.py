#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Ldb.py
# Author             : Aku (@akumarachi)
# Date created       : 12 Dec 2024

import re
import struct

class Ldb:
    def __init__(self, file):
        with open(file, "rb") as file:
            self.data = file.read()

    def get_secrets(self):
        secrets = []
        for match in re.finditer(b"secret",self.data):
            addr = match.start() + 7
            secret_len = struct.unpack_from("I",self.data[addr+4:addr+8])[0]
            secret_data = self.data[addr+8:addr+8+secret_len]
            secrets.append(secret_data)
        secrets = sorted(set(secrets))
        return secrets