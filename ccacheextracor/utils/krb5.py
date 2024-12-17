#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : krb5.py
# Author             : Aku (@akumarachi)
# Date created       : 12 Dec 2024

from .logger import logger
from struct import pack
import random
import string
import tempfile
import os

class Ticket:
    def __init__(self, type_, principals, realm, creds):
        self.header = '0504000c00010008ffffffff00000000'
        self.type_ = type_
        self.principals = principals
        self.realm = realm
        self.credentials = creds

    def write_ticket(self, outdir):
        random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=5))

        outfile = os.path.join(outdir,f"krb5_{self.principals[0]}-{random_string}.ccache")

        with open(outfile, "wb") as f:
            logger.info("Writing CCache file...")
            f.write(bytes.fromhex(self.header))
            logger.info(f"{'CCache type':<30}: {self.type_}")
            f.write(pack('>I', self.type_))

            logger.info("%-30s: %s" % ("Principals", self.principals))
            f.write(pack('>I', len(self.principals)))

            logger.info(f"{'User Realm':<30}: {self.realm}")
            f.write(pack('>I', len(self.realm)))
            f.write(self.realm.encode())

            for principal in self.principals:
                f.write(pack('>I', len(principal)))
                f.write(principal.encode())

            logger.info('Number of credentials in cache: %d' % len(self.credentials))
            for credential in self.credentials:
                f.write(credential.blob)

            logger.success(f"Ticket saved at : {outfile}" )