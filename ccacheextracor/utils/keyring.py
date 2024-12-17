#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : kcm.py
# Author             : Aku (@akumarachi)
# Date created       : 12 Dec 2024

import struct

from .krb5 import Ticket
from .logger import logger


class KeyringCred:
    def __init__(self, data):
        self.uuid = None
        self.blob_len = len(data)
        self.blob = data

    def __repr__(self):
        return f"Cred(uuid={self.uuid}, blob_len={self.blob_len}, blob={self.blob})"


class KeyringCache:
    def __init__(self, kdc_offset, principal_presence, realm, type_, principals, creds):
        self.kdc_offset = kdc_offset
        self.principal_presence = principal_presence
        self.realm = realm
        self.type = type_
        self.principals = principals
        self.creds = creds

    def get_ticket(self):
        return Ticket(self.type, self.principals, self.realm,  self.creds)

    @staticmethod
    def parse_pascal_string(data, offset, encoding='utf-8'):
        string_length = struct.unpack_from(">I", data, offset)[0]
        offset += 4
        string = data[offset:offset + string_length].decode(encoding)
        offset += string_length
        return string, offset

    @classmethod
    def parse(cls, data, creds_data):
        offset = 0
        # type
        logger.debug(data[0:4])
        type_ = struct.unpack_from(">I", data, offset)[0]
        offset += 4
        logger.debug(f"{'Type':<15}: {type_}")

        # principal_presence
        principals_len = struct.unpack_from(">I", data, offset)[0]
        offset += 4
        logger.debug(f"{'principals_len':<15}: {principals_len}")


    # realm
        realm, offset = cls.parse_pascal_string(data, offset)
        logger.debug(f"{'realm':<15}: {realm}")


    # principals
        principals = []
        for _ in range(principals_len):
            principal, offset = cls.parse_pascal_string(data, offset)
            principals.append(principal)
        logger.debug(f"{'principals':<15}: {principals}")

        # creds
        creds = []
        cred = KeyringCred(creds_data)
        creds.append(cred)
        logger.debug(f"{'creds':<15}: {creds}")

        return cls(0, 1, realm, type_, principals, creds)

    def __repr__(self):
        return (
            f"KCMCache(kdc_offset={self.kdc_offset}, principal_presence={self.principal_presence}, "
            f"realm={self.realm}, type={self.type}, principals={self.principals}, creds={self.creds})"
        )