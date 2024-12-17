#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : kcm.py
# Author             : Aku (@akumarachi)
# Date created       : 12 Dec 2024

import struct

from .krb5 import Ticket
from .logger import logger


class KcmCred:
    def __init__(self, uuid, blob_len, blob):
        self.uuid = uuid
        self.blob_len = blob_len
        self.blob = blob

    @classmethod
    def parse(cls, data, offset):
        # UUID (16 bytes)
        uuid = data[offset:offset + 16]
        offset += 16

        # blob_len (4 bytes)
        blob_len = struct.unpack_from("I", data, offset)[0]
        offset += 4

        # blob (blob_len bytes)
        blob = data[offset:offset + blob_len]
        offset += blob_len

        return cls(uuid, blob_len, blob), offset

    def __repr__(self):
        return f"Cred(uuid={self.uuid}, blob_len={self.blob_len}, blob={self.blob})"


class KCMCache:
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
        string_length = struct.unpack_from("I", data, offset)[0]
        offset += 4
        string = data[offset:offset + string_length].decode(encoding)
        offset += string_length
        return string, offset

    @classmethod
    def parse(cls, data):
        offset = 0

        # kdc_offset
        kdc_offset = struct.unpack_from("I", data, offset)[0]
        offset += 4

        # principal_presence
        principal_presence = struct.unpack_from("B", data, offset)[0]
        offset += 1

        # realm
        realm, offset = cls.parse_pascal_string(data, offset)

        # type
        type_ = struct.unpack_from("I", data, offset)[0]
        offset += 4

        # principals_len
        principals_len = struct.unpack_from("I", data, offset)[0]
        offset += 4

        # principals
        principals = []
        for _ in range(principals_len):
            principal, offset = cls.parse_pascal_string(data, offset)
            principals.append(principal)

        # creds_len
        creds_len = struct.unpack_from("I", data, offset)[0]
        offset += 4

        # creds
        creds = []
        for _ in range(creds_len):
            cred, offset = KcmCred.parse(data, offset)
            creds.append(cred)

        return cls(kdc_offset, principal_presence, realm, type_, principals, creds)

    def __repr__(self):
        return (
            f"KCMCache(kdc_offset={self.kdc_offset}, principal_presence={self.principal_presence}, "
            f"realm={self.realm}, type={self.type}, principals={self.principals}, creds={self.creds})"
        )