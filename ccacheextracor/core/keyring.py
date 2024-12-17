#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : kcmreader.py
# Author             : Aku (@akumarachi)
# Date created       : 12 Dec 2024

from ccacheextracor.utils import logger, KeyringCache

def compose(key, principal, outdir):
    logger.success("Starting CCache composer from Keyring")
    if not principal:
        principal = input("Keyring -> __krb5_princ__ :")

    if ":hex:" not in principal:
        logger.error("Expected value: :hex:XXX...")
        raise TypeError

    if not key:
        key = input("Keyring -> big_key :")

    if ":hex:" not in key:
        logger.error("Expected value: :hex:XXX...")
        raise TypeError

    principal = principal[5:]
    key = key[5:]

    logger.debug(f"Principal: {principal}")
    logger.debug(f"Key: {key}")

    KeyringCache.parse(bytes.fromhex(principal), bytes.fromhex(key)).get_ticket().write_ticket(outdir)