#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : kcmreader.py
# Author             : Aku (@akumarachi)
# Date created       : 12 Dec 2024
from ccacheextracor.utils import logger, KCMCache

from ccacheextracor.utils import Ldb

def dump(kcm_file, outdir):
    db = Ldb(kcm_file)
    secrets = db.get_secrets()
    logger.success(f"Found {len(secrets)} secrets")
    for i, secret in enumerate(secrets):
        try:
            a = KCMCache.parse(secret)
            logger.debug(a)
            if len(a.creds) > 0:
                logger.info(f"Secrets {i} is a kerberos ticket")
                a.get_ticket().write_ticket(outdir)
        except Exception as e:
            logger.error(f"Secret {i} didn't seem to be a ticket")