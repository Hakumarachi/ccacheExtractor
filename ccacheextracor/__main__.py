#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : __main__.py
# Author             : Aku (@akumarachi)
# Date created       : 12 Dec 2024

import argparse
import tempfile
from ccacheextracor.utils import logger
from ccacheextracor.core import dump, compose

VERSION = "1.0"

banner = """
   _______________   ________  ________   ______     __                  __            
  / ____/ ____/   | / ____/ / / / ____/  / ____/  __/ /__________ ______/ /_____  _____
 / /   / /   / /| |/ /   / /_/ / __/    / __/ | |/_/ __/ ___/ __ `/ ___/ __/ __ \/ ___/
/ /___/ /___/ ___ / /___/ __  / /___   / /____>  </ /_/ /  / /_/ / /__/ /_/ /_/ / /   v%s 
\____/\____/_/  |_\____/_/ /_/_____/  /_____/_/|_|\__/_/   \__,_/\___/\__/\____/_/     by @akumarachi 
""" % VERSION

def parseArgs():
    print(banner)
    parser = argparse.ArgumentParser(description='CCache Extractor')
    parser.add_argument("-q", "--quiet", action='store_true', default=False, help='avoid all messages')
    parser.add_argument("-v", "--verbose", default='success', help='Verbose mode. (default: False)')
    parser.add_argument("-o","--outdir", default=None, help="Where to save dumped tickets")

    mode_kcm = argparse.ArgumentParser(add_help=False)
    mode_kcm.add_argument('kcm_file', help='Path to the KCM file')

    mode_keyring = argparse.ArgumentParser(add_help=False)
    mode_keyring.add_argument("--key", default=None, help='Keyring big_key')
    mode_keyring.add_argument("--principals", default=None, help='Keyring __krb5_princ__')

    subparsers = parser.add_subparsers(help="Mode", dest="mode", required=True)
    mode_keyring_parser= subparsers.add_parser("keyring", parents=[mode_keyring], help="Get CCache from keyring values")
    mode_kcm_parser = subparsers.add_parser("kcm", parents=[mode_kcm], help="Get CCache from kcm secrets.ldb")
    return parser.parse_args()

def main():
    options = parseArgs()
    logger.set_verbosity(options.verbose.upper(), options.quiet)
    if not options.outdir:
        options.outdir = tempfile.mkdtemp()
        logger.info(f"Out directory created at: {options.outdir}")
    if options.mode == "kcm":
        dump(options.kcm_file, options.outdir)
    elif options.mode == "keyring":
        compose(options.key, options.principals, options.outdir)