#!/usr/bin/env python

import argparse, os
import pandas as pd
from pathlib import Path
from datetime import timedelta
import subprocess as sub
from concurrent.futures import Future, ThreadPoolExecutor
import json

parser = argparse.ArgumentParser(description="Helper script to export packages saved "
					"by tshark/wireshark in json to csv format.")

parser.add_argument("files", metavar='PATH', type=str,
                    help='the path to the pcap(ng) file(s)',
                    nargs=argparse.REMAINDER)

parser.add_argument('-d', '--directory', action='store_true',
                    help='switch to directory mode; convert all json files '
					'in the given directory',
                    required=False, default=False)

args = parser.parse_args()


if args.directory:
    if len(args.files) > 1:
        parser.error('too much arguments: if --directory is specified'
        'only one path may be supplied!')
    dirr = Path(args.files).resolve()
    target_dir = dirr / 'converted'
    if not target_dir.exists():
        target_dir.mkdir()
    for file in dirr.glob('packets-*.pcap[ng]*'):
        content = pd.DataFrame(
            json.load(
                sub.Popen(['tshark', '-T', 'json', '-r', str(file)], stdout=sub.PIPE).stdout
                )
            )
        pakets_data = pd.json_normalize(content['_source'])
        pakets_data.to_csv(target_dir / f'{file.stem}.csv')
else:
    dirr=Path(os.getcwd()).resolve()
    target_dir = dirr / 'converted'
    if not target_dir.exists():
        target_dir.mkdir()
    for f in args.files:
        if not f.endswith('.pcap') and not f.endswith('.pcapng'):
            print(f'file "{f}" ignored because is not a pcap[ng] file')
            continue
        file = Path(f).resolve()
        if not file.exists():
            print(f'file "{f}" ignored because it does not exists')
            continue
        content = pd.DataFrame(
            json.load(
                sub.Popen(['tshark', '-T', 'json', '-r', str(file)], stdout=sub.PIPE).stdout
                )
            )
        pakets_data = pd.json_normalize(content['_source'])
        pakets_data.to_csv(target_dir / f'{file.stem}.csv')

