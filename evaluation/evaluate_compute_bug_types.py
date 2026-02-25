import argparse
from collections import defaultdict
import glob
from io import SEEK_SET
import json
import os
import re
import sys
import csv
import tempfile
import angr
from pathlib import Path

from util import extract_drivername, fully_normalized_drivername

MSG_NO_IMPORTS_FOUND = b'''Looking for MmMapIoSpace, ZwOpenProcess, ZwMapViewOfSection Imports..

ZwOpenProcess import not found!

MmMapIoSpace import not found!

ZwMapViewOfSection import not found!
'''
MSG_NO_DRIVERENTRY = b'Could not find a successful DriverEntry run!!!'

# Vuln category mapping for the original (legacy) sink functions
LEGACY_SINK_TO_CATEGORY = {
    'MmapIoSpace': 'ArbitraryPhysMap',
    'ZwOpenProcess': 'ProcessAccess',
    'ZwMapViewOfSection': 'ArbitraryPhysMap',
}

# Regex for new-format Boom! lines
RE_BOOM_HANDLE_LEAK = re.compile(r'\[\+\] Boom! HandleLeak: (\S+) handle not closed')
RE_BOOM_HANDLE_EXPOSURE = re.compile(r'\[\+\] Boom! HandleExposure: (\S+) handle written to output buffer')
RE_BOOM_RW_PRIMITIVE = re.compile(r'\[\+\] Boom! RWPrimitive: (\S+) - arbitrary (Read|Write|ReadWrite)')
RE_BOOM_PROCESS_CONTROL = re.compile(r'\[\+\] Boom! ProcessControl: (\S+) - ')
RE_BOOM_PROCESS_INJECTION = re.compile(r'\[\+\] Boom! ProcessInjection: (\S+) - ')

parser = argparse.ArgumentParser()
parser.add_argument('-d', '--deduplicate', help='whether to use deduplicated names or not', default=False, action='store_true')
parser.add_argument('results_glob')
ARGS = parser.parse_args()

GLOB = ARGS.results_glob
DO_DEDUPLICATE = ARGS.deduplicate

per_driver_results = defaultdict(set)

driver_names = set()
analyses = set()

columns = ['Driver']
for analysis_run_complete in glob.iglob(os.path.join(GLOB, 'complete.json')):
    analysis_run_directory = Path(analysis_run_complete).absolute().resolve().parent
    ANALYSIS_ID = analysis_run_directory.name
    ANALYSIS_ID = ANALYSIS_ID.split('results_')[1]
    ANALYSIS_ID = ''.join(ANALYSIS_ID.split('_imports_only'))
    analyses.add(ANALYSIS_ID)

    for driver_results_dir in analysis_run_directory.glob('*.sys'):
        assert driver_results_dir.is_dir(), f"{driver_results_dir=} is not a directory"
        DRIVER_NAME = driver_results_dir.name
        driver_names.add(DRIVER_NAME)

        if not (driver_results_dir / 'vulnerable').is_file():
            continue
        with open(driver_results_dir / 'status', 'r') as f:
            status = f.read()
        with open(driver_results_dir / 'vulnerable', 'r') as f:
            vuln_desc = f.read()

        assert 'Boom!' in vuln_desc
        lines = [l.strip() for l in vuln_desc.strip().split('\n') if l.strip()]

        cur_results = set()
        cur_boom = -1

        # Legacy format: two-line IOCTL pattern
        # [+] Boom! Here is the IOCTL:  0x...
        # [+] IOCTL for <func>:  0x...
        while (cur_boom := vuln_desc.find('[+] Boom! Here is the IOCTL: ', cur_boom+1)) != -1:
            lines_after = vuln_desc[cur_boom:].split('\n')
            ioctl_code = int(lines_after[0].split()[-1], base=0)

            ioctl_func_match = re.search('IOCTL for (MmapIoSpace|ZwOpenProcess|ZwMapViewOfSection):  (0x[0-9a-f]+)', lines_after[1])
            if not ioctl_func_match:
                # Not a legacy-format Boom (extended sink) — handled by new-format parser below
                continue
            func, ioctl_code_2 = ioctl_func_match.groups()
            ioctl_code_2 = int(ioctl_code_2, base=0)
            assert ioctl_code == ioctl_code_2
            d_name = DRIVER_NAME if not DO_DEDUPLICATE else fully_normalized_drivername(DRIVER_NAME)
            vuln_category = LEGACY_SINK_TO_CATEGORY[func]
            cur_results.add((d_name, func, vuln_category))

        # New format: single-line Boom! patterns for handle leaks, exposures, and RW primitives
        for line in lines:
            m = RE_BOOM_HANDLE_LEAK.search(line)
            if m:
                api_name = m.group(1)
                d_name = DRIVER_NAME if not DO_DEDUPLICATE else fully_normalized_drivername(DRIVER_NAME)
                cur_results.add((d_name, api_name, 'HandleLeak'))
                continue

            m = RE_BOOM_HANDLE_EXPOSURE.search(line)
            if m:
                api_name = m.group(1)
                d_name = DRIVER_NAME if not DO_DEDUPLICATE else fully_normalized_drivername(DRIVER_NAME)
                cur_results.add((d_name, api_name, 'HandleExposure'))
                continue

            m = RE_BOOM_RW_PRIMITIVE.search(line)
            if m:
                sink_name = m.group(1)
                d_name = DRIVER_NAME if not DO_DEDUPLICATE else fully_normalized_drivername(DRIVER_NAME)
                cur_results.add((d_name, sink_name, 'RWPrimitive'))
                continue

            m = RE_BOOM_PROCESS_CONTROL.search(line)
            if m:
                api_name = m.group(1)
                d_name = DRIVER_NAME if not DO_DEDUPLICATE else fully_normalized_drivername(DRIVER_NAME)
                cur_results.add((d_name, api_name, 'ProcessControl'))
                continue

            m = RE_BOOM_PROCESS_INJECTION.search(line)
            if m:
                api_name = m.group(1)
                d_name = DRIVER_NAME if not DO_DEDUPLICATE else fully_normalized_drivername(DRIVER_NAME)
                cur_results.add((d_name, api_name, 'ProcessInjection'))
                continue

        d_name = (extract_drivername if not DO_DEDUPLICATE else fully_normalized_drivername)(DRIVER_NAME)
        per_driver_results[d_name].update(cur_results)

fieldnames = ['driver_name', 'triggered_sink_function', 'vuln_category']

DRIVER_KEYS = list(sorted(per_driver_results.keys()))

per_driver_dedup = {}
with tempfile.TemporaryFile('w+', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(fieldnames)
    for driver_name in DRIVER_KEYS:
        driver_results = per_driver_results[driver_name]
        for _, func, vuln_category in sorted(driver_results, key=lambda x: (x[1], x[2])):
            writer.writerow([driver_name, func, vuln_category])

    csvfile.seek(0, SEEK_SET)
    data = csvfile.read()
    print(data)

