from collections import defaultdict
import glob
import os
import re
import sys
import csv
import angr
from pathlib import Path
from util import fully_normalized_drivername

# Legacy message pattern (old angr_full_blown.py)
MSG_NO_IMPORTS_FOUND_LEGACY = b'''Looking for MmMapIoSpace, ZwOpenProcess, ZwMapViewOfSection Imports..

ZwOpenProcess import not found!

MmMapIoSpace import not found!

ZwMapViewOfSection import not found!
'''
MSG_NO_DRIVERENTRY = b'Could not find a successful DriverEntry run!!!'


def has_no_sinks_found(stdout):
    """Check if the analysis output indicates no sink imports were found.
    Handles both old and new angr_full_blown.py output formats."""
    if MSG_NO_IMPORTS_FOUND_LEGACY in stdout:
        return True
    # New format: check if all 3 original sinks were not found and no Boom! was produced
    if (b'ZwOpenProcess import not found!' in stdout and
        b'MmMapIoSpace import not found!' in stdout and
        b'ZwMapViewOfSection import not found!' in stdout and
        b'Boom!' not in stdout):
        return True
    return False

RE_BOOM_HANDLE_LEAK = re.compile(rb'\[\+\] Boom! HandleLeak:')
RE_BOOM_HANDLE_EXPOSURE = re.compile(rb'\[\+\] Boom! HandleExposure:')
RE_BOOM_RW_PRIMITIVE = re.compile(rb'\[\+\] Boom! RWPrimitive:')


GLOB = sys.argv[1]

per_driver_results = defaultdict(dict)

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

        status_file = driver_results_dir / 'status'
        if not status_file.exists():
            continue  # skip incomplete result dirs (runner crashed mid-flight)
        flagged = (driver_results_dir / 'vulnerable').is_file()
        with open(status_file, 'r') as f:
            status = f.read()
        if os.path.exists(driver_results_dir / 'stdout'):
            with open(driver_results_dir / 'stdout', 'rb') as f:
                stdout = f.read()
        else:
            stdout = b''
        timed_out = status.strip() == '124'
        with open(driver_results_dir / 'time_taken', 'r') as f:
            time_taken = float(f.read())

        msg = ''
        if flagged:
            msg = 'VULNERABLE'
        elif status.strip() == '124': # timeout
            msg = 'timeout'
        elif driver_results_dir.name.startswith("CITMDRV_IA64_"):
            msg = 'unsupported architecture: ia64'
        elif has_no_sinks_found(stdout):
            msg = 'no sinks found'
        # elif MSG_NO_DRIVERENTRY in stdout:
        #     msg = 'could not locate ioctl handler'

        handle_leak_count = len(RE_BOOM_HANDLE_LEAK.findall(stdout))
        handle_exposure_count = len(RE_BOOM_HANDLE_EXPOSURE.findall(stdout))
        rw_primitive_count = len(RE_BOOM_RW_PRIMITIVE.findall(stdout))

        per_driver_results[DRIVER_NAME][ANALYSIS_ID] = {
            'driver': driver_results_dir.name,
            'analysis': msg,
            'time_taken': time_taken,
            'handle_leak_count': handle_leak_count,
            'handle_exposure_count': handle_exposure_count,
            'rw_primitive_count': rw_primitive_count,
        }

fieldnames = ['driver_name', 'normalized_driver_name']

ANALYSIS_KEYS = list(sorted(analyses))
DRIVER_KEYS = list(sorted(driver_names))
for key in ANALYSIS_KEYS:
    fieldnames += [key, key + '_time_taken', key + '_handle_leak_count', key + '_handle_exposure_count', key + '_rw_primitive_count']

with open('results.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(fieldnames)
    for driver_name in DRIVER_KEYS:
        norm = fully_normalized_drivername(driver_name)
        driver_results = per_driver_results[driver_name]
        row = [driver_name.replace(',', '_'), norm]
        for analysis in ANALYSIS_KEYS:
            r = driver_results[analysis]
            row += [r['analysis'], r['time_taken'], r['handle_leak_count'], r['handle_exposure_count'], r['rw_primitive_count']]
        writer.writerow(row)

