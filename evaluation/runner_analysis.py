import functools
import hashlib
import json
from lib2to3.pgen2 import driver
import os
import shutil
import subprocess
import angr
import sys
import time
import xml.etree.ElementTree as ET

from multiprocessing.pool import Pool
from pathlib import Path

import config

_SIPOLICY_NS = 'urn:schemas-microsoft-com:sipolicy'

def load_blocklist(xml_path: Path):
    """Parse SiPolicy XML and return set of blocked SHA256 hashes (uppercase hex)."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    hashes = set()
    for deny in root.iter(f'{{{_SIPOLICY_NS}}}Deny'):
        h = deny.get('Hash', '').upper()
        if h:
            hashes.add(h)
    return hashes

def sha256_of(path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest().upper()

def recreate_dir(d):
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d, exist_ok=False)

def get_next_free_path(id):
    for i in range(100000000):
        p = id + f'_run{i}'
        if not os.path.exists(p):
            return p
    assert False


def map_analyze_imports(out_dir_path, driver_path):
    t = time.time()
    proj = angr.Project(driver_path)
    all_imports = {imp for obj in proj.loader.all_pe_objects for imp in obj.imports}

    matching_imports = all_imports.intersection({'ZwMapViewOfSection', "MmMapIoSpace", 'ZwOpenProcess'})
    # assert matching_imports, f"{driver_name} does not have any of the imports"

    return driver_path, time.time() - t, matching_imports


def reduce_analyze_imports(out_dir_path, driver_paths, results_generator):
    NON_IMPORTS = 0
    for i, (driver_name, time_taken, matching_imports) in results_generator:
        print(f"{i}/{len(driver_paths)}: {time_taken:.04f}")
        if not matching_imports:
            NON_IMPORTS += 1
            print('$' * 40)
            print('$' * 40)
            print('$' * 40)
            print(driver_name)
            print('$' * 40)
            print('$' * 40)
            print('$' * 40)

    print(f"{NON_IMPORTS} of {len(driver_paths)} drivers did not have any sink functions available.")

def is_vulnerable_result(subprocess_result: subprocess.CompletedProcess):
    # Mark as vulnerable if a CONFIRMED Boom! line appears in stdout.
    # We check for specific confirmed patterns rather than any "Boom!" occurrence.
    # find_ioctls() prints "[+] Boom! Here is the IOCTL:" when it finds ANY path to a
    # sink — including suppressed false positives. Only the analysis-confirmed lines
    # below indicate a real vulnerability.
    stdout = subprocess_result.stdout
    # Legacy format: original 3 sinks (MmMapIoSpace, ZwOpenProcess, ZwMapViewOfSection)
    if b'[+] IOCTL for MmapIoSpace:' in stdout: return True
    if b'[+] IOCTL for ZwOpenProcess:' in stdout: return True
    if b'[+] IOCTL for ZwMapViewOfSection:' in stdout: return True
    # New format: extended sinks (RWPrimitive, HandleLeak, HandleExposure, ProcessControl)
    if b'[+] Boom! RWPrimitive:' in stdout: return True
    if b'[+] Boom! HandleLeak:' in stdout: return True
    if b'[+] Boom! HandleExposure:' in stdout: return True
    if b'[+] Boom! ProcessControl:' in stdout: return True
    if b'[+] Boom! ProcessInjection:' in stdout: return True
    return False

def map_angr_full_blown(out_dir_path, driver_path):
    t = time.time()

    driver_name = os.path.basename(driver_path)
    result_dir = out_dir_path / driver_name
    recreate_dir(result_dir)

    # Skip drivers already in the Microsoft Vulnerable Driver Blocklist.
    if BLOCKLIST_HASHES:
        file_hash = sha256_of(driver_path)
        if file_hash in BLOCKLIST_HASHES:
            with open(str(result_dir / 'status'), 'w') as f:
                f.write('blocklisted')
            with open(str(result_dir / 'time_taken'), 'w') as f:
                f.write(str(time.time() - t))
            print(f"[skip] {driver_name} is in the Microsoft blocklist, skipping.")
            # Return a fake CompletedProcess with no output so the rest of the
            # pipeline treats this as a non-vulnerable, non-errored result.
            return driver_path, time.time() - t, subprocess.CompletedProcess(
                args=[], returncode=0, stdout=b'', stderr=b''
            )

    cmd = ['timeout', str(ARGS.timeout), sys.executable]
    cmd += [config.POPKORN_DIR / 'angr_analysis/angr_full_blown.py']
    if ARGS.directed:
        cmd += ['--directed']
    cmd += [driver_path]

    start_t = time.time()
    result = subprocess.run(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    end_t = time.time()

    with open(str(result_dir / 'time_taken'), 'w') as f:
        f.write(str(end_t - start_t))

    if result.stdout:
        with open(str(result_dir / 'stdout'), 'wb') as f:
            f.write(result.stdout)
    if result.stderr:
        with open(str(result_dir / 'stderr'), 'wb') as f:
            f.write(result.stderr)

    if is_vulnerable_result(result):
        with open(str(result_dir / 'vulnerable'), 'wb') as f:
            f.write(result.stdout)

    with open(str(result_dir / 'status'), 'wb') as f:
        f.write(str(result.returncode).encode())

    return driver_path, time.time() - t, result

def reduce_angr_full_blown(out_dir_path: Path, driver_paths, results_generator):
    results = {}

    for i, (driver_path, time_taken, result) in results_generator:
        driver_path: str
        time_taken: float
        result: subprocess.CompletedProcess
        
        print(f"{i}/{len(driver_paths)}: {time_taken:.04f}")
        x = {
            'status': result.returncode,
            'time_taken': time_taken,
            'vulnerable': is_vulnerable_result(result)
        }
        results[os.path.basename(driver_path)] = x

    with open(out_dir_path / 'complete.json', 'w') as f:
        json.dump(results, f, indent=2)

def analyze_map_reduce(config_name, mapper, reducer):
    cur_config = config.CONFIGS[config_name]

    OUTDIR = f'results_{config_name}_timeout{ARGS.timeout}'
    if ARGS.directed:
        OUTDIR += '_directed'
    OUTDIR = config.CUR_DIR / OUTDIR

    # Use a persistent numbered directory (run0, run1, ...) instead of a
    # temporary directory so partial results are never deleted on crash.
    OUT_DIR = Path(get_next_free_path(str(OUTDIR)))
    os.makedirs(OUT_DIR)
    print(f"Writing results of analyzing {config_name=} to {OUT_DIR=}")

    drivers = list(cur_config['driver_generator']())
    results = enumerate(pool.imap_unordered(functools.partial(mapper, OUT_DIR), drivers))
    reducer(OUT_DIR, drivers, results)



ANALYSES = {
    'imports': {
        'map': map_analyze_imports,
        'reduce': reduce_analyze_imports,
    },
    'full_blown': {
        'map': map_angr_full_blown,
        'reduce': reduce_angr_full_blown
    }
}

SECONDS = 1
MINUTES = 60 * SECONDS
HOURS = 60 * MINUTES
DAYS = 24 * HOURS

DEFAULT_TIMEOUT = 10 * MINUTES


AVAILABLE_CPUS = len(os.sched_getaffinity(0))
NPROC = AVAILABLE_CPUS >> 1

# Set before Pool creation so worker processes inherit it via fork.
BLOCKLIST_HASHES = set()

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--directed', default=False, action='store_true', help='use directed angr analysis')
    parser.add_argument('-t', '--timeout', default=DEFAULT_TIMEOUT, type=int, help='the timeout for each analysis')
    parser.add_argument('-p', '--parallel', default=(AVAILABLE_CPUS//2), type=int, help='the number of tasks to spawn in parallel')
    parser.add_argument('-a', '--analysis', default='full_blown', choices=list(ANALYSES.keys()), help='which analysis to run')
    parser.add_argument('--blocklist', default=None, metavar='SIPOLICY_XML',
                        help='Path to SiPolicy_Audit.xml; skip drivers already in the Microsoft blocklist')
    parser.add_argument('dataset', choices=list(config.CONFIGS.keys()))

    ARGS = parser.parse_args()

    if ARGS.blocklist:
        print(f"[*] Loading blocklist from {ARGS.blocklist} ...")
        BLOCKLIST_HASHES.update(load_blocklist(Path(ARGS.blocklist)))
        print(f"    {len(BLOCKLIST_HASHES)} hashes loaded.")

    pool = Pool(ARGS.parallel)

    analysis = ANALYSES[ARGS.analysis]
    analyze_map_reduce(ARGS.dataset, analysis['map'], analysis['reduce'])
