import argparse
import functools
from lib2to3.pgen2 import driver
import hashlib
import os
import shutil
import subprocess
import angr
import archinfo
import cle
import pefile
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

NPROC = 8

# Original POPKORN sinks (physical memory mapping and process access)
ORIGINAL_SINK_IMPORTS = {'ZwMapViewOfSection', 'MmMapIoSpace', 'ZwOpenProcess'}

# Extended sinks: handle-creating APIs for handle leak/exposure detection
# Both Zw* and Nt* prefixes are included since drivers use them interchangeably.
HANDLE_CREATING_IMPORTS = {
    'ZwCreateFile',       'NtCreateFile',
    'ZwOpenFile',         'NtOpenFile',
    'ZwOpenProcess',      'NtOpenProcess',
    'ZwOpenThread',       'NtOpenThread',
    'ZwOpenSection',      'NtOpenSection',
    'ZwOpenKey',          'NtOpenKey',
    'ZwDuplicateObject',  'NtDuplicateObject',
    'ObOpenObjectByPointer',
    'ZwCreateSection',    'NtCreateSection',
    'ZwOpenEvent',        'NtOpenEvent',
    'ZwOpenMutant',       'NtOpenMutant',
    'ZwOpenSemaphore',    'NtOpenSemaphore',
    'ZwOpenSymbolicLinkObject', 'NtOpenSymbolicLinkObject',
    'ZwOpenTimer',        'NtOpenTimer',
}

# Extended sinks: RW primitive APIs (from research_rw_primitives.md and design_rw_detection.md)
RW_PRIMITIVE_IMPORTS = {
    # Standalone sinks
    'MmMapIoSpaceEx',
    'MmCopyMemory',
    'ZwReadVirtualMemory',
    'ZwWriteVirtualMemory',
    'NtReadVirtualMemory',
    'NtWriteVirtualMemory',
    # Port I/O sinks (HAL exports)
    'READ_PORT_UCHAR',
    'READ_PORT_USHORT',
    'READ_PORT_ULONG',
    'WRITE_PORT_UCHAR',
    'WRITE_PORT_USHORT',
    'WRITE_PORT_ULONG',
    # Registry write sink
    'ZwSetValueKey',
    # MDL chain components (detecting chain: IoAllocateMdl -> MmBuildMdlForNonPagedPool/MmProbeAndLockPages -> MmMapLockedPages)
    'MmMapLockedPages',
    'MmMapLockedPagesSpecifyCache',
    'IoAllocateMdl',
    'MmBuildMdlForNonPagedPool',
    'MmProbeAndLockPages',
    # Info disclosure / secondary sinks
    'MmGetPhysicalAddress',
    'HalTranslateBusAddress',
    'MmAllocateContiguousMemory',
}

# Process-control sinks: EDR/AV killing, process suspension, and cross-process injection.
# ZwTerminateProcess is the TrueSightKiller pattern; others enable suspension and injection.
PROCESS_CONTROL_IMPORTS = {
    'ZwTerminateProcess',   'NtTerminateProcess',
    'ZwTerminateThread',    'NtTerminateThread',
    'ZwSuspendProcess',     'NtSuspendProcess',
    'ZwSuspendThread',      'NtSuspendThread',
    'ZwAllocateVirtualMemory', 'NtAllocateVirtualMemory',
    'ZwProtectVirtualMemory',  'NtProtectVirtualMemory',
    'ZwUnmapViewOfSection',    'NtUnmapViewOfSection',
}

EXTENDED_SINK_IMPORTS = (ORIGINAL_SINK_IMPORTS | HANDLE_CREATING_IMPORTS |
                         RW_PRIMITIVE_IMPORTS | PROCESS_CONTROL_IMPORTS)


def recreate_dir(d):
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d, exist_ok=False)

def has_digital_signature(path):
    """Return True if the PE file has an embedded Authenticode signature block."""
    try:
        pe = pefile.PE(str(path), fast_load=True)
        # DATA_DIRECTORY index 4 is IMAGE_DIRECTORY_ENTRY_SECURITY
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        return sec_dir.VirtualAddress != 0 and sec_dir.Size != 0
    except Exception:
        return False


def map_analyze_imports(driver_path):
    t = time.time()
    matching_imports = set()
    signed = True  # default: don't filter unless --signed-only
    blocklisted = False
    try:
        if BLOCKLIST_HASHES:
            file_hash = sha256_of(driver_path)
            if file_hash in BLOCKLIST_HASHES:
                blocklisted = True
        if not blocklisted:
            if ARGS.signed_only:
                signed = has_digital_signature(driver_path)
            if signed:
                proj = angr.Project(driver_path)
                all_imports = {imp for obj in proj.loader.all_pe_objects for imp in obj.imports}
                matching_imports = all_imports.intersection(SINK_IMPORTS)
    except Exception as ex:
        print(ex)
        pass
    return driver_path, time.time() - t, matching_imports, signed, blocklisted


def reduce_analyze_imports(driver_paths, results_generator):

    recreate_dir(OUT_DATASET_DIR)

    UNSIGNED = 0
    NON_IMPORTS = 0
    IMPORTS = 0
    BLOCKLISTED = 0
    for i, (driver_path, time_taken, matching_imports, signed, blocklisted) in results_generator:
        driver_name = Path(driver_path).name
        assert driver_name

        print(f"{i}/{len(driver_paths)}: {time_taken:.04f}")
        if blocklisted:
            BLOCKLISTED += 1
            continue
        if not signed:
            UNSIGNED += 1
            continue
        if not matching_imports:
            NON_IMPORTS += 1
            continue

        IMPORTS += 1
        shutil.copyfile(driver_path, OUT_DATASET_DIR / driver_name)

    if BLOCKLIST_HASHES:
        print(f"{BLOCKLISTED} of {len(driver_paths)} drivers skipped (in Microsoft blocklist).")
    if ARGS.signed_only:
        print(f"{UNSIGNED} of {len(driver_paths)} drivers skipped (no digital signature).")
    print(f"{NON_IMPORTS} of {len(driver_paths)} drivers did not have any sink functions available.")
    print(f"{IMPORTS} of {len(driver_paths)} drivers have been copied to the new dataset @ {OUT_DATASET_DIR}.")

def analyze_map_reduce(config_name, mapper, reducer):
    cur_config = config.CONFIGS[config_name]

    drivers = list(cur_config['driver_generator']())
    NON_IMPORTS = 0
    results = enumerate(pool.imap_unordered(mapper, drivers))
    reducer(drivers, results)


parser = argparse.ArgumentParser()
parser.add_argument('--extended', default=False, action='store_true',
                    help='Use extended sink imports (handle-creating + RW primitive APIs)')
parser.add_argument('--signed-only', dest='signed_only', default=False, action='store_true',
                    help='Only include drivers that have an embedded Authenticode digital signature')
parser.add_argument('--blocklist', default=None, metavar='SIPOLICY_XML',
                    help='Path to SiPolicy_Audit.xml; skip drivers already in the Microsoft blocklist')
parser.add_argument('dataset')
ARGS = parser.parse_args()

BLOCKLIST_HASHES = set()
if ARGS.blocklist:
    print(f"[*] Loading blocklist from {ARGS.blocklist} ...")
    BLOCKLIST_HASHES = load_blocklist(Path(ARGS.blocklist))
    print(f"    {len(BLOCKLIST_HASHES)} hashes loaded.")

SINK_IMPORTS = EXTENDED_SINK_IMPORTS if ARGS.extended else ORIGINAL_SINK_IMPORTS

pool = Pool(NPROC)
DATASET_NAME = ARGS.dataset
DATASET_DIR = config.POPKORN_DIR / 'datasets'
if ARGS.extended and ARGS.signed_only:
    suffix = '_extended_sinks_signed'
elif ARGS.extended:
    suffix = '_extended_sinks_only'
elif ARGS.signed_only:
    suffix = '_signed_imports_only'
else:
    suffix = '_imports_only'
OUT_DATASET_DIR = DATASET_DIR / (ARGS.dataset + suffix)
analyze_map_reduce(ARGS.dataset, map_analyze_imports, reduce_analyze_imports)
