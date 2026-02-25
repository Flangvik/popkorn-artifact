"""
check_blocklist.py
Compares POPKORN-found vulnerable drivers against the Windows Vulnerable
Driver Blocklist (SiPolicy XML).

Usage:
    python check_blocklist.py <blocklist_xml> [results_dir ...]

Examples:
    # Check all result dirs against blocklist
    python check_blocklist.py \
        "C:/Users/Melvin/Downloads/VulnerableDriverBlockList/VulnerableDriverBlockList/SiPolicy_Audit.xml" \
        "./results_dp_drivers_pack_extended_sinks_signed_timeout1800_run0" \
        "./results_dp_drivers_raw_extended_sinks_only_timeout3600_qlkpud3d"
"""

import argparse
import hashlib
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


NS = 'urn:schemas-microsoft-com:sipolicy'


def load_blocklist(xml_path: Path):
    """Parse SiPolicy XML and return:
      - names_blocked: set of lowercase driver filenames mentioned in any Deny rule FriendlyName
      - hashes_blocked: dict {HEX_HASH_UPPER -> friendly_name} for quick lookup
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    names_blocked = set()
    hashes_blocked = {}  # hash_hex_upper -> friendly_name string

    for deny in root.iter(f'{{{NS}}}Deny'):
        friendly = deny.get('FriendlyName', '')
        hash_val = deny.get('Hash', '').upper()

        # FriendlyName looks like "ASIO32.sys Hash Sha1" or
        # "asrdrv104\<sha256> Hash Sha256" — extract the .sys filename
        parts = friendly.split()
        if parts:
            candidate = parts[0]
            # Strip any leading path component (e.g. "asrdrv104\..." → take basename)
            basename = candidate.replace('\\', '/').split('/')[-1]
            if basename.lower().endswith('.sys'):
                names_blocked.add(basename.lower())

        if hash_val:
            hashes_blocked[hash_val] = friendly

    return names_blocked, hashes_blocked


def sha256_of(path: Path) -> str:
    """Return uppercase hex SHA256 of a file."""
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest().upper()


def collect_vulnerable_drivers(results_dirs):
    """
    Scan result directories for 'vulnerable' marker files.
    Returns list of (driver_name, driver_dir_path).
    """
    found = []
    for results_dir in results_dirs:
        results_dir = Path(results_dir)
        if not results_dir.is_dir():
            print(f"[!] Results dir not found: {results_dir}", file=sys.stderr)
            continue
        for vuln_file in results_dir.rglob('vulnerable'):
            driver_dir = vuln_file.parent
            found.append((driver_dir.name, driver_dir))
    return found


def find_driver_binary(driver_name: str, dataset_dirs):
    """Search dataset directories for the actual .sys binary to hash."""
    for d in dataset_dirs:
        candidate = Path(d) / driver_name
        if candidate.is_file():
            return candidate
    return None


def main():
    parser = argparse.ArgumentParser(description='Compare POPKORN results against MS driver blocklist')
    parser.add_argument('blocklist_xml', help='Path to SiPolicy_Audit.xml')
    parser.add_argument('results_dirs', nargs='+', help='One or more results_* directories')
    parser.add_argument('--dataset-dirs', nargs='*', default=[], help='Dataset dirs to find actual .sys files for hash check')
    args = parser.parse_args()

    print(f"[*] Loading blocklist: {args.blocklist_xml}")
    names_blocked, hashes_blocked = load_blocklist(Path(args.blocklist_xml))
    print(f"    Blocked driver names : {len(names_blocked)}")
    print(f"    Blocked hashes       : {len(hashes_blocked)}")
    print()

    print("[*] Collecting vulnerable drivers from results...")
    vulns = collect_vulnerable_drivers(args.results_dirs)
    print(f"    Found {len(vulns)} vulnerable driver(s)")
    print()

    if not vulns:
        print("[!] No vulnerable drivers found in the given result directories.")
        return

    # Default dataset dirs to search (common locations relative to this script)
    script_dir = Path(__file__).resolve().parent
    default_dataset_dirs = [
        script_dir.parent / 'datasets' / 'dp_drivers_pack',
        script_dir.parent / 'datasets' / 'dp_drivers_pack_extended_sinks_signed',
        script_dir.parent / 'datasets' / 'dp_drivers_raw',
        script_dir.parent / 'datasets' / 'dp_drivers_raw_extended_sinks_only',
    ]
    dataset_dirs = [Path(d) for d in args.dataset_dirs] + default_dataset_dirs

    print(f"{'Driver':<40} {'Name match':^12} {'Hash match':^12}  Note")
    print('-' * 80)

    in_blocklist = []
    not_in_blocklist = []

    for driver_name, driver_dir in sorted(vulns):
        name_match = driver_name.lower() in names_blocked

        hash_match = False
        hash_note = ''
        binary = find_driver_binary(driver_name, dataset_dirs)
        if binary:
            file_hash = sha256_of(binary)
            if file_hash in hashes_blocked:
                hash_match = True
                hash_note = hashes_blocked[file_hash]
        else:
            hash_note = '(binary not found for hash check)'

        status = 'YES' if (name_match or hash_match) else 'no'
        print(f"{driver_name:<40} {'YES' if name_match else 'no':^12} {'YES' if hash_match else 'no':^12}  {hash_note}")

        if name_match or hash_match:
            in_blocklist.append(driver_name)
        else:
            not_in_blocklist.append(driver_name)

    print()
    print(f"[+] In blocklist     : {len(in_blocklist)}")
    for d in sorted(in_blocklist):
        print(f"      {d}")

    print(f"[-] NOT in blocklist : {len(not_in_blocklist)}  <- potential new findings!")
    for d in sorted(not_in_blocklist):
        print(f"      {d}")


if __name__ == '__main__':
    main()
