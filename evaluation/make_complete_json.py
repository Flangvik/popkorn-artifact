"""Reconstruct complete.json from per-driver result directories after a crashed run."""
import json
import sys
from pathlib import Path

results_dir = Path(sys.argv[1])
results = {}

for driver_dir in sorted(results_dir.glob('*.sys')):
    status_file = driver_dir / 'status'
    stdout_file = driver_dir / 'stdout'
    time_file   = driver_dir / 'time_taken'

    if not status_file.exists():
        continue

    status = status_file.read_text().strip()
    stdout = stdout_file.read_bytes() if stdout_file.exists() else b''
    time_taken = float(time_file.read_text()) if time_file.exists() else 0.0

    is_vulnerable = b'Boom!' in stdout

    results[driver_dir.name] = {
        'status': int(status) if status.lstrip('-').isdigit() else -1,
        'vulnerable': is_vulnerable,
        'time_taken': time_taken,
    }

    if is_vulnerable:
        (driver_dir / 'vulnerable').touch()

out = results_dir / 'complete.json'
with open(out, 'w') as f:
    json.dump(results, f, indent=2)

vuln_count = sum(1 for v in results.values() if v['vulnerable'])
print(f"Written {out}")
print(f"Drivers: {len(results)}, Vulnerable: {vuln_count}")
