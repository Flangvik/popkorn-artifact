#!/bin/bash
RESDIR=/home/popkorn/popkorn/evaluation/results_dp_drivers_raw_extended_sinks_only_timeout3600_qlkpud3d
for d in b57nd60x.sys b57nd60a.sys b57amd64.sys B57Ports.sys; do
    echo "=== $d ==="
    tail -5 "$RESDIR/$d/stdout" 2>/dev/null || echo "(no stdout yet)"
done
