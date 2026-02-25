# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

POPKORN is a research artifact for the paper "POPKORN: Popping Windows Kernel Drivers At Scale" (ACSAC 2022). It uses symbolic execution via [angr](https://angr.io/) to detect privilege escalation vulnerabilities in Windows kernel driver binaries (`.sys` files).

**Original sinks:** `MmMapIoSpace`, `ZwOpenProcess`, `ZwMapViewOfSection`.

**Extended sinks (new):** Handle leak/exposure detection for 14 handle-creating APIs (e.g., `ZwCreateFile`, `ZwOpenThread`, `ZwDuplicateObject`, `ObOpenObjectByPointer`), and RW primitive detection for 12 additional APIs (e.g., `MmMapIoSpaceEx`, `MmCopyMemory`, `ZwReadVirtualMemory`, `ZwWriteVirtualMemory`, MDL chain APIs).

**Vulnerability categories:** `ArbitraryPhysMap`, `ProcessAccess`, `HandleLeak`, `HandleExposure`, `RWPrimitive`.

## Environment

**Required:** Ubuntu 20.04, Python 3.8.10, angr 9.2.18, capstone 5.0.6 (pinned — later versions break things). The Docker container is the canonical environment.

```bash
# Pull prebuilt image
docker pull lukasdresel/popkorn

# Or build locally
docker build -t popkorn .

# Run container
docker run -it popkorn
```

Inside the container, the virtualenv `popkorn` is auto-activated via `.bashrc`. Use `workon popkorn` if it isn't active.

## Running Analysis

**Single driver:**
```bash
python angr_analysis/angr_full_blown.py /path/to/driver.sys
```
Look for `[+] Boom!` in output to confirm a vulnerability was found. Boom! formats:
- Legacy: `[+] Boom! Here is the IOCTL:  0x...` followed by `[+] IOCTL for <sink>:  0x...`
- Handle leak: `[+] Boom! HandleLeak: <api_name> handle not closed`
- Handle exposure: `[+] Boom! HandleExposure: <api_name> handle written to output buffer`
- RW primitive: `[+] Boom! RWPrimitive: <SinkName> - arbitrary <Read/Write/ReadWrite>`

**Batch analysis (from `evaluation/`):**
```bash
# Run with 8 parallel tasks, 1-hour timeout per driver
python runner_analysis.py --parallel 8 --timeout 3600 <dataset_name>

# Export results summary to CSV
python export_results_to_csv.py ./results_<dataset_name>_timeout3600_run*/

# Print vulnerable drivers and which sinks they trigger
python evaluate_compute_bug_types.py './results_<dataset_name>_timeout3600_*'
```

**Full paper reproduction** (run 5 times for statistical validity):
```bash
cd evaluation/
for i in `seq 1 5`; do
    python runner_analysis.py --parallel 8 --timeout 3600 popkorn_drivers_with_sink_imports_only
done
python export_results_to_csv.py ./results_popkorn_drivers_with_sink_imports_only_timeout3600_run*
python evaluate_count_imports.py popkorn_drivers_with_sink_imports_only
python evaluate_compute_bug_types.py './results_popkorn_drivers_with_sink_imports_only_timeout3600_*'
```

**Analysis on a custom dataset:**
```bash
mkdir datasets/my_dataset
cp /path/to/drivers/*.sys datasets/my_dataset/
cd evaluation/
python runner_analysis.py --parallel 8 --timeout 3600 my_dataset
```

## Architecture

### Core Analysis (`angr_analysis/`)

- **`angr_full_blown.py`** — Main symbolic execution engine. Entry point for analyzing a single `.sys` file. It:
  1. Identifies WDM drivers and locates the IOCTL dispatch handler
  2. Checks for imports of vulnerable sink functions (original + extended sinks)
  3. Hooks handle-creating APIs to track kernel handle lifecycle (leak/exposure detection)
  4. Hooks RW primitive APIs to detect arbitrary read/write via symbolic parameter analysis
  5. Runs constrained symbolic execution to determine if user-controlled IOCTL buffer data can reach a sink
  6. Outputs `[+] Boom!` with vulnerability category, sink function name, and IOCTL constraints

- **`kernel_types.py`** — Registers Windows kernel struct types (`DRIVER_OBJECT`, `DEVICE_OBJECT`, `UNICODE_STRING`, etc.) with angr's type system so symbolic execution understands kernel memory layout.

- **`research_handle_leaks.md`** — Reference document cataloging all Windows kernel handle-creating APIs (14 APIs), their signatures, output handle parameter indices, and detection strategy for handle leak/exposure vulnerabilities.

- **`research_rw_primitives.md`** — Reference document cataloging extended RW primitive sink APIs (12 APIs) beyond the original POPKORN sinks, including standalone sinks (MmMapIoSpaceEx, MmCopyMemory, ZwRead/WriteVirtualMemory), MDL chain components (IoAllocateMdl, MmMapLockedPages), and info disclosure APIs.

### Evaluation Harness (`evaluation/`)

- **`runner_analysis.py`** — Map-reduce orchestrator. Spawns `angr_full_blown.py` as subprocesses with timeout enforcement, collects stdout/stderr/status per driver into a results directory. Default parallelism = `cpu_count() / 2`.

- **`config.py`** — Auto-discovers datasets under `datasets/` and provides a generator of `.sys` file paths for each dataset name.

- **`export_results_to_csv.py`** — Aggregates result directories into a summary CSV (driver name, status, timing, handle_leak_count, handle_exposure_count, rw_primitive_count).

- **`evaluate_compute_bug_types.py`** — Parses `Boom!` markers from runner output to produce `driver_name,triggered_sink_function,vuln_category` CSV. Supports both legacy two-line IOCTL format and new single-line HandleLeak/HandleExposure/RWPrimitive formats.

- **`evaluate_count_imports.py`** — Counts how many drivers import each sink function.

- **`evaluate_time_taken.py`** — Extracts per-driver analysis timing from result directories.

- **`create_filtered_imports_driver_dataset.py`** — Dataset preprocessing: filters drivers by PE imports matching sink functions. Use `--extended` flag to include handle-creating APIs and RW primitive APIs in addition to the original 3 sinks. Produces `<dataset>_imports_only` or `<dataset>_extended_sinks_only` dataset directories.

- **`manual_dedup.py`** — Manual driver deduplication utility.

### Datasets (`datasets/`)

| Dataset | Description |
|---|---|
| `popkorn_drivers_with_sink_imports_only` | Main evaluation set (~300+ WDM drivers importing at least one original sink) |
| `popkorn_drivers_with_extended_sinks_only` | Extended evaluation set (drivers importing any original, handle-creating, or RW primitive sink) |
| `physmem_drivers` | Full physmem_drivers repo collection |
| `physmem_drivers_imports_only` | Filtered subset (WDM + sink imports) |
| `CVE_sure` / `CVE_unsure` | Ground-truth CVE drivers for validation |

### Result Directory Layout

`runner_analysis.py` creates `results_<dataset>_timeout<N>_run<N>/` containing per-driver subdirectories with:
- `stdout` / `stderr` — Raw angr output
- `returncode` — Exit status
- `vuln` marker file — Present if `Boom!` was found

## Key Notes

- `capstone==5.0.6` is pinned intentionally — newer versions are incompatible.
- The angr unicorn engine warning (`failed loading "angr_native.so"`) is harmless and expected in the Docker environment.
- Analysis is stochastic due to symbolic execution path selection; running 5× and aggregating is the paper's methodology.
- `--parallel` defaults to half the available CPU cores; RAM is the practical bottleneck (~1–2 GB per concurrent driver analysis).
