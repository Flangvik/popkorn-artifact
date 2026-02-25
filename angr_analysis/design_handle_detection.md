# Design: Handle Leak and Handle Exposure Detection

## 1. Overview

This document describes the architecture for detecting two new vulnerability classes in Windows kernel drivers using angr symbolic execution:

1. **Handle Leak**: A kernel handle is opened during IOCTL dispatch but never closed before the handler returns. This leaks kernel resources and can lead to denial-of-service or privilege escalation.

2. **Handle Exposure**: A kernel handle value is written to a user-accessible output buffer, exposing kernel object references to userland.

## 2. Current State

The existing code tracks `open_section_handles` (a tuple of `(handle_bvs, object_name)`) only for `ZwOpenSection`. There is no `ZwClose` hook. There is no generic handle tracking infrastructure.

## 3. Scope of Handle-Creating APIs

The following APIs create kernel handles that must be tracked. All are NT kernel exports that a `.sys` driver may import:

| API | Handle Parameter | Key Info |
|-----|-----------------|----------|
| `ZwOpenSection` | arg0 (OUT PHANDLE) | Already hooked; needs migration to generic tracking |
| `ZwCreateSection` | arg0 (OUT PHANDLE) | Section object creation |
| `ZwOpenProcess` | arg0 (OUT PHANDLE) | Already a sink; handle also needs tracking |
| `ZwOpenKey` / `ZwCreateKey` | arg0 (OUT PHANDLE) | Registry key handles |
| `ZwOpenFile` / `ZwCreateFile` | arg0 (OUT PHANDLE) | File handles |
| `ZwOpenEvent` | arg0 (OUT PHANDLE) | Event object handles |
| `ZwOpenThread` | arg0 (OUT PHANDLE) | Thread handle (same pattern as ZwOpenProcess) |
| `ZwDuplicateObject` | arg3 (OUT PHANDLE) | Duplicates a handle; high severity if target is user process |
| `ObOpenObjectByPointer` | arg6 (OUT PHANDLE) | Object manager handle creation |
| `ZwOpenMutant` | arg0 (OUT PHANDLE) | Mutex object (3-param pattern) |
| `ZwOpenSemaphore` | arg0 (OUT PHANDLE) | Semaphore object (3-param pattern) |
| `ZwOpenSymbolicLinkObject` | arg0 (OUT PHANDLE) | Symbolic link object (3-param pattern) |
| `ZwOpenTimer` | arg0 (OUT PHANDLE) | Timer object (3-param pattern) |

**Phase 1 (High Priority):** `ZwOpenSection` (migrate existing), `ZwCreateSection`, `ZwOpenProcess` (extend existing), `ZwOpenThread`, `ZwDuplicateObject`, `ObOpenObjectByPointer`, `ZwOpenKey`, `ZwCreateKey`, `ZwOpenFile`, `ZwCreateFile`, `ZwClose`.

**Phase 1 (Low Priority, same 3-param pattern):** `ZwOpenEvent`, `ZwOpenMutant`, `ZwOpenSemaphore`, `ZwOpenSymbolicLinkObject`, `ZwOpenTimer`.

`ZwClose` is the universal handle-closing API that must be hooked to remove handles from tracking.

## 4. Data Structures

### 4.1 Handle Tracking State

Replace `state.globals['open_section_handles']` with a unified tracking structure:

```python
# state.globals['open_handles'] is a tuple of:
#   (handle_bvs, api_name, creation_pc_int)
#
# - handle_bvs: the symbolic BVS written to the PHANDLE output parameter
# - api_name: string identifying which API created it (e.g., "ZwOpenSection")
# - creation_pc_int: integer PC address where the hook ran (for diagnostics)
```

Backward compatibility: `open_section_handles` will be removed. The existing `ZwMapViewOfSection_analysis` will be updated to query `open_handles` instead, filtering by `api_name == "ZwOpenSection"`.

### 4.2 Initialization

In `find_ioctls()`, add to state setup:
```python
state.globals['open_handles'] = ()
```

In `find_ioctl_handler()`, also initialize (some handles may be opened during DriverEntry):
```python
init_state.globals['open_handles'] = ()
```

## 5. SimProcedure Design

### 5.1 Generic Handle-Creating Hook Pattern

All handle-creating hooks follow the same pattern:

```python
class HookZwCreateHandle(angr.SimProcedure):
    """Base pattern for any Zw*Open*/Zw*Create* that outputs a handle."""

    API_NAME = "Generic"        # Override in subclass
    HANDLE_ARG_INDEX = 0        # Which argument is the PHANDLE output

    def run(self, *args):
        handle_out_ptr = args[self.HANDLE_ARG_INDEX]

        # Create a unique symbolic handle
        handle_bvs = claripy.BVS(
            f'handle_{self.API_NAME}_{self.state.addr:#x}',
            self.state.arch.bits
        )

        # Write handle to output pointer
        self.state.memory.store(
            handle_out_ptr, handle_bvs,
            endness=self.state.arch.memory_endness
        )

        # Track the handle
        creation_pc = self.state.addr
        self.state.globals['open_handles'] += (
            (handle_bvs, self.API_NAME, creation_pc),
        )

        return 0  # STATUS_SUCCESS
```

Each concrete hook class overrides `API_NAME` and optionally adds API-specific logic.

### 5.2 HookZwOpenSection (Modified)

Keep existing `open_section_handles` logic for `ZwMapViewOfSection_analysis` backward compatibility, BUT also register in `open_handles`:

```python
class HookZwOpenSection(angr.SimProcedure):
    def run(self, SectionHandle, DesiredAccess, ObjectAttributes):
        handle_bvs = claripy.BVS(
            f'handle_ZwOpenSection_{self.state.addr:#x}',
            self.state.arch.bits
        )
        self.state.memory.store(
            SectionHandle, handle_bvs,
            endness=self.state.arch.memory_endness
        )

        # Existing section-specific tracking (for ZwMapViewOfSection analysis)
        object_name_struct = self.state.mem[ObjectAttributes].OBJECT_ATTRIBUTES.ObjectName.deref
        try:
            object_name = object_name_struct.Buffer.deref.wstring.concrete
        except:
            object_name = "<unknown>"
        self.state.globals['open_section_handles'] += ((handle_bvs, object_name),)

        # Generic handle tracking (for leak/exposure detection)
        self.state.globals['open_handles'] += (
            (handle_bvs, "ZwOpenSection", self.state.addr),
        )

        return 0
```

### 5.3 HookZwClose (New)

This is the critical counterpart. When a handle is closed, we remove it from `open_handles`:

```python
class HookZwClose(angr.SimProcedure):
    def run(self, Handle):
        remaining = []
        closed_any = False

        for entry in self.state.globals['open_handles']:
            stored_handle, api_name, creation_pc = entry
            # Use solver-based matching: could this handle equal the argument?
            if self.state.solver.satisfiable(
                extra_constraints=[stored_handle == Handle]
            ):
                closed_any = True
                # Do NOT add this entry to remaining (it's being closed)
                # Also remove from open_section_handles if applicable
                if api_name == "ZwOpenSection":
                    self.state.globals['open_section_handles'] = tuple(
                        e for e in self.state.globals['open_section_handles']
                        if not self.state.solver.satisfiable(
                            extra_constraints=[e[0] == Handle]
                        )
                    )
            else:
                remaining.append(entry)

        self.state.globals['open_handles'] = tuple(remaining)
        return 0  # STATUS_SUCCESS
```

**Key design decision**: We use `solver.satisfiable(extra_constraints=[...])` rather than concrete equality because handles may be symbolic. If the solver says the stored handle *could* equal the closed handle under current constraints, we remove it. This is sound: if a driver properly closes its handles on any feasible path, we don't report a false positive.

### 5.4 Additional Handle Hooks

Each follows the generic pattern. Specific examples:

```python
class HookZwCreateSection(angr.SimProcedure):
    def run(self, SectionHandle, DesiredAccess, ObjectAttributes,
            MaximumSize, SectionPageProtection, AllocationAttributes,
            FileHandle):
        handle_bvs = claripy.BVS(
            f'handle_ZwCreateSection_{self.state.addr:#x}',
            self.state.arch.bits
        )
        self.state.memory.store(
            SectionHandle, handle_bvs,
            endness=self.state.arch.memory_endness
        )
        self.state.globals['open_handles'] += (
            (handle_bvs, "ZwCreateSection", self.state.addr),
        )
        return 0

class HookZwOpenKey(angr.SimProcedure):
    def run(self, KeyHandle, DesiredAccess, ObjectAttributes):
        handle_bvs = claripy.BVS(
            f'handle_ZwOpenKey_{self.state.addr:#x}',
            self.state.arch.bits
        )
        self.state.memory.store(
            KeyHandle, handle_bvs,
            endness=self.state.arch.memory_endness
        )
        self.state.globals['open_handles'] += (
            (handle_bvs, "ZwOpenKey", self.state.addr),
        )
        return 0

class HookZwCreateKey(angr.SimProcedure):
    def run(self, KeyHandle, DesiredAccess, ObjectAttributes,
            TitleIndex, Class, CreateOptions, Disposition):
        handle_bvs = claripy.BVS(
            f'handle_ZwCreateKey_{self.state.addr:#x}',
            self.state.arch.bits
        )
        self.state.memory.store(
            KeyHandle, handle_bvs,
            endness=self.state.arch.memory_endness
        )
        self.state.globals['open_handles'] += (
            (handle_bvs, "ZwCreateKey", self.state.addr),
        )
        return 0

class HookZwOpenFile(angr.SimProcedure):
    def run(self, FileHandle, DesiredAccess, ObjectAttributes,
            IoStatusBlock, ShareAccess, OpenOptions):
        handle_bvs = claripy.BVS(
            f'handle_ZwOpenFile_{self.state.addr:#x}',
            self.state.arch.bits
        )
        self.state.memory.store(
            FileHandle, handle_bvs,
            endness=self.state.arch.memory_endness
        )
        self.state.globals['open_handles'] += (
            (handle_bvs, "ZwOpenFile", self.state.addr),
        )
        return 0

class HookZwCreateFile(angr.SimProcedure):
    def run(self, FileHandle, DesiredAccess, ObjectAttributes,
            IoStatusBlock, AllocationSize, FileAttributes,
            ShareAccess, CreateDisposition, CreateOptions,
            EaBuffer, EaLength):
        handle_bvs = claripy.BVS(
            f'handle_ZwCreateFile_{self.state.addr:#x}',
            self.state.arch.bits
        )
        self.state.memory.store(
            FileHandle, handle_bvs,
            endness=self.state.arch.memory_endness
        )
        self.state.globals['open_handles'] += (
            (handle_bvs, "ZwCreateFile", self.state.addr),
        )
        return 0

class HookZwOpenThread(angr.SimProcedure):
    def run(self, ThreadHandle, DesiredAccess, ObjectAttributes, ClientId):
        handle_bvs = claripy.BVS(
            f'handle_ZwOpenThread_{self.state.addr:#x}',
            self.state.arch.bits
        )
        self.state.memory.store(
            ThreadHandle, handle_bvs,
            endness=self.state.arch.memory_endness
        )
        self.state.globals['open_handles'] += (
            (handle_bvs, "ZwOpenThread", self.state.addr),
        )
        return 0

class HookZwDuplicateObject(angr.SimProcedure):
    def run(self, SourceProcessHandle, SourceHandle,
            TargetProcessHandle, TargetHandle,
            DesiredAccess, HandleAttributes, Options):
        handle_bvs = claripy.BVS(
            f'handle_ZwDuplicateObject_{self.state.addr:#x}',
            self.state.arch.bits
        )
        # TargetHandle is at arg index 3 (PHANDLE, output)
        self.state.memory.store(
            TargetHandle, handle_bvs,
            endness=self.state.arch.memory_endness
        )
        self.state.globals['open_handles'] += (
            (handle_bvs, "ZwDuplicateObject", self.state.addr),
        )
        return 0

class HookObOpenObjectByPointer(angr.SimProcedure):
    def run(self, Object, HandleAttributes, PassedAccessState,
            DesiredAccess, ObjectType, AccessMode, Handle):
        handle_bvs = claripy.BVS(
            f'handle_ObOpenObjectByPointer_{self.state.addr:#x}',
            self.state.arch.bits
        )
        # Handle is at arg index 6 (PHANDLE, output)
        self.state.memory.store(
            Handle, handle_bvs,
            endness=self.state.arch.memory_endness
        )
        self.state.globals['open_handles'] += (
            (handle_bvs, "ObOpenObjectByPointer", self.state.addr),
        )
        return 0

# Low-priority 3-param hooks (all follow: PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)
# HookZwOpenEvent, HookZwOpenMutant, HookZwOpenSemaphore,
# HookZwOpenSymbolicLinkObject, HookZwOpenTimer
# Each is identical to HookZwOpenKey with different API_NAME.
```

### 5.5 Extending HookZwOpenProcess

The existing `ZwOpenProcess` is already a *sink target* (for the "arbitrary process open" vulnerability). We additionally need to track its handle for leak detection:

The existing code does not hook ZwOpenProcess as a SimProcedure -- it uses it as a *target address* for `find_ioctls()`. We must NOT break that. Instead, we add a SimProcedure hook that:
1. Tracks the handle in `open_handles`
2. Returns STATUS_SUCCESS and writes a symbolic handle
3. Does NOT interfere with the existing "reach this address" detection

**Important subtlety**: The existing detection works by finding a path that *reaches* `ZwOpenProcess`'s import address. If we hook it with a SimProcedure, the path still "reaches" it (the hook fires at the PLT stub address). angr treats SimProcedure hooks as executing at the hooked address, so `find_ioctls()` with `target_addr = ZwOpenProcess_addr` will still trigger when the SimProcedure runs. This is compatible.

```python
class HookZwOpenProcess(angr.SimProcedure):
    def run(self, ProcessHandle, DesiredAccess, ObjectAttributes, ClientId):
        handle_bvs = claripy.BVS(
            f'handle_ZwOpenProcess_{self.state.addr:#x}',
            self.state.arch.bits
        )
        self.state.memory.store(
            ProcessHandle, handle_bvs,
            endness=self.state.arch.memory_endness
        )
        self.state.globals['open_handles'] += (
            (handle_bvs, "ZwOpenProcess", self.state.addr),
        )
        return 0
```

## 6. Detection Logic

### 6.1 Handle Leak Detection

Performed when `find_ioctls()` returns a found state (i.e., we reached a sink). At that point, we inspect `state.globals['open_handles']`:

```python
def check_handle_leaks(found_state):
    """Check if any handles opened during IOCTL dispatch were not closed."""
    open_handles = found_state.globals.get('open_handles', ())
    for handle_bvs, api_name, creation_pc in open_handles:
        print(f"[+] Boom! HandleLeak: {api_name} handle not closed "
              f"(opened at {creation_pc:#x})")
```

**When to check**: After *every* successful `find_ioctls()` run that finds a path to any sink. Additionally, we need a separate analysis mode that checks deadended states (paths that returned from the IOCTL handler normally without hitting any existing sink). This catches drivers that leak handles on normal IOCTL paths that don't involve any of the existing sinks.

For Phase 1, we check at existing found states only. Phase 2 would add a dedicated "IOCTL return" analysis.

### 6.2 Handle Exposure Detection

A handle is "exposed" if its symbolic value appears in memory that will be returned to userland. In the IOCTL model, the output buffer is `IRP.AssociatedIrp.SystemBuffer` (for METHOD_BUFFERED) or `IRP.UserBuffer` (for METHOD_NEITHER/METHOD_OUT_DIRECT).

Detection approach:
1. At the found state, read the output buffer contents symbolically
2. Check if any handle BVS variables appear in the output buffer's AST

```python
def check_handle_exposure(found_state, ioctl_inbuf_addr, irp_addr):
    """Check if any handle values were written to the IOCTL output buffer."""
    open_handles = found_state.globals.get('open_handles', ())
    if not open_handles:
        return

    # Read SystemBuffer (output for METHOD_BUFFERED)
    output_buf_addr = found_state.mem[irp_addr].IRP.AssociatedIrp.SystemBuffer.resolved
    try:
        output_content = found_state.memory.load(output_buf_addr, 0x200)
    except:
        return

    for handle_bvs, api_name, creation_pc in open_handles:
        # Check if handle's symbolic variables appear in output buffer
        handle_vars = handle_bvs.variables
        output_vars = output_content.variables
        if handle_vars & output_vars:
            print(f"[+] Boom! HandleExposure: {api_name} handle written "
                  f"to output buffer (opened at {creation_pc:#x})")
```

## 7. Integration with Main Analysis Flow

### 7.1 Import Detection Changes

In `check_imports()`, add detection for new handle APIs and ZwClose:

```python
def check_imports(proj):
    # ... existing code ...

    # Handle-creating APIs to hook (even if not sinks themselves)
    handle_apis = [
        "ZwCreateSection", "ZwOpenKey", "ZwCreateKey",
        "ZwOpenFile", "ZwCreateFile", "ZwClose"
    ]
    for api in handle_apis:
        sym = proj.loader.find_symbol(api)
        if sym:
            print(f"[+] Found {api}: {hex(sym.rebased_addr)}")
            import_addr[api] = sym.rebased_addr

    return import_addr
```

### 7.2 Hook Registration in `__main__`

```python
# Handle tracking hooks (always registered, regardless of sink detection)
# ZwClose (handle closer)
proj.hook_symbol("ZwClose", HookZwClose(cc=mycc))

# High-priority handle creators
proj.hook_symbol("ZwCreateSection", HookZwCreateSection(cc=mycc))
proj.hook_symbol("ZwOpenProcess", HookZwOpenProcess(cc=mycc))
proj.hook_symbol("ZwOpenThread", HookZwOpenThread(cc=mycc))
proj.hook_symbol("ZwDuplicateObject", HookZwDuplicateObject(cc=mycc))
proj.hook_symbol("ObOpenObjectByPointer", HookObOpenObjectByPointer(cc=mycc))
proj.hook_symbol("ZwOpenKey", HookZwOpenKey(cc=mycc))
proj.hook_symbol("ZwCreateKey", HookZwCreateKey(cc=mycc))
proj.hook_symbol("ZwOpenFile", HookZwOpenFile(cc=mycc))
proj.hook_symbol("ZwCreateFile", HookZwCreateFile(cc=mycc))

# Low-priority handle creators (3-param pattern)
proj.hook_symbol("ZwOpenEvent", HookZwOpenEvent(cc=mycc))
proj.hook_symbol("ZwOpenMutant", HookZwOpenMutant(cc=mycc))
proj.hook_symbol("ZwOpenSemaphore", HookZwOpenSemaphore(cc=mycc))
proj.hook_symbol("ZwOpenSymbolicLinkObject", HookZwOpenSymbolicLinkObject(cc=mycc))
proj.hook_symbol("ZwOpenTimer", HookZwOpenTimer(cc=mycc))
```

Note: `proj.hook_symbol()` silently does nothing if the symbol is not imported by the driver. So registering all hooks unconditionally is safe.

### 7.3 Post-Analysis Checks

After each `find_ioctls()` call in `__main__`, add leak/exposure checks:

```python
if MMMAPIOSPACE:
    found_path, ioctl_code = find_ioctls(proj, driver_base_state, ioctl_handler_addr, mmmap_addr)
    if ioctl_code:
        # ... existing analysis ...
        MmMapIoSpace_analysis(found_path)
        print_constraint(found_path)
        # NEW: handle checks
        check_handle_leaks(found_path)
        check_handle_exposure(found_path, ioctl_inbuf_addr=0x7000000, irp_addr=0x1337000)
```

## 8. Global Flag Management

Add new global flags:

```python
HANDLE_LEAK = False
HANDLE_EXPOSURE = False
```

These are set to `True` when any handle-creating API is imported (detected in `check_imports()`). The handle leak/exposure checks only produce output but don't need separate `find_ioctls()` runs -- they piggyback on existing sink analysis.

However, for drivers that import handle APIs but NOT any existing sink (MmMapIoSpace, ZwOpenProcess, ZwMapViewOfSection), we need a fallback: run `find_ioctls()` targeting deadended states to detect leaks on normal IOCTL paths. This is a Phase 2 enhancement.

## 9. Output Format

Strict grep-able format:

```
[+] Boom! HandleLeak: ZwOpenSection handle not closed (opened at 0x14000abcd)
[+] Boom! HandleLeak: ZwCreateKey handle not closed (opened at 0x14000ef01)
[+] Boom! HandleExposure: ZwOpenProcess handle written to output buffer (opened at 0x14000ef01)
```

## 10. Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| Solver overhead from satisfiability checks in ZwClose | Limit to at most 32 tracked handles per state; warn and skip if exceeded |
| False positives from paths that wouldn't normally execute | Existing constraint system already limits to feasible paths |
| ZwClose hook removing wrong handle (symbolic aliasing) | Conservative: if close *could* match, we remove it. This reduces false positives at cost of potential false negatives |
| DriverEntry opens handles that persist legitimately | Only initialize `open_handles` tracking in `find_ioctls()` (IOCTL dispatch), not from DriverEntry state. DriverEntry handles are expected to persist. |

## 11. Testing Strategy

1. Test with existing CVE_sure drivers to ensure no regressions
2. Create a minimal synthetic driver that opens ZwOpenKey without closing -> should detect leak
3. Create a minimal synthetic driver that writes handle to output buffer -> should detect exposure
4. Run full dataset analysis and compare results to baseline
