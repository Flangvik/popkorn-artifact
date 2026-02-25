# Design: Extended Read/Write Primitive Detection

## 1. Overview

This document describes the architecture for detecting additional arbitrary read/write primitive sinks beyond the three currently detected by POPKORN (`MmMapIoSpace`, `ZwMapViewOfSection`, `ZwOpenProcess`).

The existing sinks detect *memory mapping* and *process access* primitives. This extension adds detection of:

- **Arbitrary physical/virtual memory read/write** via additional APIs
- **Arbitrary port I/O** for hardware-level attacks
- **Arbitrary registry access** where keys/values are user-controlled

## 2. Current Sink Detection Pattern

The existing pattern is:
1. `check_imports()` looks for the import symbol
2. A global flag is set if found
3. `find_ioctls()` performs symbolic execution targeting that address
4. A `*_analysis()` function checks whether critical arguments are tainted by IOCTL input

The extension follows the same pattern. The key insight is: **a sink is only "Boom!" worthy if the critical address/value argument is tainted by IOCTL input** (i.e., its `.variables` set contains `'ioctl_inbuf'` or `'ioctl_type3_inbuf'` substrings).

## 3. New Sink APIs

### 3.1 Memory Read/Write Primitives

| API | Vuln Type | Critical Args | Taint Check |
|-----|-----------|--------------|-------------|
| `MmMapIoSpace` | ReadWrite | arg0 (PhysicalAddress) | Already detected |
| `MmMapIoSpaceEx` | ReadWrite | arg0 (PhysicalAddress) | NEW - same as MmMapIoSpace + arg3 (Protect) |
| `ZwMapViewOfSection` | ReadWrite | arg0 (SectionHandle) | Already detected |
| `MmCopyMemory` | Read | arg1 (SourceAddress), arg2 (PhysicalOrVirtual flag) | NEW |
| `ZwReadVirtualMemory` | Read | arg1 (BaseAddress) | NEW - undocumented but exported by ntoskrnl |
| `ZwWriteVirtualMemory` | Write | arg1 (BaseAddress), arg2 (Buffer) | NEW - undocumented but exported by ntoskrnl |

### 3.2 Port I/O Primitives

| API | Vuln Type | Critical Args | Taint Check |
|-----|-----------|--------------|-------------|
| `READ_PORT_UCHAR` / `READ_PORT_USHORT` / `READ_PORT_ULONG` | Read | arg0 (Port) | NEW |
| `WRITE_PORT_UCHAR` / `WRITE_PORT_USHORT` / `WRITE_PORT_ULONG` | Write | arg0 (Port), arg1 (Value) | NEW |

These are HAL exports. They map to `in`/`out` x86 instructions. Some drivers import the HAL functions; others inline the instructions. Phase 1 covers the imported function case.

### 3.3 Registry Primitives (User-Controlled)

| API | Vuln Type | Critical Args | Taint Check |
|-----|-----------|--------------|-------------|
| `ZwSetValueKey` | Write | arg1 (ValueName), arg4 (Data) from IOCTL input | NEW |

This catches drivers that let IOCTL callers write arbitrary registry values.

### 3.10 MmMapLockedPagesSpecifyCache / MmMapLockedPages

| Property | Value |
|----------|-------|
| **Signature (SpecifyCache)** | `PVOID MmMapLockedPagesSpecifyCache(PMDL MemoryDescriptorList, KPROCESSOR_MODE AccessMode, MEMORY_CACHING_TYPE CacheType, PVOID RequestedAddress, ULONG BugCheckOnFailure, ULONG Priority)` |
| **Signature (Legacy)** | `PVOID MmMapLockedPages(PMDL MemoryDescriptorList, KPROCESSOR_MODE AccessMode)` |
| **Vulnerability** | Maps MDL pages into virtual address space. If the MDL was created from user-controlled address via `IoAllocateMdl`, enables arbitrary physical memory mapping. |
| **Critical Args** | `MemoryDescriptorList` (arg0) -- traced back via MDL provenance |
| **Taint Check** | Requires MDL provenance tracking (Section 8) |
| **Sink Name** | `MmMapLockedPages` |

### 3.11 MmGetPhysicalAddress

| Property | Value |
|----------|-------|
| **Signature** | `PHYSICAL_ADDRESS MmGetPhysicalAddress(PVOID BaseAddress)` |
| **Vulnerability** | Physical address disclosure. Enables KASLR bypass and feeds into MmMapIoSpace chains. |
| **Critical Args** | `BaseAddress` (arg0) |
| **Taint Check** | `BaseAddress` must be symbolic/tainted |
| **Sink Name** | `MmGetPhysicalAddress` |
| **Notes** | Lower severity informational primitive. |

### 3.12 HalTranslateBusAddress

| Property | Value |
|----------|-------|
| **Signature** | `BOOLEAN HalTranslateBusAddress(INTERFACE_TYPE InterfaceType, ULONG BusNumber, PHYSICAL_ADDRESS BusAddress, PULONG AddressSpace, PPHYSICAL_ADDRESS TranslatedAddress)` |
| **Vulnerability** | Translates bus-relative addresses. If `BusAddress` is user-controlled, facilitates MMIO attacks. |
| **Critical Args** | `BusAddress` (arg2) |
| **Sink Name** | `HalTranslateBusAddress` |

## 4. Phase 1 Implementation Scope

For the initial implementation, we add detection for ALL sinks listed above:

1. **MmMapIoSpaceEx** - Direct extension of existing MmMapIoSpace
2. **MmCopyMemory** - Arbitrary physical/virtual memory read
3. **ZwReadVirtualMemory** - Arbitrary process memory read (undocumented, high value)
4. **ZwWriteVirtualMemory** - Arbitrary process memory write (undocumented, high value)
5. **MmMapLockedPagesSpecifyCache / MmMapLockedPages** - MDL-based arbitrary physical memory mapping
6. **MmGetPhysicalAddress** - Physical address disclosure
7. **HalTranslateBusAddress** - Bus address translation for MMIO attacks
8. **READ_PORT_UCHAR/USHORT/ULONG** - Arbitrary port read
9. **WRITE_PORT_UCHAR/USHORT/ULONG** - Arbitrary port write
10. **ZwSetValueKey** - Arbitrary registry write

Phase 2 (future):
- `__readmsr`/`__writemsr` (instruction-level hooking for MSR access)
- Inlined `in`/`out` instructions

## 5. Taint Checking Helper

Create a shared helper function for all new sinks:

```python
def is_ioctl_tainted(bv):
    """Check if a bitvector's symbolic variables are tainted by IOCTL input.

    Returns True if any variable in the BV's AST comes from the IOCTL
    input buffer (METHOD_BUFFERED SystemBuffer or METHOD_NEITHER Type3InputBuffer).
    """
    if not bv.symbolic:
        return False
    return any(
        'ioctl_inbuf' in v or 'ioctl_type3_inbuf' in v
        for v in bv.variables
    )


def check_narrow_constraints(found_state, bvs, name="arg"):
    """Check if a symbolic value is constrained to a narrow range.

    If the solver can only produce <= 4 distinct values, the argument
    is likely constrained by the driver's validation logic and may not
    be practically exploitable. Print a warning.
    """
    if not bvs.symbolic:
        return
    vals = found_state.solver.eval_upto(bvs, 5)
    if len(vals) <= 4:
        print(f"[!] Note: {name} is constrained to {len(vals)} values: "
              f"{[hex(v) for v in vals]} -- may be a false positive")
```

## 6. Analysis Functions for New Sinks

### 6.1 Design Decision: Hook vs. Target Address

For the existing sinks (MmMapIoSpace, ZwOpenProcess, ZwMapViewOfSection), the detection works by:
1. Using the import address as a `target_addr` for `find_ioctls()`
2. Running a separate `*_analysis()` function on the found state

For new sinks, we follow the same approach: find a path to the sink address, then analyze the arguments at the found state using calling convention introspection.

### 6.2 Analysis Functions

```python
def MmMapIoSpaceEx_analysis(found_state):
    """MmMapIoSpaceEx(PhysicalAddress, NumberOfBytes, Protect)"""
    prototype = mycc.guess_prototype((0, 0, 0))
    PhysicalAddress, NumberOfBytes, Protect = mycc.get_args(found_state, prototype)

    if is_ioctl_tainted(PhysicalAddress):
        print("[+] Boom! RWPrimitive: MmMapIoSpaceEx - "
              f"arbitrary ReadWrite (PhysicalAddress={PhysicalAddress})")
    elif is_ioctl_tainted(NumberOfBytes):
        print("[+] Boom! RWPrimitive: MmMapIoSpaceEx - "
              f"arbitrary ReadWrite (NumberOfBytes controlled)")


def MmCopyMemory_analysis(found_state):
    """MmCopyMemory(TargetAddress, SourceAddress, NumberOfBytes,
                    Flags, NumberOfBytesTransferred)

    SourceAddress is a LARGE_INTEGER (physical or virtual depending on Flags).
    If Flags == MM_COPY_MEMORY_PHYSICAL (0x1), SourceAddress is physical.
    If Flags == MM_COPY_MEMORY_VIRTUAL (0x2), SourceAddress is virtual.
    """
    prototype = mycc.guess_prototype((0, 0, 0, 0, 0))
    TargetAddr, SourceAddr, NumBytes, Flags, _ = mycc.get_args(
        found_state, prototype
    )

    if is_ioctl_tainted(SourceAddr):
        check_narrow_constraints(found_state, SourceAddr, "SourceAddress")
        print("[+] Boom! RWPrimitive: MmCopyMemory - "
              f"arbitrary Read (SourceAddress={SourceAddr})")
    if is_ioctl_tainted(TargetAddr):
        check_narrow_constraints(found_state, TargetAddr, "TargetAddress")
        print("[+] Boom! RWPrimitive: MmCopyMemory - "
              f"arbitrary Write (TargetAddress={TargetAddr})")


def ReadPortAnalysis(found_state, port_size_name):
    """READ_PORT_UCHAR/USHORT/ULONG(Port)"""
    prototype = mycc.guess_prototype((0,))
    Port, = mycc.get_args(found_state, prototype)

    if is_ioctl_tainted(Port):
        print(f"[+] Boom! RWPrimitive: READ_PORT_{port_size_name} - "
              f"arbitrary Read (Port={Port})")


def WritePortAnalysis(found_state, port_size_name):
    """WRITE_PORT_UCHAR/USHORT/ULONG(Port, Value)"""
    prototype = mycc.guess_prototype((0, 0))
    Port, Value = mycc.get_args(found_state, prototype)

    if is_ioctl_tainted(Port) and is_ioctl_tainted(Value):
        print(f"[+] Boom! RWPrimitive: WRITE_PORT_{port_size_name} - "
              f"arbitrary Write (Port+Value controlled)")
    elif is_ioctl_tainted(Port):
        print(f"[+] Boom! RWPrimitive: WRITE_PORT_{port_size_name} - "
              f"arbitrary Write (Port controlled)")


def ZwReadVirtualMemory_analysis(found_state):
    """ZwReadVirtualMemory(ProcessHandle, BaseAddress, Buffer,
                           NumberOfBytesToRead, NumberOfBytesRead)

    Undocumented but exported by ntoskrnl. Reads memory from a process.
    """
    prototype = mycc.guess_prototype((0, 0, 0, 0, 0))
    ProcessHandle, BaseAddress, Buffer, NumBytes, _ = mycc.get_args(
        found_state, prototype
    )

    if is_ioctl_tainted(BaseAddress):
        print("[+] Boom! RWPrimitive: ZwReadVirtualMemory - "
              f"arbitrary Read (BaseAddress={BaseAddress})")


def ZwWriteVirtualMemory_analysis(found_state):
    """ZwWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer,
                            NumberOfBytesToWrite, NumberOfBytesWritten)

    Undocumented but exported by ntoskrnl. Writes memory to a process.
    """
    prototype = mycc.guess_prototype((0, 0, 0, 0, 0))
    ProcessHandle, BaseAddress, Buffer, NumBytes, _ = mycc.get_args(
        found_state, prototype
    )

    if is_ioctl_tainted(BaseAddress) and is_ioctl_tainted(Buffer):
        print("[+] Boom! RWPrimitive: ZwWriteVirtualMemory - "
              f"arbitrary Write (BaseAddress+Buffer controlled)")
    elif is_ioctl_tainted(BaseAddress):
        print("[+] Boom! RWPrimitive: ZwWriteVirtualMemory - "
              f"arbitrary Write (BaseAddress controlled)")


def ZwSetValueKey_analysis(found_state):
    """ZwSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize)"""
    prototype = mycc.guess_prototype((0, 0, 0, 0, 0, 0))
    KeyHandle, ValueName, TitleIndex, Type, Data, DataSize = mycc.get_args(
        found_state, prototype
    )

    if is_ioctl_tainted(Data) or is_ioctl_tainted(ValueName):
        print("[+] Boom! RWPrimitive: ZwSetValueKey - "
              f"arbitrary Write (registry, Data tainted={is_ioctl_tainted(Data)}, "
              f"ValueName tainted={is_ioctl_tainted(ValueName)})")


def MmMapLockedPages_analysis(found_state):
    """Handles both MmMapLockedPages and MmMapLockedPagesSpecifyCache.
    For SpecifyCache, extra args are ignored -- only MDL (arg0) matters."""
    prototype = mycc.guess_prototype((0, 0))
    MemoryDescriptorList, AccessMode = mycc.get_args(found_state, prototype)

    # Direct check: is MDL pointer itself tainted?
    if MemoryDescriptorList.symbolic and is_ioctl_tainted(MemoryDescriptorList):
        print("[+] MDL pointer is user controlled: "
              f"MDL={MemoryDescriptorList} ..")
        print("[+] Boom! RWPrimitive: MmMapLockedPages - "
              "arbitrary ReadWrite (MDL pointer tainted)")
        return

    # Provenance check: trace MDL back through IoAllocateMdl
    mdl_prov = found_state.globals.get('mdl_provenance', ())
    for (mdl_addr, source_addr, api_name) in mdl_prov:
        if found_state.solver.satisfiable(
                extra_constraints=[MemoryDescriptorList == mdl_addr]):
            if source_addr.symbolic and is_ioctl_tainted(source_addr):
                check_narrow_constraints(found_state, source_addr, "MDL.SourceAddr")
                print("[+] MDL created from user-controlled address: "
                      f"SourceAddr={source_addr} (via {api_name}) ..")
                print("[+] Boom! RWPrimitive: MmMapLockedPages - "
                      "arbitrary ReadWrite (MDL chain vulnerable)")
                return


def MmGetPhysicalAddress_analysis(found_state):
    """MmGetPhysicalAddress(BaseAddress)"""
    prototype = mycc.guess_prototype((0,))
    BaseAddress, = mycc.get_args(found_state, prototype)

    if BaseAddress.symbolic and is_ioctl_tainted(BaseAddress):
        check_narrow_constraints(found_state, BaseAddress, "BaseAddress")
        print("[+] BaseAddress is user controlled: "
              f"Addr={BaseAddress} ..")
        print("[+] Boom! RWPrimitive: MmGetPhysicalAddress - "
              "physical address disclosure")


def HalTranslateBusAddress_analysis(found_state):
    """HalTranslateBusAddress(InterfaceType, BusNumber, BusAddress,
                               AddressSpace, TranslatedAddress)"""
    prototype = mycc.guess_prototype((0, 0, 0, 0, 0))
    InterfaceType, BusNumber, BusAddress, AddressSpace, TranslatedAddress = \
        mycc.get_args(found_state, prototype)

    if BusAddress.symbolic and is_ioctl_tainted(BusAddress):
        check_narrow_constraints(found_state, BusAddress, "BusAddress")
        print("[+] BusAddress is user controlled: "
              f"Addr={BusAddress} ..")
        print("[+] Boom! RWPrimitive: HalTranslateBusAddress - "
              "arbitrary bus address translation")
```

## 7. Integration with check_imports() and Main Flow

### 7.1 RW Sinks Dict (replaces individual boolean flags)

```python
# Module-level dict: maps api_name -> rebased_addr for all detected RW sinks.
# Replaces individual boolean flags (MMMAPIOSPACEEX etc.) — use `'ApiName' in RW_SINKS`
# to check presence, and `RW_SINKS['ApiName']` to get the address.
RW_SINKS = {}
```

### 7.2 Extended check_imports()

```python
def check_imports(proj):
    # ... existing code for MmMapIoSpace, ZwOpenProcess, ZwMapViewOfSection ...

    # New RW primitive sinks (includes Nt-prefixed variants of undocumented APIs)
    new_rw_sinks = [
        "MmMapIoSpaceEx",
        "MmCopyMemory",
        "ZwReadVirtualMemory",
        "NtReadVirtualMemory",   # Nt-prefixed variant; same detection logic
        "ZwWriteVirtualMemory",
        "NtWriteVirtualMemory",  # Nt-prefixed variant; same detection logic
        "MmMapLockedPagesSpecifyCache",
        "MmMapLockedPages",
        "MmGetPhysicalAddress",
        "HalTranslateBusAddress",
        "READ_PORT_UCHAR",
        "READ_PORT_USHORT",
        "READ_PORT_ULONG",
        "WRITE_PORT_UCHAR",
        "WRITE_PORT_USHORT",
        "WRITE_PORT_ULONG",
        "ZwSetValueKey",
    ]

    # Also detect MDL chain helper APIs (needed for provenance hooks)
    for mdl_api in ['IoAllocateMdl', 'MmBuildMdlForNonPagedPool']:
        sym = proj.loader.find_symbol(mdl_api)
        if sym:
            print(f"[+] Found {mdl_api}: {hex(sym.rebased_addr)}")
            import_addr[mdl_api] = sym.rebased_addr

    for api_name in new_rw_sinks:
        sym = proj.loader.find_symbol(api_name)
        if sym:
            print(f"[+] Found {api_name}: {hex(sym.rebased_addr)}")
            RW_SINKS[api_name] = sym.rebased_addr
            import_addr[api_name] = sym.rebased_addr

    return import_addr
```

### 7.3 Main Flow Extension

In `__main__`, after existing sink analysis. All checks use `RW_SINKS` dict — no individual boolean flags:

```python
# Simple single-target sinks
_SIMPLE_SINKS = {
    'MmMapIoSpaceEx':       MmMapIoSpaceEx_analysis,
    'MmCopyMemory':         MmCopyMemory_analysis,
    'MmGetPhysicalAddress': MmGetPhysicalAddress_analysis,
    'HalTranslateBusAddress': HalTranslateBusAddress_analysis,
    'ZwSetValueKey':        ZwSetValueKey_analysis,
}
for _api, _fn in _SIMPLE_SINKS.items():
    if _api in RW_SINKS:
        found_path, ioctl_code = find_ioctls(proj, driver_base_state, ioctl_handler_addr, RW_SINKS[_api])
        if ioctl_code:
            print(f"[+] IOCTL for {_api}: {hex(ioctl_code)}")
            _fn(found_path)
            print_constraint(found_path)

# ZwRead/WriteVirtualMemory: check both Zw and Nt prefixed variants
for _zw, _nt, _fn in [
    ('ZwReadVirtualMemory',  'NtReadVirtualMemory',  ZwReadVirtualMemory_analysis),
    ('ZwWriteVirtualMemory', 'NtWriteVirtualMemory', ZwWriteVirtualMemory_analysis),
]:
    _api = _zw if _zw in RW_SINKS else (_nt if _nt in RW_SINKS else None)
    if _api:
        found_path, ioctl_code = find_ioctls(proj, driver_base_state, ioctl_handler_addr, RW_SINKS[_api])
        if ioctl_code:
            print(f"[+] IOCTL for {_api}: {hex(ioctl_code)}")
            _fn(found_path)
            print_constraint(found_path)

# MDL-based mapping (both variants share one analysis function)
for _api in ['MmMapLockedPagesSpecifyCache', 'MmMapLockedPages']:
    if _api in RW_SINKS:
        found_path, ioctl_code = find_ioctls(proj, driver_base_state, ioctl_handler_addr, RW_SINKS[_api])
        if ioctl_code:
            print(f"[+] IOCTL for {_api}: {hex(ioctl_code)}")
            MmMapLockedPages_analysis(found_path)
            print_constraint(found_path)

# Port I/O
for _api in ['READ_PORT_UCHAR', 'READ_PORT_USHORT', 'READ_PORT_ULONG']:
    if _api in RW_SINKS:
        found_path, ioctl_code = find_ioctls(proj, driver_base_state, ioctl_handler_addr, RW_SINKS[_api])
        if ioctl_code:
            print(f"[+] IOCTL for {_api}: {hex(ioctl_code)}")
            ReadPortAnalysis(found_path, _api.split('_')[-1])
            print_constraint(found_path)

for _api in ['WRITE_PORT_UCHAR', 'WRITE_PORT_USHORT', 'WRITE_PORT_ULONG']:
    if _api in RW_SINKS:
        found_path, ioctl_code = find_ioctls(proj, driver_base_state, ioctl_handler_addr, RW_SINKS[_api])
        if ioctl_code:
            print(f"[+] IOCTL for {_api}: {hex(ioctl_code)}")
            WritePortAnalysis(found_path, _api.split('_')[-1])
            print_constraint(found_path)
```

## 8. SimProcedure Hooks for New Sinks

**Why hooks ARE needed**: POPKORN uses `auto_load_libs=False`, meaning external calls that are not hooked cause angr to raise `SimProcedureError` or jump to unresolvable addresses. For symbolic execution to explore paths through new sink APIs without crashing, each new API needs a SimProcedure hook that returns a plausible value. The hook fires at the hooked address, and angr's Explorer technique still detects when the path reaches that address.

Additionally, some sink APIs (MmMapLockedPages, MmMapIoSpaceEx) appear as intermediate calls on paths to other sinks. Without hooks, those paths would fail before reaching the final target.

### 8.1 Sink SimProcedure Hooks

```python
class HookMmCopyMemory(angr.SimProcedure):
    def run(self, TargetAddress, SourceAddress, NumberOfBytes, Flags,
            NumberOfBytesTransferred):
        self.state.memory.store(NumberOfBytesTransferred, NumberOfBytes,
                                endness=self.state.arch.memory_endness)
        return 0

class HookMmMapIoSpaceEx(angr.SimProcedure):
    def run(self, PhysicalAddress, NumberOfBytes, Protect):
        return next_base_addr()

class HookZwWriteVirtualMemory(angr.SimProcedure):
    def run(self, ProcessHandle, BaseAddress, Buffer,
            NumberOfBytesToWrite, NumberOfBytesWritten):
        return 0

class HookZwReadVirtualMemory(angr.SimProcedure):
    def run(self, ProcessHandle, BaseAddress, Buffer,
            NumberOfBytesToRead, NumberOfBytesRead):
        return 0

class HookMmMapLockedPagesSpecifyCache(angr.SimProcedure):
    def run(self, MemoryDescriptorList, AccessMode, CacheType,
            RequestedAddress, BugCheckOnFailure, Priority):
        return next_base_addr()

class HookMmMapLockedPages(angr.SimProcedure):
    def run(self, MemoryDescriptorList, AccessMode):
        return next_base_addr()

class HookMmGetPhysicalAddress(angr.SimProcedure):
    def run(self, BaseAddress):
        return claripy.BVS('phys_addr', 64)

class HookHalTranslateBusAddress(angr.SimProcedure):
    def run(self, InterfaceType, BusNumber, BusAddress,
            AddressSpace, TranslatedAddress):
        translated = claripy.BVS('translated_bus_addr', 64)
        self.state.memory.store(TranslatedAddress, translated,
                                endness=self.state.arch.memory_endness)
        self.state.memory.store(AddressSpace, claripy.BVV(1, 32),
                                endness=self.state.arch.memory_endness)
        return 1  # TRUE

class HookReadPort(angr.SimProcedure):
    RESULT_BITS = 8
    def run(self, Port):
        return claripy.BVS('port_read_val', self.RESULT_BITS)

class HookReadPortUChar(HookReadPort):
    RESULT_BITS = 8

class HookReadPortUShort(HookReadPort):
    RESULT_BITS = 16

class HookReadPortULong(HookReadPort):
    RESULT_BITS = 32

class HookWritePort(angr.SimProcedure):
    def run(self, Port, Value):
        return  # void

class HookZwSetValueKey(angr.SimProcedure):
    def run(self, KeyHandle, ValueName, TitleIndex, Type, Data, DataSize):
        return 0
```

### 8.2 MDL Chain Hooks

```python
class HookIoAllocateMdl(angr.SimProcedure):
    """IoAllocateMdl(VirtualAddress, Length, SecondaryBuffer, ChargeQuota, Irp)"""
    def run(self, VirtualAddress, Length, SecondaryBuffer, ChargeQuota, Irp):
        mdl_addr = next_base_addr()
        mdl_data = claripy.BVS('mdl_data', 8 * 0x40)
        self.state.memory.store(mdl_addr, mdl_data)
        # Track MDL provenance: which VirtualAddress created this MDL
        self.state.globals['mdl_provenance'] = \
            self.state.globals.get('mdl_provenance', ()) + (
                (mdl_addr, VirtualAddress, 'IoAllocateMdl'),
            )
        return mdl_addr

class HookMmBuildMdlForNonPagedPool(angr.SimProcedure):
    """VOID MmBuildMdlForNonPagedPool(PMDL MemoryDescriptorList)"""
    def run(self, MemoryDescriptorList):
        return  # void, MDL provenance carries through
```

### 8.3 Hook Registration in __main__

```python
# New RW primitive sink hooks
proj.hook_symbol('MmCopyMemory', HookMmCopyMemory(cc=mycc))
proj.hook_symbol('MmMapIoSpaceEx', HookMmMapIoSpaceEx(cc=mycc))
proj.hook_symbol('ZwWriteVirtualMemory', HookZwWriteVirtualMemory(cc=mycc))
proj.hook_symbol('ZwReadVirtualMemory', HookZwReadVirtualMemory(cc=mycc))
proj.hook_symbol('MmMapLockedPagesSpecifyCache',
                 HookMmMapLockedPagesSpecifyCache(cc=mycc))
proj.hook_symbol('MmMapLockedPages', HookMmMapLockedPages(cc=mycc))
proj.hook_symbol('MmGetPhysicalAddress', HookMmGetPhysicalAddress(cc=mycc))
proj.hook_symbol('HalTranslateBusAddress', HookHalTranslateBusAddress(cc=mycc))
proj.hook_symbol('READ_PORT_UCHAR', HookReadPortUChar(cc=mycc))
proj.hook_symbol('READ_PORT_USHORT', HookReadPortUShort(cc=mycc))
proj.hook_symbol('READ_PORT_ULONG', HookReadPortULong(cc=mycc))
proj.hook_symbol('WRITE_PORT_UCHAR', HookWritePort(cc=mycc))
proj.hook_symbol('WRITE_PORT_USHORT', HookWritePort(cc=mycc))
proj.hook_symbol('WRITE_PORT_ULONG', HookWritePort(cc=mycc))
proj.hook_symbol('ZwSetValueKey', HookZwSetValueKey(cc=mycc))
# MDL chain helpers
proj.hook_symbol('IoAllocateMdl', HookIoAllocateMdl(cc=mycc))
proj.hook_symbol('MmBuildMdlForNonPagedPool',
                 HookMmBuildMdlForNonPagedPool(cc=mycc))
```

Note: `proj.hook_symbol()` silently does nothing if the symbol is not imported by the driver. Safe to register all hooks unconditionally.

### 8.4 State Initialization

In `find_ioctls()`, add MDL provenance tracking alongside existing state.globals:
```python
state.globals['mdl_provenance'] = ()
```

## 9. Output Format

All new detections use the consistent format:

```
[+] Boom! RWPrimitive: <SinkName> - arbitrary <Read/Write/ReadWrite>
```

Examples:
```
[+] Boom! RWPrimitive: MmMapIoSpaceEx - arbitrary ReadWrite (PhysicalAddress=<BV64 ...>)
[+] Boom! RWPrimitive: MmCopyMemory - arbitrary Read (SourceAddress=<BV64 ...>)
[+] Boom! RWPrimitive: ZwReadVirtualMemory - arbitrary Read (BaseAddress=<BV64 ...>)
[+] Boom! RWPrimitive: ZwWriteVirtualMemory - arbitrary Write (BaseAddress=<BV64 ...>)
[+] Boom! RWPrimitive: MmMapLockedPages - arbitrary ReadWrite (MDL chain vulnerable)
[+] Boom! RWPrimitive: MmGetPhysicalAddress - physical address disclosure
[+] Boom! RWPrimitive: HalTranslateBusAddress - arbitrary bus address translation
[+] Boom! RWPrimitive: READ_PORT_ULONG - arbitrary Read (Port=<BV32 ...>)
[+] Boom! RWPrimitive: WRITE_PORT_UCHAR - arbitrary Write (Port=<BV32 ...>)
[+] Boom! RWPrimitive: ZwSetValueKey - arbitrary Write (registry, Data tainted=True, ValueName tainted=False)
```

## 10. Evaluation Script Impact

The evaluation script `evaluate_compute_bug_types.py` greps for `Boom!` markers. The new output format is grep-compatible. The script may need minor updates to parse the new sink names.

The existing format is:
- `[+] Boom! Here is the IOCTL: 0x...`
- `[+] Driver's MmMapIoSpace is potentially vulnerable!!`

The new format adds:
- `[+] Boom! RWPrimitive: <name> - arbitrary <type>`

Both patterns contain `Boom!` so existing grep-based detection will catch them. The evaluation scripts should be extended to extract the specific sink name (Task #7).

## 11. Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| State explosion from many more targets | Each target analyzed in a separate `find_ioctls()` call with independent state |
| Port I/O functions may be inlined (not imported) | Phase 1 only catches imported functions; Phase 2 would add instruction-level hooks |
| Some READ_PORT drivers read ports for legitimate config, not as a vulnerability | The taint check (`is_ioctl_tainted`) ensures only user-controlled port addresses trigger |
| MmCopyMemory has complex calling convention (LARGE_INTEGER as second arg) | On x64, LARGE_INTEGER fits in a register. On x86, it's passed as two DWORDs on stack. `guess_prototype` may not handle this correctly -- needs testing |
| False positives from symbolic but constrained args | `is_ioctl_tainted()` + `check_narrow_constraints()` reduce false positives |
| MDL chain not detected if IoAllocateMdl not imported | Falls back to checking MDL pointer taint directly |
| Many drivers import these APIs but use them safely | The taint check is the soundness guarantee; only truly user-controlled arguments trigger |
| Regression on existing 3 sinks | Existing code paths untouched; new sinks added separately after existing blocks |
| Eval script can't parse new sink names | Task #7 updates the regex to include new sink names |

## 12. Coordination with Handle Detection (Task #5)

The handle detection hooks (ZwClose, ZwOpenKey, etc.) are always registered. When a new RW sink is the target:
- Handle hooks fire normally during symbolic execution
- After reaching the sink, both the RW analysis AND handle leak checks run
- This gives us combined detection: "driver reaches MmCopyMemory with tainted args AND also leaks a ZwOpenKey handle on the same path"
