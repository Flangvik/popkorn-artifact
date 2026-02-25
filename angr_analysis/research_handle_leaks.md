# Handle Leak Research: Windows Kernel Handle-Creating APIs

## Overview

This document catalogs all Windows kernel APIs that create handles, relevant to
detecting handle leak and handle exposure vulnerabilities in IOCTL handler
contexts. A handle leak occurs when a kernel handle is opened during IOCTL
processing but never closed (via ZwClose) before IRP completion. A handle
exposure occurs when a kernel handle value is written back to the user-mode
output buffer, allowing the calling process to use or abuse that handle.

## Calling Convention

All Zw/Nt system service routines use NTAPI calling convention:
- **x86 (IA-32):** `__stdcall` (callee cleans stack, parameters pushed right-to-left)
- **x64 (AMD64):** Microsoft x64 calling convention (first 4 params in RCX, RDX, R8, R9; rest on stack)

In angr terms:
- x86: `SimCCStdcall`
- x64: `SimCCMicrosoftAMD64`

---

## Handle-Creating APIs

### 1. ZwCreateFile

| Property | Value |
|---|---|
| **Signature** | `NTSTATUS ZwCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)` |
| **Param Count** | 11 |
| **Output Handle Param** | `FileHandle` (index 0) |
| **Return Type** | NTSTATUS |
| **Header** | wdm.h |
| **Notes** | Creates or opens a file/device. Very common in drivers. AllocationSize (index 4), EaBuffer (index 9) are optional. |

### 2. ZwOpenFile

| Property | Value |
|---|---|
| **Signature** | `NTSTATUS ZwOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions)` |
| **Param Count** | 6 |
| **Output Handle Param** | `FileHandle` (index 0) |
| **Return Type** | NTSTATUS |
| **Header** | wdm.h |
| **Notes** | Opens an existing file. Simpler than ZwCreateFile. |

### 3. ZwOpenProcess

| Property | Value |
|---|---|
| **Signature** | `NTSTATUS ZwOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)` |
| **Param Count** | 4 |
| **Output Handle Param** | `ProcessHandle` (index 0) |
| **Return Type** | NTSTATUS |
| **Header** | ntddk.h |
| **Notes** | Already partially hooked in POPKORN. Opens handle to process. ClientId (index 3) is the key taint parameter -- if symbolic, attacker controls which process to open. |

### 4. ZwOpenThread

| Property | Value |
|---|---|
| **Signature** | `NTSTATUS ZwOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)` |
| **Param Count** | 4 |
| **Output Handle Param** | `ThreadHandle` (index 0) |
| **Return Type** | NTSTATUS |
| **Header** | ntddk.h |
| **Notes** | Same pattern as ZwOpenProcess but for threads. ClientId (index 3) identifies the target thread. |

### 5. ZwOpenSection

| Property | Value |
|---|---|
| **Signature** | `NTSTATUS ZwOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)` |
| **Param Count** | 3 |
| **Output Handle Param** | `SectionHandle` (index 0) |
| **Return Type** | NTSTATUS |
| **Header** | wdm.h |
| **Notes** | Already hooked in POPKORN (HookZwOpenSection). Opens a section object. ObjectName in ObjectAttributes is tracked for \Device\PhysicalMemory detection. |

### 6. ZwOpenKey

| Property | Value |
|---|---|
| **Signature** | `NTSTATUS ZwOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)` |
| **Param Count** | 3 |
| **Output Handle Param** | `KeyHandle` (index 0) |
| **Return Type** | NTSTATUS |
| **Header** | wdm.h |
| **Notes** | Opens a registry key. Commonly used in driver init but can appear in IOCTLs. |

### 7. ZwDuplicateObject

| Property | Value |
|---|---|
| **Signature** | `NTSTATUS ZwDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options)` |
| **Param Count** | 7 |
| **Output Handle Param** | `TargetHandle` (index 3) |
| **Return Type** | NTSTATUS |
| **Header** | ntifs.h |
| **Notes** | Duplicates a handle. TargetProcessHandle (index 2) and TargetHandle (index 3) are optional. If TargetProcessHandle is the current user-mode process, the duplicated handle is directly usable by usermode. Particularly dangerous: if SourceHandle is a powerful kernel handle, duplicating to user process gives escalation. |

### 8. ObOpenObjectByPointer

| Property | Value |
|---|---|
| **Signature** | `NTSTATUS ObOpenObjectByPointer(PVOID Object, ULONG HandleAttributes, PACCESS_STATE PassedAccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PHANDLE Handle)` |
| **Param Count** | 7 |
| **Output Handle Param** | `Handle` (index 6) |
| **Return Type** | NTSTATUS |
| **Header** | ntifs.h |
| **Notes** | Opens a handle from a kernel object pointer. If AccessMode (index 5) is UserMode, handle goes into user process handle table. PassedAccessState (index 2) and ObjectType (index 4) are optional. |

### 9. ObReferenceObjectByHandle

| Property | Value |
|---|---|
| **Signature** | `NTSTATUS ObReferenceObjectByHandle(HANDLE Handle, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PVOID *Object, POBJECT_HANDLE_INFORMATION HandleInformation)` |
| **Param Count** | 6 |
| **Output Handle Param** | N/A (outputs object pointer, not a handle) |
| **Return Type** | NTSTATUS |
| **Header** | wdm.h |
| **Notes** | Does NOT create a handle. Gets an object pointer from a handle. Included because a stub exists in POPKORN (HookObReferenceObjectByHandle). The Object output (index 4) is a pointer, not a handle. For handle leak tracking, this API is irrelevant but the stub should return 0 and write a symbolic pointer. |

### 10. NtCreateSection / ZwCreateSection

| Property | Value |
|---|---|
| **Signature** | `NTSTATUS ZwCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle)` |
| **Param Count** | 7 |
| **Output Handle Param** | `SectionHandle` (index 0) |
| **Return Type** | NTSTATUS |
| **Header** | ntifs.h |
| **Notes** | Creates a section object. ObjectAttributes (index 2), MaximumSize (index 3), FileHandle (index 6) are optional. |

### 11. ZwOpenEvent

| Property | Value |
|---|---|
| **Signature** | `NTSTATUS ZwOpenEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)` |
| **Param Count** | 3 |
| **Output Handle Param** | `EventHandle` (index 0) |
| **Return Type** | NTSTATUS |
| **Header** | wdm.h |
| **Notes** | Opens a named event object. |

### 12. ZwOpenMutant

| Property | Value |
|---|---|
| **Signature** | `NTSTATUS ZwOpenMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)` |
| **Param Count** | 3 |
| **Output Handle Param** | `MutantHandle` (index 0) |
| **Return Type** | NTSTATUS |
| **Header** | (undocumented in WDK; available via ntdll) |
| **Notes** | Opens a mutant (mutex) object. Same 3-param pattern as ZwOpenEvent/ZwOpenSection. |

### 13. ZwOpenSemaphore

| Property | Value |
|---|---|
| **Signature** | `NTSTATUS ZwOpenSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)` |
| **Param Count** | 3 |
| **Output Handle Param** | `SemaphoreHandle` (index 0) |
| **Return Type** | NTSTATUS |
| **Header** | (undocumented in WDK; available via ntdll) |
| **Notes** | Opens a semaphore object. Same 3-param pattern. |

### 14. ZwOpenSymbolicLinkObject

| Property | Value |
|---|---|
| **Signature** | `NTSTATUS ZwOpenSymbolicLinkObject(PHANDLE LinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)` |
| **Param Count** | 3 |
| **Output Handle Param** | `LinkHandle` (index 0) |
| **Return Type** | NTSTATUS |
| **Header** | wdm.h |
| **Notes** | Opens a symbolic link object. |

### 15. ZwOpenTimer

| Property | Value |
|---|---|
| **Signature** | `NTSTATUS ZwOpenTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)` |
| **Param Count** | 3 |
| **Output Handle Param** | `TimerHandle` (index 0) |
| **Return Type** | NTSTATUS |
| **Header** | (undocumented in WDK; available via ntdll) |
| **Notes** | Opens a timer object. Same 3-param pattern. |

---

## ZwClose / NtClose

| Property | Value |
|---|---|
| **Signature** | `NTSTATUS ZwClose(HANDLE Handle)` |
| **Param Count** | 1 |
| **Return Type** | NTSTATUS |
| **Header** | wdm.h |
| **Notes** | Closes any object handle. The hook must remove the handle from the tracked `open_handles` set. |

---

## Summary Table: Quick Reference

| API Name | ParamCount | HandleOutIndex | Pattern |
|---|---|---|---|
| ZwCreateFile | 11 | 0 | `(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ...)` |
| ZwOpenFile | 6 | 0 | `(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ...)` |
| ZwOpenProcess | 4 | 0 | `(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID)` |
| ZwOpenThread | 4 | 0 | `(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID)` |
| ZwOpenSection | 3 | 0 | `(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)` |
| ZwOpenKey | 3 | 0 | `(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)` |
| ZwDuplicateObject | 7 | 3 | `(HANDLE, HANDLE, HANDLE, PHANDLE, ...)` |
| ObOpenObjectByPointer | 7 | 6 | `(PVOID, ULONG, PACCESS_STATE, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, PHANDLE)` |
| ZwCreateSection | 7 | 0 | `(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ...)` |
| ZwOpenEvent | 3 | 0 | `(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)` |
| ZwOpenMutant | 3 | 0 | `(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)` |
| ZwOpenSemaphore | 3 | 0 | `(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)` |
| ZwOpenSymbolicLinkObject | 3 | 0 | `(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)` |
| ZwOpenTimer | 3 | 0 | `(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)` |
| ZwClose | 1 | N/A | `(HANDLE)` -- closes handle |

---

## Vulnerability Definitions

### Handle Leak

A **handle leak** occurs when:
1. A handle-creating API is called during IOCTL dispatch processing
2. The call succeeds (returns STATUS_SUCCESS / NTSTATUS == 0)
3. The handle is NOT closed via ZwClose before the IRP completion routine returns

**Detection:** At the IOCTL handler return point (IRP completion), check if
`open_handles` (the set of symbolically-tracked handles created during this
execution path) is non-empty. Any handle remaining in the set was leaked.

**Impact:** Leaked kernel handles consume kernel resources. In the worst case,
repeated IOCTL calls can exhaust the kernel handle table (denial of service).
Leaked handles to sensitive objects (processes, threads, sections) can persist
across IOCTL calls if the handle table is per-process (for user-mode handles).

### Handle Exposure

A **handle exposure** occurs when:
1. A handle-creating API stores a handle value at a symbolic location
2. That handle value is subsequently written to the IRP output buffer
   (`IRP->AssociatedIrp.SystemBuffer` for METHOD_BUFFERED or
   `IRP->UserBuffer` for METHOD_NEITHER)
3. The user-mode caller can then read the handle value from the output buffer

**Detection:** After symbolic execution reaches the IRP completion, check if
any handle symbolic variable appears in constraints or memory stores that
target the output buffer region. Specifically: if the handle BVS (created by
the SimProcedure hook) appears in the data written to `SystemBuffer` or
`UserBuffer`, it has been exposed to user mode.

**Impact:** Exposed kernel handles (especially process/thread handles with full
access rights) allow user-mode code to perform privileged operations. For
example, a handle to the System process (PID 4) with PROCESS_ALL_ACCESS allows
arbitrary code injection into the kernel's address space.

---

## Implementation Notes for angr Hooks

### General Pattern for Handle-Creating Hooks

All handle-creating API hooks should follow this pattern:

```python
class HookZwOpenXxx(angr.SimProcedure):
    def run(self, HandleOut, ...other_params...):
        # Create a symbolic handle
        new_handle = claripy.BVS('handle_ZwOpenXxx', self.state.arch.bits)

        # Write handle to output pointer
        self.state.memory.store(HandleOut, new_handle,
                                endness=self.state.arch.memory_endness)

        # Track in open_handles set
        api_name = 'ZwOpenXxx'
        self.state.globals['open_handles'] = \
            self.state.globals.get('open_handles', ()) + ((new_handle, api_name),)

        return 0  # STATUS_SUCCESS
```

### ZwClose Hook

```python
class HookZwClose(angr.SimProcedure):
    def run(self, Handle):
        # Remove handle from tracking set
        current_handles = self.state.globals.get('open_handles', ())
        self.state.globals['open_handles'] = tuple(
            (h, name) for h, name in current_handles
            if not self.state.solver.is_true(h == Handle)
        )
        return 0
```

### Prioritization for Implementation

**High priority** (commonly seen in vulnerable drivers):
1. ZwOpenProcess (already a sink)
2. ZwOpenSection (already hooked)
3. ZwCreateFile / ZwOpenFile
4. ZwDuplicateObject
5. ObOpenObjectByPointer

**Medium priority** (less common but possible):
6. ZwOpenThread
7. ZwCreateSection
8. ZwOpenKey

**Low priority** (rare in IOCTL handlers):
9. ZwOpenEvent
10. ZwOpenMutant
11. ZwOpenSemaphore
12. ZwOpenSymbolicLinkObject
13. ZwOpenTimer

### Handle Type Classification for Severity

| Handle Target | Severity | Reason |
|---|---|---|
| Process (ZwOpenProcess) | Critical | Process handle enables code injection, token theft |
| Thread (ZwOpenThread) | Critical | Thread handle enables APC injection, context manipulation |
| Section (\Device\PhysicalMemory) | Critical | Physical memory access enables arbitrary R/W |
| File/Device (ZwCreateFile) | High | Can access sensitive files or device objects |
| Section (other) | High | Shared memory access can enable data manipulation |
| Registry Key (ZwOpenKey) | Medium | Registry manipulation, persistence |
| Duplicated Object | Varies | Depends on source handle type |
| Event/Mutex/Semaphore/Timer | Low | DoS potential through synchronization abuse |
| Symbolic Link | Low | Minimal direct exploitation value |

---

## References

- [ZwCreateFile - MSDN](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatefile)
- [ZwOpenFile - MSDN](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenfile)
- [ZwOpenProcess - MSDN](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-zwopenprocess)
- [ZwOpenKey - MSDN](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenkey)
- [ZwDuplicateObject - MSDN](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwduplicateobject)
- [ObOpenObjectByPointer - MSDN](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-obopenobjectbypointer)
- [ZwCreateSection - MSDN](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatesection)
- [ZwOpenEvent - MSDN](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenevent)
- [ZwOpenSymbolicLinkObject - MSDN](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopensymboliclinkobject)
- [ZwClose - MSDN](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwclose)
- [NtOpenMutant - NtDoc](https://ntdoc.m417z.com/ntopenmutant)
- [NtOpenSemaphore - NtDoc](https://ntdoc.m417z.com/ntopensemaphore)
- [NtOpenTimer - NtDoc](https://ntdoc.m417z.com/ntopentimer)
- [NtOpenThread - NtDoc](https://ntdoc.m417z.com/ntopenthread)
