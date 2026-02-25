# Extended RW Primitive Research: Sink APIs Beyond Current POPKORN Detections

## Overview

This document catalogs Windows kernel APIs beyond the three currently detected
by POPKORN (MmMapIoSpace, ZwMapViewOfSection, ZwOpenProcess) that enable
read-write primitives when parameters are user-controlled via IOCTL input
buffers. Each API includes its exact signature, vulnerable parameters,
vulnerability classification, and detection strategy for symbolic execution.

## Current POPKORN Sinks (for context)

| Sink | Detection | What It Checks |
|---|---|---|
| MmMapIoSpace | PhysicalAddress symbolic | ArbitraryReadWrite via physical memory mapping |
| ZwMapViewOfSection | SectionHandle -> \Device\PhysicalMemory | ArbitraryReadWrite via section mapping |
| ZwOpenProcess | ClientId symbolic | ProcessHandle (handle leak / process access) |

---

## New Sink APIs

### 1. MmMapIoSpaceEx

| Property | Value |
|---|---|
| **Signature** | `PVOID MmMapIoSpaceEx(PHYSICAL_ADDRESS PhysicalAddress, SIZE_T NumberOfBytes, ULONG Protect)` |
| **Header** | wdm.h |
| **Return Type** | PVOID (mapped virtual address, or NULL on failure) |
| **Available Since** | Windows 10 |
| **Param Count** | 3 |

**Parameters (0-indexed):**

| Index | Name | Type | Direction |
|---|---|---|---|
| 0 | PhysicalAddress | PHYSICAL_ADDRESS (LARGE_INTEGER) | in |
| 1 | NumberOfBytes | SIZE_T | in |
| 2 | Protect | ULONG | in |

**Vulnerability Analysis:**

| Vulnerable Param | Condition | Vuln Type |
|---|---|---|
| PhysicalAddress (0) | Symbolic (tainted by ioctl_inbuf) | ArbitraryReadWrite |
| NumberOfBytes (1) | Symbolic (tainted) | ArbitraryReadWrite (controls mapping size) |

**Detection Strategy:**
Identical to MmMapIoSpace. Check if `PhysicalAddress` argument is symbolic. If so,
user controls which physical address gets mapped to a virtual address the driver
can read/write, which effectively provides arbitrary physical memory access.

**Notes:** MmMapIoSpaceEx is the recommended replacement for MmMapIoSpace (which is
deprecated for new code). The Protect parameter adds page protection flags
(PAGE_READWRITE, PAGE_READONLY, PAGE_EXECUTE_READWRITE) but does not change the
fundamental vulnerability if the address is user-controlled.

---

### 2. MmCopyMemory

| Property | Value |
|---|---|
| **Signature** | `NTSTATUS MmCopyMemory(PVOID TargetAddress, MM_COPY_ADDRESS SourceAddress, SIZE_T NumberOfBytes, ULONG Flags, PSIZE_T NumberOfBytesTransferred)` |
| **Header** | ntddk.h |
| **Return Type** | NTSTATUS |
| **Available Since** | Windows 8.1 |
| **Param Count** | 5 |

**Parameters (0-indexed):**

| Index | Name | Type | Direction |
|---|---|---|---|
| 0 | TargetAddress | PVOID | in (destination buffer, must be nonpageable) |
| 1 | SourceAddress | MM_COPY_ADDRESS (union: VirtualAddress or PhysicalAddress) | in |
| 2 | NumberOfBytes | SIZE_T | in |
| 3 | Flags | ULONG (MM_COPY_MEMORY_PHYSICAL=0x1 or MM_COPY_MEMORY_VIRTUAL=0x2) | in |
| 4 | NumberOfBytesTransferred | PSIZE_T | out |

**MM_COPY_ADDRESS structure:**
```c
typedef union _MM_COPY_ADDRESS {
    PVOID            VirtualAddress;
    PHYSICAL_ADDRESS PhysicalAddress;
} MM_COPY_ADDRESS;
```

**Vulnerability Analysis:**

| Vulnerable Param | Condition | Vuln Type |
|---|---|---|
| SourceAddress (1) | Symbolic + Flags=MM_COPY_MEMORY_PHYSICAL | ArbitraryRead (reads arbitrary physical memory) |
| SourceAddress (1) | Symbolic + Flags=MM_COPY_MEMORY_VIRTUAL | ArbitraryRead (reads arbitrary virtual memory) |
| TargetAddress (0) | Symbolic (points to user buffer) | ArbitraryWrite (if source is kernel data) |
| NumberOfBytes (2) | Symbolic | Amplifies read/write range |

**Detection Strategy:**
1. Check if `SourceAddress` (param 1) is symbolic. If so, attacker controls the read address.
2. Check `Flags` (param 3): if MM_COPY_MEMORY_PHYSICAL (0x1), it reads physical memory.
3. If `TargetAddress` (param 0) points to a user-accessible buffer (e.g., SystemBuffer)
   AND `SourceAddress` is symbolic, this is a classic arbitrary read primitive.
4. Combined: if both SourceAddress and TargetAddress are influenced by ioctl_inbuf, classify
   as ArbitraryRead.

**Notes:** MmCopyMemory is designed to safely copy memory without causing bugchecks on
invalid addresses (unlike direct pointer dereference). This makes it attractive for
drivers that need to access physical memory, but also makes it a powerful arbitrary
read primitive if parameters are user-controlled.

---

### 3. ZwReadVirtualMemory (NtReadVirtualMemory)

| Property | Value |
|---|---|
| **Signature** | `NTSTATUS ZwReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead)` |
| **Header** | Undocumented (not in WDK headers; exported by ntoskrnl) |
| **Return Type** | NTSTATUS |
| **Param Count** | 5 |

**Parameters (0-indexed):**

| Index | Name | Type | Direction |
|---|---|---|---|
| 0 | ProcessHandle | HANDLE | in |
| 1 | BaseAddress | PVOID | in (address in target process to read from) |
| 2 | Buffer | PVOID | in (destination buffer) |
| 3 | NumberOfBytesToRead | SIZE_T | in |
| 4 | NumberOfBytesRead | PSIZE_T | out (optional) |

**Vulnerability Analysis:**

| Vulnerable Param | Condition | Vuln Type |
|---|---|---|
| BaseAddress (1) | Symbolic | ArbitraryRead |
| ProcessHandle (0) | Points to System process or -1 (NtCurrentProcess) | Escalation: reads from privileged process |
| NumberOfBytesToRead (3) | Symbolic | Controls amount of data exfiltrated |

**Detection Strategy:**
Check if `BaseAddress` (param 1) is symbolic and tainted by ioctl_inbuf. If the
ProcessHandle is the current process or a powerful process handle obtained earlier
(e.g., via ZwOpenProcess), the attacker can read arbitrary memory from that process.

---

### 4. ZwWriteVirtualMemory (NtWriteVirtualMemory)

| Property | Value |
|---|---|
| **Signature** | `NTSTATUS ZwWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten)` |
| **Header** | Undocumented (not in WDK headers; exported by ntoskrnl) |
| **Return Type** | NTSTATUS |
| **Param Count** | 5 |

**Parameters (0-indexed):**

| Index | Name | Type | Direction |
|---|---|---|---|
| 0 | ProcessHandle | HANDLE | in |
| 1 | BaseAddress | PVOID | in (address in target process to write to) |
| 2 | Buffer | PVOID | in (source data buffer) |
| 3 | NumberOfBytesToWrite | SIZE_T | in |
| 4 | NumberOfBytesWritten | PSIZE_T | out (optional) |

**Vulnerability Analysis:**

| Vulnerable Param | Condition | Vuln Type |
|---|---|---|
| BaseAddress (1) | Symbolic | ArbitraryWrite |
| Buffer (2) | Symbolic (attacker controls write data) | ArbitraryWrite |
| ProcessHandle (0) | Powerful process handle | Escalation |

**Detection Strategy:**
Check if `BaseAddress` (param 1) is symbolic. If so, attacker controls the write
destination. If both BaseAddress and Buffer are symbolic, it is a full arbitrary
write (attacker controls where and what is written).

---

### 5. MmMapLockedPages

| Property | Value |
|---|---|
| **Signature** | `PVOID MmMapLockedPages(PMDL MemoryDescriptorList, KPROCESSOR_MODE AccessMode)` |
| **Header** | wdm.h |
| **Return Type** | PVOID (mapped virtual address) |
| **Param Count** | 2 |

**Parameters (0-indexed):**

| Index | Name | Type | Direction |
|---|---|---|---|
| 0 | MemoryDescriptorList | PMDL | in |
| 1 | AccessMode | KPROCESSOR_MODE | in (KernelMode=0 or UserMode=1) |

**Vulnerability Analysis:**

| Vulnerable Param | Condition | Vuln Type |
|---|---|---|
| MemoryDescriptorList (0) | MDL constructed from user-controlled address | ArbitraryReadWrite |
| AccessMode (1) | UserMode = maps into user space | ArbitraryReadWrite from usermode |

**Detection Strategy:**
This API is part of the MDL chain (see "MDL Chain Detection" below). If the MDL
was built using `IoAllocateMdl` with a user-controlled `VirtualAddress` parameter,
and then `MmBuildMdlForNonPagedPool` or `MmProbeAndLockPages` was called on it,
mapping it makes that memory accessible. If AccessMode=UserMode, the mapping goes
directly to user space.

**Notes:** MmMapLockedPages is deprecated in favor of MmMapLockedPagesSpecifyCache
but still widely used in older drivers. Bugchecks on failure (no NULL return).

---

### 6. MmMapLockedPagesSpecifyCache

| Property | Value |
|---|---|
| **Signature** | `PVOID MmMapLockedPagesSpecifyCache(PMDL MemoryDescriptorList, KPROCESSOR_MODE AccessMode, MEMORY_CACHING_TYPE CacheType, PVOID RequestedAddress, ULONG BugCheckOnFailure, ULONG Priority)` |
| **Header** | wdm.h |
| **Return Type** | PVOID (mapped virtual address, or NULL) |
| **Param Count** | 6 |

**Parameters (0-indexed):**

| Index | Name | Type | Direction |
|---|---|---|---|
| 0 | MemoryDescriptorList | PMDL | in |
| 1 | AccessMode | KPROCESSOR_MODE | in |
| 2 | CacheType | MEMORY_CACHING_TYPE | in |
| 3 | RequestedAddress | PVOID | in (optional, for UserMode mapping target) |
| 4 | BugCheckOnFailure | ULONG | in (should be FALSE for drivers) |
| 5 | Priority | ULONG (MM_PAGE_PRIORITY) | in |

**Vulnerability Analysis:**
Same as MmMapLockedPages. The key is the MDL origin. If the MDL was constructed
from a user-controlled address, the resulting mapping provides arbitrary R/W.

| Vulnerable Param | Condition | Vuln Type |
|---|---|---|
| MemoryDescriptorList (0) | MDL from user-controlled IoAllocateMdl | ArbitraryReadWrite |
| AccessMode (1) | UserMode = user-space mapping | ArbitraryReadWrite |
| RequestedAddress (3) | If symbolic, influences mapping location | ArbitraryReadWrite |

**Detection Strategy:** Same as MmMapLockedPages. Track MDL provenance.

---

### 7. IoAllocateMdl (chain component)

| Property | Value |
|---|---|
| **Signature** | `PMDL IoAllocateMdl(PVOID VirtualAddress, ULONG Length, BOOLEAN SecondaryBuffer, BOOLEAN ChargeQuota, PIRP Irp)` |
| **Header** | wdm.h |
| **Return Type** | PMDL |
| **Param Count** | 5 |

**Parameters (0-indexed):**

| Index | Name | Type | Direction |
|---|---|---|---|
| 0 | VirtualAddress | PVOID | in (base virtual address for MDL) |
| 1 | Length | ULONG | in (size of buffer) |
| 2 | SecondaryBuffer | BOOLEAN | in |
| 3 | ChargeQuota | BOOLEAN | in |
| 4 | Irp | PIRP | in/out (optional) |

**Vulnerability Analysis:**

| Vulnerable Param | Condition | Vuln Type |
|---|---|---|
| VirtualAddress (0) | Symbolic (tainted by ioctl_inbuf) | Chain: enables ArbitraryReadWrite when followed by MmBuildMdlForNonPagedPool + MmMapLockedPages |
| Length (1) | Symbolic | Controls size of memory region described |

**Detection Strategy:**
Track whether VirtualAddress (param 0) is symbolic. If it is, tag the returned
MDL pointer as "tainted_mdl" in state.globals. When subsequent calls to
MmBuildMdlForNonPagedPool or MmProbeAndLockPages use this MDL, propagate the taint.
When MmMapLockedPages[SpecifyCache] is called with a tainted MDL, flag as vulnerable.

---

### 8. MmBuildMdlForNonPagedPool (chain component)

| Property | Value |
|---|---|
| **Signature** | `VOID MmBuildMdlForNonPagedPool(PMDL MemoryDescriptorList)` |
| **Header** | wdm.h |
| **Return Type** | VOID |
| **Param Count** | 1 |

**Parameters (0-indexed):**

| Index | Name | Type | Direction |
|---|---|---|---|
| 0 | MemoryDescriptorList | PMDL | in/out |

**Vulnerability Analysis:**
Not directly vulnerable. Part of the MDL chain. Updates the MDL to describe the
physical pages backing the nonpaged pool allocation. If the original
IoAllocateMdl address was user-controlled, this step fills in the PFN array for
that address, enabling the mapping step to provide access to arbitrary kernel memory.

**Detection Strategy:** Propagate taint: if the MDL was tagged as tainted_mdl from
IoAllocateMdl, keep it tainted through this call.

---

### 9. MmProbeAndLockPages (chain component)

| Property | Value |
|---|---|
| **Signature** | `VOID MmProbeAndLockPages(PMDL MemoryDescriptorList, KPROCESSOR_MODE AccessMode, LOCK_OPERATION Operation)` |
| **Header** | wdm.h |
| **Return Type** | VOID |
| **Param Count** | 3 |

**Parameters (0-indexed):**

| Index | Name | Type | Direction |
|---|---|---|---|
| 0 | MemoryDescriptorList | PMDL | in/out |
| 1 | AccessMode | KPROCESSOR_MODE | in |
| 2 | Operation | LOCK_OPERATION | in (IoReadAccess, IoWriteAccess, IoModifyAccess) |

**Vulnerability Analysis:**
Part of the MDL chain. Probes, makes resident, and locks the virtual memory
pages described by the MDL. If the MDL describes a user-controlled address
range, locking those pages gives the kernel stable access to that memory.

| Vulnerable Param | Condition | Vuln Type |
|---|---|---|
| MemoryDescriptorList (0) | Tainted MDL from IoAllocateMdl | Chain component |
| Operation (2) | IoWriteAccess / IoModifyAccess | Enables write access |

**Detection Strategy:** Same as MmBuildMdlForNonPagedPool -- propagate MDL taint.

---

### 10. MmGetPhysicalAddress

| Property | Value |
|---|---|
| **Signature** | `PHYSICAL_ADDRESS MmGetPhysicalAddress(PVOID BaseAddress)` |
| **Header** | ntddk.h |
| **Return Type** | PHYSICAL_ADDRESS (LARGE_INTEGER) -- returned by value |
| **Param Count** | 1 |

**Parameters (0-indexed):**

| Index | Name | Type | Direction |
|---|---|---|---|
| 0 | BaseAddress | PVOID | in |

**Vulnerability Analysis:**

| Vulnerable Param | Condition | Vuln Type |
|---|---|---|
| BaseAddress (0) | Symbolic + return value written to output buffer | AddressDisclosure |

**Detection Strategy:**
1. Check if `BaseAddress` (param 0) is symbolic.
2. Check if the return value (PHYSICAL_ADDRESS) is written to the IOCTL output
   buffer (SystemBuffer or UserBuffer). If so, the driver is leaking the physical
   address corresponding to a user-controlled virtual address.
3. This is an AddressDisclosure vulnerability, not a direct R/W, but it enables
   further exploitation: knowing the physical address allows mapping via
   MmMapIoSpace or \Device\PhysicalMemory.

**Notes:** The return is a 64-bit value (PHYSICAL_ADDRESS). On x86, it is returned
in EDX:EAX. On x64, it is returned in RAX.

---

### 11. HalTranslateBusAddress

| Property | Value |
|---|---|
| **Signature** | `BOOLEAN HalTranslateBusAddress(INTERFACE_TYPE InterfaceType, ULONG BusNumber, PHYSICAL_ADDRESS BusAddress, PULONG AddressSpace, PPHYSICAL_ADDRESS TranslatedAddress)` |
| **Header** | hal.h (deprecated; use IoTranslateBusAddress or bus-specific APIs) |
| **Return Type** | BOOLEAN |
| **Param Count** | 5 |

**Parameters (0-indexed):**

| Index | Name | Type | Direction |
|---|---|---|---|
| 0 | InterfaceType | INTERFACE_TYPE (enum) | in |
| 1 | BusNumber | ULONG | in |
| 2 | BusAddress | PHYSICAL_ADDRESS | in |
| 3 | AddressSpace | PULONG | in/out (0=memory, 1=I/O) |
| 4 | TranslatedAddress | PPHYSICAL_ADDRESS | out |

**Vulnerability Analysis:**

| Vulnerable Param | Condition | Vuln Type |
|---|---|---|
| BusAddress (2) | Symbolic (tainted by ioctl_inbuf) | AddressDisclosure / enables ArbitraryReadWrite |
| TranslatedAddress (4) | Output used by subsequent MmMapIoSpace | Chain: physical address for mapping |

**Detection Strategy:**
Check if `BusAddress` (param 2) is symbolic. If the `TranslatedAddress` output
is subsequently passed to MmMapIoSpace/MmMapIoSpaceEx, flag the chain as
vulnerable. The translation step itself is an enabler, not the final primitive.

**Notes:** Deprecated API. Rarely seen in modern drivers but may exist in legacy code.

---

### 12. MmAllocateContiguousMemory

| Property | Value |
|---|---|
| **Signature** | `PVOID MmAllocateContiguousMemory(SIZE_T NumberOfBytes, PHYSICAL_ADDRESS HighestAcceptableAddress)` |
| **Header** | wdm.h |
| **Return Type** | PVOID (virtual address of allocated memory, or NULL) |
| **Param Count** | 2 |

**Parameters (0-indexed):**

| Index | Name | Type | Direction |
|---|---|---|---|
| 0 | NumberOfBytes | SIZE_T | in |
| 1 | HighestAcceptableAddress | PHYSICAL_ADDRESS | in |

**Vulnerability Analysis:**

| Vulnerable Param | Condition | Vuln Type |
|---|---|---|
| NumberOfBytes (0) | Symbolic (tainted by ioctl_inbuf) | Resource exhaustion / DoS |
| HighestAcceptableAddress (1) | Symbolic | Low severity: controls allocation constraint |

**Detection Strategy:**
Check if `NumberOfBytes` (param 0) is symbolic. A user-controlled allocation size
can lead to resource exhaustion. This is typically a DoS vulnerability, not an
arbitrary R/W. Lower priority than other sinks.

**Notes:** The allocated memory is nonpaged and physically contiguous. Primarily used
for DMA buffers. Not a direct R/W primitive but can be part of chains.

---

## MDL Chain Detection

The MDL chain is a multi-step pattern commonly found in vulnerable drivers:

```
IoAllocateMdl(user_controlled_addr, user_controlled_size, ...)
    -> returns PMDL
MmBuildMdlForNonPagedPool(mdl)   OR   MmProbeAndLockPages(mdl, ...)
    -> MDL now describes locked physical pages
MmMapLockedPages(mdl, UserMode)  OR  MmMapLockedPagesSpecifyCache(mdl, UserMode, ...)
    -> returns virtual address mapping the physical pages
```

**Detection Strategy (taint propagation):**

1. **Hook IoAllocateMdl:** If `VirtualAddress` (param 0) or `Length` (param 1) is
   symbolic, tag the returned MDL pointer as tainted in `state.globals['tainted_mdls']`.

2. **Hook MmBuildMdlForNonPagedPool:** If `MemoryDescriptorList` (param 0) is in the
   tainted MDL set, keep it tainted (no-op for taint).

3. **Hook MmProbeAndLockPages:** Same as above. Propagate MDL taint.

4. **Hook MmMapLockedPages / MmMapLockedPagesSpecifyCache:** If
   `MemoryDescriptorList` (param 0) is in the tainted MDL set, flag as
   **ArbitraryReadWrite** vulnerability. If `AccessMode` is UserMode, severity is
   higher because the mapping is directly accessible from user space.

---

## Summary: All New Sinks

| API | Vuln Type | Key Symbolic Param | Priority | Standalone / Chain |
|---|---|---|---|---|
| MmMapIoSpaceEx | ArbitraryReadWrite | PhysicalAddress (0) | High | Standalone |
| MmCopyMemory | ArbitraryRead | SourceAddress (1) | High | Standalone |
| ZwReadVirtualMemory | ArbitraryRead | BaseAddress (1) | High | Standalone |
| ZwWriteVirtualMemory | ArbitraryWrite | BaseAddress (1) | High | Standalone |
| MmMapLockedPages | ArbitraryReadWrite | MDL (0) - tainted | High | Chain (MDL) |
| MmMapLockedPagesSpecifyCache | ArbitraryReadWrite | MDL (0) - tainted | High | Chain (MDL) |
| MmGetPhysicalAddress | AddressDisclosure | BaseAddress (0) | Medium | Standalone |
| HalTranslateBusAddress | AddressDisclosure | BusAddress (2) | Low | Chain enabler |
| MmAllocateContiguousMemory | DoS | NumberOfBytes (0) | Low | Standalone |
| IoAllocateMdl | Chain component | VirtualAddress (0) | High (in chain) | Chain start |
| MmBuildMdlForNonPagedPool | Chain component | MDL (0) | High (in chain) | Chain middle |
| MmProbeAndLockPages | Chain component | MDL (0) | High (in chain) | Chain middle |

---

## Implementation Priority Recommendation

### Phase 1: Standalone sinks (highest impact, easiest to implement)

1. **MmMapIoSpaceEx** -- Trivial extension of existing MmMapIoSpace detection.
   Same analysis logic, just hook the additional symbol name.

2. **MmCopyMemory** -- New standalone sink. Check SourceAddress symbolic + Flags.

3. **ZwReadVirtualMemory** -- New standalone sink. Check BaseAddress symbolic.

4. **ZwWriteVirtualMemory** -- New standalone sink. Check BaseAddress symbolic.

### Phase 2: MDL chain detection (medium complexity)

5. **IoAllocateMdl + MmBuildMdlForNonPagedPool + MmMapLockedPages[SpecifyCache]**
   Requires taint propagation through state.globals for MDL tracking.

### Phase 3: Information disclosure and secondary sinks (lower priority)

6. **MmGetPhysicalAddress** -- Check if return value flows to output buffer.

7. **HalTranslateBusAddress** -- Legacy, low prevalence.

8. **MmAllocateContiguousMemory** -- DoS class, low severity.

---

## angr Hook Pseudocode for Key New Sinks

### MmMapIoSpaceEx

```python
class HookMmMapIoSpaceEx(angr.SimProcedure):
    def run(self, PhysicalAddress, NumberOfBytes, Protect):
        # Same analysis as MmMapIoSpace
        if PhysicalAddress.symbolic:
            log_vulnerability("MmMapIoSpaceEx", "ArbitraryReadWrite",
                            f"PhysicalAddress is symbolic: {PhysicalAddress}")
        addr = next_base_addr()
        return addr
```

### MmCopyMemory

```python
class HookMmCopyMemory(angr.SimProcedure):
    def run(self, TargetAddress, SourceAddress, NumberOfBytes, Flags, NumberOfBytesTransferred):
        if SourceAddress.symbolic:
            log_vulnerability("MmCopyMemory", "ArbitraryRead",
                            f"SourceAddress is symbolic: {SourceAddress}")
        # Write NumberOfBytes to NumberOfBytesTransferred
        self.state.memory.store(NumberOfBytesTransferred, NumberOfBytes,
                                endness=self.state.arch.memory_endness)
        return 0  # STATUS_SUCCESS
```

### ZwReadVirtualMemory

```python
class HookZwReadVirtualMemory(angr.SimProcedure):
    def run(self, ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead):
        if BaseAddress.symbolic:
            log_vulnerability("ZwReadVirtualMemory", "ArbitraryRead",
                            f"BaseAddress is symbolic: {BaseAddress}")
        # Write symbolic data to Buffer to simulate read
        if NumberOfBytesRead.op != 'BVV' or self.state.solver.eval(NumberOfBytesRead) != 0:
            pass  # Optional: store read count
        return 0
```

### ZwWriteVirtualMemory

```python
class HookZwWriteVirtualMemory(angr.SimProcedure):
    def run(self, ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten):
        if BaseAddress.symbolic:
            log_vulnerability("ZwWriteVirtualMemory", "ArbitraryWrite",
                            f"BaseAddress is symbolic: {BaseAddress}")
        return 0
```

---

## References

- [MmMapIoSpaceEx - MSDN](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmmapiospaceex)
- [MmCopyMemory - MSDN](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-mmcopymemory)
- [NtReadVirtualMemory - NtDoc](https://ntdoc.m417z.com/ntreadvirtualmemory)
- [NtWriteVirtualMemory - NtDoc](https://ntdoc.m417z.com/ntwritevirtualmemory)
- [MmMapLockedPages - MSDN](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmmaplockedpages)
- [MmMapLockedPagesSpecifyCache - MSDN](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmmaplockedpagesspecifycache)
- [IoAllocateMdl - MSDN](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioallocatemdl)
- [MmBuildMdlForNonPagedPool - MSDN](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmbuildmdlfornonpagedpool)
- [MmProbeAndLockPages - MSDN](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmprobeandlockpages)
- [MmGetPhysicalAddress - MSDN](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-mmgetphysicaladdress)
- [MmAllocateContiguousMemory - MSDN](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmallocatecontiguousmemory)
- [MmMapIoSpace - MSDN](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmmapiospace)
- [MSRC: New Class of Kernel Exploit Primitive (2022)](https://msrc-blog.microsoft.com/2022/03/22/exploring-a-new-class-of-kernel-exploit-primitive/)
- [Theori: Windows Driver LPE - MDL chain exploitation](https://theori.io/blog/chaining-n-days-to-compromise-all-part-3-windows-driver-lpe-medium-to-system)
