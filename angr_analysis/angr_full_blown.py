"""POPKORN symbolic execution engine for Windows kernel driver vulnerability detection.

Analyzes a single WDM driver (.sys file) by:
1. Loading the PE binary with angr and identifying IoCreateDevice (WDM marker)
2. Running symbolic execution through DriverEntry to locate the IOCTL dispatch handler
3. Checking driver imports for vulnerable sink functions (original: MmMapIoSpace,
   ZwOpenProcess, ZwMapViewOfSection; extended: MmMapIoSpaceEx, MmCopyMemory,
   ZwRead/WriteVirtualMemory, READ/WRITE_PORT_*, ZwSetValueKey, MDL chain APIs;
   process-control: ZwTerminateProcess, ZwTerminateThread, ZwSuspendProcess,
   ZwSuspendThread, ZwAllocateVirtualMemory, ZwProtectVirtualMemory,
   ZwUnmapViewOfSection)
4. Hooking handle-creating APIs (ZwOpenSection, ZwCreateFile, ZwOpenProcess, etc.)
   and ZwClose to track kernel handle lifecycle for leak/exposure detection
5. For each sink, running constrained symbolic execution from the IOCTL handler to
   the sink address, checking if user-controlled IOCTL buffer data can reach it
6. Reporting vulnerabilities as '[+] Boom!' lines with category, sink name, and
   IOCTL code constraints

Vulnerability categories:
- ArbitraryPhysMap: MmMapIoSpace/MmMapIoSpaceEx with symbolic PhysicalAddress
- ProcessAccess: ZwOpenProcess with symbolic ClientId
- HandleLeak: handle-creating API called without matching ZwClose
- HandleExposure: handle value written to user-mode output buffer
- RWPrimitive: extended sink with symbolic critical parameter (address/port/data)
- ProcessControl: ZwTerminateProcess/ZwTerminateThread/ZwSuspendProcess/ZwSuspendThread
  with symbolic process/thread handle (EDR/AV killing and blinding)
- ProcessInjection: ZwAllocateVirtualMemory/ZwProtectVirtualMemory/ZwUnmapViewOfSection
  with symbolic process handle or address (cross-process code injection)

Usage: python angr_full_blown.py [-d] /path/to/driver.sys
"""
import logging
from os import major
from pathlib import Path

from angr.exploration_techniques.director import ExecuteAddressGoal
logging.getLogger("angr").setLevel(logging.CRITICAL)

import angr
import kernel_types
import archinfo
import claripy
import sys
import collections
import IPython
from threading import Event, Timer
import ipdb
import time
import argparse

from importlib import reload  # To avoid root logger being set by the environment
reload(logging)

MMMAPIOSPACE = False
ZWOPENPROCESS = False
ZWMAPVIEWOFSECTION = False

# Maps api_name -> rebased_addr for all detected extended RW sinks.
# Use `'ApiName' in RW_SINKS` to check presence, `RW_SINKS['ApiName']` for addr.
RW_SINKS = {}

# Maps api_name -> rebased_addr for process-control sinks (ProcessControl + ProcessInjection).
# Covers EDR/AV killing, process suspension, and cross-process memory manipulation.
PROCESS_CONTROL_SINKS = {}

# True if the driver imports any Kernel Streaming (KS) framework API.
# KS drivers use MDL chains for internal audio/video buffer management — not physical mapping.
# All MDL-based RWPrimitive Booms are suppressed for KS drivers.
KS_DRIVER = False

mem_string = ""
handler = None


def check_imports(proj):
    global MMMAPIOSPACE
    global ZWOPENPROCESS
    global ZWMAPVIEWOFSECTION
    global KS_DRIVER

    print("\nLooking for sink imports..\n")

    mmmap_addr = proj.loader.find_symbol("MmMapIoSpace")
    zwopenprocess = proj.loader.find_symbol("ZwOpenProcess")
    zwmapview = proj.loader.find_symbol("ZwMapViewOfSection")
    import_addr = {}

    if zwopenprocess:
        print("[+] Found ZwOpenProcess: ", hex(zwopenprocess.rebased_addr))
        ZWOPENPROCESS = True
        import_addr['ZwOpenProcess'] = zwopenprocess.rebased_addr
    else:
        print("ZwOpenProcess import not found!")

    if mmmap_addr:
        print("[+] Found MmapIoSpace: ", hex(mmmap_addr.rebased_addr))
        MMMAPIOSPACE = True
        import_addr['MmapIoSpace'] = mmmap_addr.rebased_addr
    else:
        print("MmMapIoSpace import not found!")

    if zwmapview:
        print("[+] Found ZwMapViewOfSection: ", hex(zwmapview.rebased_addr))
        ZWMAPVIEWOFSECTION = True
        import_addr['ZwMapViewOfSection'] = zwmapview.rebased_addr
    else:
        print("ZwMapViewOfSection import not found!")

    # New RW primitive sinks (includes Nt-prefixed variants of undocumented APIs)
    new_rw_sinks = [
        "MmMapIoSpaceEx",
        "MmCopyMemory",
        "ZwReadVirtualMemory",
        "NtReadVirtualMemory",
        "ZwWriteVirtualMemory",
        "NtWriteVirtualMemory",
        "READ_PORT_UCHAR",
        "READ_PORT_USHORT",
        "READ_PORT_ULONG",
        "WRITE_PORT_UCHAR",
        "WRITE_PORT_USHORT",
        "WRITE_PORT_ULONG",
        "ZwSetValueKey",
        "MmMapLockedPagesSpecifyCache",
        "MmMapLockedPages",
        "MmGetPhysicalAddress",
        "HalTranslateBusAddress",
    ]

    for api_name in new_rw_sinks:
        sym = proj.loader.find_symbol(api_name)
        if sym:
            print(f"[+] Found {api_name}: {hex(sym.rebased_addr)}")
            RW_SINKS[api_name] = sym.rebased_addr
            import_addr[api_name] = sym.rebased_addr

    # MDL chain helper APIs (not sinks, but needed for provenance hooks)
    for mdl_api in ['IoAllocateMdl', 'MmBuildMdlForNonPagedPool']:
        sym = proj.loader.find_symbol(mdl_api)
        if sym:
            print(f"[+] Found {mdl_api}: {hex(sym.rebased_addr)}")
            import_addr[mdl_api] = sym.rebased_addr

    # Process-control sink detection (ProcessControl + ProcessInjection)
    # These enable EDR/AV killing, process suspension, and cross-process code injection.
    process_control_apis = [
        "ZwTerminateProcess",       # Kill any process (TrueSightKiller pattern)
        "ZwTerminateThread",        # Kill individual threads
        "ZwSuspendProcess",         # Blind EDR by suspending all threads
        "ZwSuspendThread",          # Blind EDR by suspending individual threads
        "ZwAllocateVirtualMemory",  # Allocate memory in another process (code injection)
        "ZwProtectVirtualMemory",   # Change page protections cross-process (RWX shellcode)
        "ZwUnmapViewOfSection",     # Unmap sections from another process (remove EDR DLLs)
    ]
    for api_name in process_control_apis:
        sym = proj.loader.find_symbol(api_name)
        if sym:
            print(f"[+] Found {api_name}: {hex(sym.rebased_addr)}")
            PROCESS_CONTROL_SINKS[api_name] = sym.rebased_addr
            import_addr[api_name] = sym.rebased_addr

    # Handle-creating API detection (for handle leak analysis)
    handle_apis = ['ZwClose', 'ZwCreateSection', 'ZwOpenThread',
                   'ZwDuplicateObject', 'ObOpenObjectByPointer',
                   'ZwOpenKey', 'ZwCreateKey', 'ZwOpenFile', 'ZwCreateFile',
                   'ZwOpenEvent', 'ZwOpenMutant', 'ZwOpenSemaphore',
                   'ZwOpenSymbolicLinkObject', 'ZwOpenTimer']
    for api in handle_apis:
        sym = proj.loader.find_symbol(api)
        if sym:
            print(f"[+] Found {api}: {hex(sym.rebased_addr)}")
            import_addr[api] = sym.rebased_addr

    # KS framework detection: drivers that import from ks.sys or specific KS APIs use MDLs
    # for internal audio/video streaming buffer management — not arbitrary physical mapping.
    # Check DLL-level dependency first (catches jmcam.sys which imports KsGetPinFromIrp etc.)
    requested = [n.lower() for n in proj.loader.requested_names]
    if 'ks.sys' in requested:
        print("[!] KS framework driver detected (imports from ks.sys) — "
              "MDL-based Booms will be suppressed")
        KS_DRIVER = True
    else:
        ks_apis = ['KsCreateFilterFactory', 'KsSetMajorFunctionHandler',
                   'KsInitializeDriver', 'KsCreatePin', 'KsAddItemToObjectBag']
        for ks_api in ks_apis:
            if proj.loader.find_symbol(ks_api):
                print(f"[!] KS framework driver detected ({ks_api} imported) — "
                      "MDL-based Booms will be suppressed")
                KS_DRIVER = True
                break

    return import_addr


def find_driver_type(proj):
    iocreatedevice_addr = proj.loader.find_symbol("IoCreateDevice")
    driver_type = ""
    if iocreatedevice_addr:

        print("Found WDM driver: ", hex(iocreatedevice_addr.rebased_addr))
        #logging.info("Found WDM driver: %s", hex(iocreatedevice_addr.rebased_addr))
        driver_type = "wdm"
    else:
        print("Different driver type detected..")
        #logging.info("Different driver type detected..")

    return driver_type


def ioctl_handler_hook(state):
    global handler
    ioctl_handler_addr = state.solver.eval(state.inspect.mem_write_expr)
    state.globals['ioctl_handler'] = int(ioctl_handler_addr)
    handler = int(ioctl_handler_addr)


FIRST_ADDR = 0x444f0000


def next_base_addr(size=0x1000):
    global FIRST_ADDR
    v = FIRST_ADDR
    FIRST_ADDR += size
    return v


def read_concrete_utf16_string(state, addr):
    i = 0
    while True:
        assert i <= 0x1000
        val = state.memory.load(addr + i, 2, endness=state.arch.memory_endness)
        concrete = state.solver.eval_one(val)
        if concrete == 0:
            return state.memory.load(addr, i + 2)
        i += 2


def find_ioctl_handler(proj):
    global ioctl_handler
    global handler

    do_addr = next_base_addr()
    driver_object = claripy.BVS("driver_object", 8 * 0x100)
    rp_addr = next_base_addr()
    registry_path = claripy.BVS("registry_path", 8 * 0x100)

    # init_state = proj.factory.call_state(proj.entry, do_addr, rp_addr, cc=mycc, add_options=angr.options.unicorn)
    init_state = proj.factory.call_state(proj.entry, do_addr, rp_addr, cc=mycc)
    init_state.globals['open_section_handles'] = ()
    init_state.globals['open_handles'] = ()
    init_state.globals['driver_object_addr'] = do_addr

    init_state.memory.store(do_addr, driver_object)
    init_state.memory.store(rp_addr, registry_path)
    print("DriverObject @ {}".format(hex(do_addr)))
    #logging.info("DriverObject @ %s", hex(do_addr))

    #init_state.inspect.b('mem_write', when=angr.BP_AFTER, action=lambda s: print("MEM_WRITE @ {} to {}".format(s, s.inspect.mem_write_address)))
    init_state.inspect.b("mem_write", mem_write_address=do_addr + (0xe0 if proj.arch.name == archinfo.ArchAMD64.name else 0x70), when=angr.BP_AFTER, action=ioctl_handler_hook)

    print("\n[+] Finding the IOCTL Handler..\n\n")
    #logging.debug("[+] Finding the IOCTL Handler..\n")

    sm = proj.factory.simgr(init_state)

    dfs = angr.exploration_techniques.DFS()
    sm.use_technique(dfs)

    ed_ioctl = ExplosionDetector(threshold=100)
    sm.use_technique(ed_ioctl)

    def filter_func(s):
        if 'ioctl_handler' not in s.globals:
            return False
        retval = mycc.return_val(angr.types.BASIC_TYPES['long int']).get_value(s)
        return not s.solver.satisfiable(extra_constraints=[retval != 0])

    for i in range(0x100000):
        #while len(sm.active) > 0 and not ed_ioctl.state_exploded_bool:
        sm.step()
        sm.move(from_stash='deadended', to_stash='found', filter_func=filter_func)
        print(sm, {_s: _ss for _s, _ss in sm.stashes.items() if _ss})
        #sm.explore()
        if len(sm.found) or not len(sm.active):
            break
    else:
        print("DriverEntry hit limit of executions, could not locate")

    if sm.errored:
        # ipdb.set_trace()
        print('\n'.join(map(repr, proj.loader.all_objects)))
        for s in sm.errored:
            print(f"ERROR: {repr(s)}", file=sys.stderr)

    if not sm.found:
        # import ipdb; ipdb.set_trace()
        print(f"Could not find a successful DriverEntry run!!! {sm=}, {sm.stashes}")
        #logging.error("Could not find a successful DriverEntry run!!!")
        #ipdb.set_trace()
        #assert False

    success_state = sm.found[0]

    ioctl_handler = success_state.globals['ioctl_handler'] or handler
    print("[+] Found ioctl handler @ {:x}".format(ioctl_handler))
    #logging.critical("[+] Found ioctl handler @ %s", ioctl_handler)
    return ioctl_handler, success_state


def find_ioctls(proj: angr.Project, driver_base_state: angr.SimState, ioctl_handler_addr, target_addr):
    irp_addr = 0x1337000
    irsp_addr = 0x6000000
    ioctl_inbuf_addr = 0x7000000
    type3_input_buf_addr = 0x8000000

    if 'device_object_addr' in driver_base_state.globals:
        device_object_addr = claripy.BVV(driver_base_state.globals['device_object_addr'], driver_base_state.arch.bits)
    else:
        device_object_addr = claripy.BVS('device_object_ptr', driver_base_state.arch.bits)
    state: angr.SimState = proj.factory.call_state(ioctl_handler_addr, device_object_addr, irp_addr, cc=mycc,
                                    # base_state=driver_base_state, add_options=angr.options.unicorn)
                                    base_state=driver_base_state)
    state.globals['open_section_handles'] = tuple()
    state.globals['open_handles'] = ()
    state.globals['mdl_provenance'] = ()
    irp = claripy.BVS("irp_buf", 8 * 0x200)
    ioctl_inbuf = claripy.BVS("ioctl_inbuf", 8 * 0x200).reversed
    type3_input_buf = claripy.BVS('ioctl_type3_inbuf', 8 * 0x200)

    state.memory.store(irp_addr, irp)
    state.memory.store(ioctl_inbuf_addr, ioctl_inbuf)
    state.memory.store(type3_input_buf_addr, type3_input_buf)

    major_func, minor_func, output_buf_length, input_buf_length, ioctlcode = map(lambda x: claripy.BVS(*x), [
        ("MajorFunction", 8), ("MinorFunction", 8), ('OutputBufferLength', 32), ('InputBufferLength', 32),
        ('IoControlCode', 32)])

    state.add_constraints(major_func == 14)
    state.add_constraints(ioctlcode != 0)  # Exclude degenerate IOCTL=0 paths (solver artifact)

    state.globals['ioctlcode_bvs'] = ioctlcode  # Store for method-type checks in analysis functions

    state.mem[irp_addr].IRP.Tail.Overlay.s.u.CurrentStackLocation = irsp_addr
    state.mem[irp_addr].IRP.AssociatedIrp.SystemBuffer = ioctl_inbuf_addr
    state.mem[irp_addr].IRP.MdlAddress = 0  # Null out I/O manager MDL — prevents METHOD_OUT_DIRECT FPs

    state.mem[irsp_addr].IO_STACK_LOCATION.MajorFunction = major_func
    state.mem[irsp_addr].IO_STACK_LOCATION.MinorFunction = minor_func

    _params = state.mem[irsp_addr].IO_STACK_LOCATION.Parameters
    # Hack, here we need to use .val because we had to have the hacky POINTER_ALIGNED_ULONG to get the offsets right
    _params.DeviceIoControl.OutputBufferLength.val = output_buf_length
    _params.DeviceIoControl.InputBufferLength.val = input_buf_length
    _params.DeviceIoControl.IoControlCode.val = ioctlcode
    _params.DeviceIoControl.Type3InputBuffer = type3_input_buf_addr
    sm = proj.factory.simgr(state)

    sm.populate('found', [])

    if ARGS.directed:
        def hit_callback(
            goal: angr.exploration_techniques.director.BaseGoal,
            state: angr.SimState,
            simgr: angr.SimulationManager
        ):
            print('#' * 80)
            print(f"hit goal {goal=} {state=} {simgr=}")
            print('#' * 80)
            simgr.populate('found', [state])

        director = angr.exploration_techniques.Director(
            # peek_blocks=200,
            # peek_functions=10,
            goal_satisfied_callback=hit_callback)
        director.add_goal(ExecuteAddressGoal(target_addr))
        sm.use_technique(director)

    # Explosion Detection HERE!!
    dfs = angr.exploration_techniques.DFS()
    sm.use_technique(dfs)

    ed = ExplosionDetector(threshold=10000)
    sm.use_technique(ed)

    if not ARGS.directed:
        exp = angr.exploration_techniques.Explorer(find=target_addr)
        sm.use_technique(exp)

    sol = None

    while len(sm.active) > 0 and not ed.state_exploded_bool:
        #new_state = sm.active[0]
        #state_addr = new_state.solver.eval(new_state.regs.pc)
        #sm.step()
        sm.step()
        print(sm)

        if sm.found:
            print("Found sol early..")
            sol = sm.found[0]
            break

    print("\nFinding the IOCTL codes..")
    #logging.debug("Finding the IOCTL codes..")
    ioctl = ""

    if ed.state_exploded_bool:
        print("\nState Exploded!")
        # ipdb.set_trace()

    if sm.errored:
        # ipdb.set_trace()
        for s in sm.errored:
            print(f"ERROR: {repr(s)}", file=sys.stderr)

    if sol:
        #sol = sm.found[0]
        #IPython.embed()
        ioctl = sol.solver.eval(ioctlcode)
        print("[+] Boom! Here is the IOCTL: ", hex(ioctl))
        #logging.critical("[+] Boom! Here is the IOCTL: %s", hex(ioctl))

    else:
        print("No IOCTL codes found!")
        # import ipdb; ipdb.set_trace()
        #logging.info("No IOCTL codes found!")

    return sol, ioctl


def MmMapIoSpace_analysis(found_state):

    prototype = mycc.guess_prototype((0, 0))
    PhysicalAddress, NumberOfBytes = mycc.get_args(found_state, prototype)

    if not PhysicalAddress.symbolic:
        return

    # Require address to be tainted by IOCTL input buffer
    if not is_ioctl_tainted(PhysicalAddress):
        return

    # False-positive filter 1: 32-bit physical address cap.
    # On x64 Windows with >4GB RAM, EPROCESS structures are located above 4GB.
    # A driver that can only supply a 32-bit physical address (HighPart always 0)
    # cannot reach EPROCESS and is not exploitable for PPL bypass / EPROCESS patching.
    try:
        max_pa = found_state.solver.max(PhysicalAddress)
        if max_pa < 0x100000000:
            print(f"[!] PhysicalAddress constrained to 32-bit range "
                  f"(max=0x{max_pa:x}) — cannot reach EPROCESS above 4GB, "
                  f"suppressing Boom!")
            return
    except Exception:
        pass

    # False-positive filter 2: narrowly-constrained address.
    # If the solver can only produce 1-2 distinct physical address values,
    # the address is effectively constant (e.g. a firmware mailbox or PCI BAR)
    # rather than a fully user-controlled value.
    if check_narrow_constraints(found_state, PhysicalAddress, "PhysicalAddress"):
        return

    if NumberOfBytes.symbolic:
        print("[+] Address and Size are user controlled: Addr={}, size={} ..".format(PhysicalAddress, NumberOfBytes))
    else:
        print("[+] Address is user controlled: Addr={}, mapping {} bytes ..".format(PhysicalAddress, NumberOfBytes))
    print("[+] Driver's MmMapIoSpace is potentially vulnerable!!")


def ZwMapViewOfSection_analysis(found_state):
    prototype = mycc.guess_prototype((0,))
    # import ipdb; ipdb.set_trace()
    handle, = mycc.get_args(found_state, prototype)
    if not handle.symbolic:
        return

    if any('handle_ZwOpenSection' not in v for v in handle.variables):
        print("[+] SectionHandle is user controlled, handle={} ..".format(handle))
        print("[+] Driver's ZwMapViewOfSection is potentially vulnerable!!")
        #logging.critical("[+] SectionHandle is user controlled, handle=%s ..",handle)
        #logging.critical("[+] Driver's ZwMapViewOfSection is potentially vulnerable!!")
    else:
        # Okay, now we have to check what this handle refers to
        handles = dict(found_state.globals['open_section_handles'])
        if handle not in handles:
            print("[+] ZwMapViewOfSection called on unknown handle!! Handle={} ...".format(repr(handle)))
            #logging.error("[+] ZwMapViewOfSection called on unknown handle!! Handle=%s ...", repr(handle))
            return

        if handles[handle] == '\\Device\\PhysicalMemory':
            print("[+] ZwMapViewOfSection is potentially vulnerable, mapping PhysicalMemory .. ")
            #logging.critical("[+] ZwMapViewOfSection is potentially vulnerable, mapping \\Device\\PhysicalMemory .. ")


def ZwOpenProcess_analysis(found_state):
    prototype = mycc.guess_prototype((0, 0, 0, 0))
    # import ipdb; ipdb.set_trace()
    _, _, _, ClientID = mycc.get_args(found_state, prototype)
    if ClientID.symbolic:
        print("[+] ClientID of the process is user controlled, ClientID={} .. ".format(ClientID))
        print("[+] Driver's ZwOpenProcess is potentially vulnerable!!")
        #logging.critical("[+] ClientID of the process is user controlled, ClientID=%s.. ",ClientID)
        #logging.critical("[+] Driver's ZwOpenProcess is potentially vulnerable!!")


def MmMapIoSpaceEx_analysis(found_state):
    """MmMapIoSpaceEx(PhysicalAddress, NumberOfBytes, Protect)"""
    prototype = mycc.guess_prototype((0, 0, 0))
    PhysicalAddress, NumberOfBytes, Protect = mycc.get_args(found_state, prototype)

    if is_ioctl_tainted(PhysicalAddress):
        # 32-bit address cap check
        try:
            max_pa = found_state.solver.max(PhysicalAddress)
            if max_pa < 0x100000000:
                print(f"[!] MmMapIoSpaceEx PhysicalAddress 32-bit only "
                      f"(max=0x{max_pa:x}) — suppressing Boom!")
                return
        except Exception:
            pass
        if check_narrow_constraints(found_state, PhysicalAddress, "PhysicalAddress"):
            return
        print("[+] Boom! RWPrimitive: MmMapIoSpaceEx - "
              f"arbitrary ReadWrite (PhysicalAddress={PhysicalAddress})")
    elif is_ioctl_tainted(NumberOfBytes):
        print("[+] Boom! RWPrimitive: MmMapIoSpaceEx - "
              f"arbitrary ReadWrite (NumberOfBytes controlled)")


def MmCopyMemory_analysis(found_state):
    """MmCopyMemory(TargetAddress, SourceAddress, NumberOfBytes, Flags, NumberOfBytesTransferred)"""
    prototype = mycc.guess_prototype((0, 0, 0, 0, 0))
    TargetAddr, SourceAddr, NumBytes, Flags, _ = mycc.get_args(found_state, prototype)

    if is_ioctl_tainted(SourceAddr):
        print("[+] Boom! RWPrimitive: MmCopyMemory - "
              f"arbitrary Read (SourceAddress={SourceAddr})")
    if is_ioctl_tainted(TargetAddr):
        print("[+] Boom! RWPrimitive: MmCopyMemory - "
              f"arbitrary Write (TargetAddress={TargetAddr})")


def ZwReadVirtualMemory_analysis(found_state):
    """ZwReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead)"""
    prototype = mycc.guess_prototype((0, 0, 0, 0, 0))
    ProcessHandle, BaseAddress, Buffer, NumBytes, _ = mycc.get_args(found_state, prototype)

    if is_ioctl_tainted(BaseAddress):
        print("[+] Boom! RWPrimitive: ZwReadVirtualMemory - "
              f"arbitrary Read (BaseAddress={BaseAddress})")


def ZwWriteVirtualMemory_analysis(found_state):
    """ZwWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten)"""
    prototype = mycc.guess_prototype((0, 0, 0, 0, 0))
    ProcessHandle, BaseAddress, Buffer, NumBytes, _ = mycc.get_args(found_state, prototype)

    if is_ioctl_tainted(BaseAddress) and is_ioctl_tainted(Buffer):
        print("[+] Boom! RWPrimitive: ZwWriteVirtualMemory - "
              f"arbitrary Write (BaseAddress+Buffer controlled)")
    elif is_ioctl_tainted(BaseAddress):
        print("[+] Boom! RWPrimitive: ZwWriteVirtualMemory - "
              f"arbitrary Write (BaseAddress controlled)")


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
    """MmMapLockedPagesSpecifyCache or MmMapLockedPages -- MDL-based mapping.
    Check if the MDL argument is tainted directly or via IoAllocateMdl provenance."""
    prototype = mycc.guess_prototype((0, 0))
    MemoryDescriptorList, AccessMode = mycc.get_args(found_state, prototype)

    # Suppress all MDL Boom for KS framework drivers (internal streaming buffer management)
    if KS_DRIVER:
        print("[!] KS framework driver — suppressing MDL-based Boom "
              "(Kernel Streaming internal buffer management, not physical mapping)")
        return

    # Suppress: METHOD_OUT_DIRECT IOCTLs (bits[1:0] == 2) have their output MDL managed by
    # the I/O manager. Any IoAllocateMdl in this context is for internal driver purposes,
    # not for user-controlled physical mapping. bypusb.sys is the canonical example.
    ioctl_bvs = found_state.globals.get('ioctlcode_bvs')
    if ioctl_bvs is not None:
        try:
            ioctl_val = found_state.solver.eval(ioctl_bvs)
            if (ioctl_val & 3) == 2:
                print(f"[!] IOCTL {hex(ioctl_val)} is METHOD_OUT_DIRECT — "
                      "output MDL managed by I/O manager, suppressing MDL Boom!")
                return
        except Exception:
            pass

    # Direct check: is MDL pointer itself tainted?
    if MemoryDescriptorList.symbolic and is_ioctl_tainted(MemoryDescriptorList):
        print("[+] MDL pointer is user controlled: "
              f"MDL={MemoryDescriptorList} ..")
        print("[+] Boom! RWPrimitive: MmMapLockedPages - "
              "arbitrary ReadWrite (MDL pointer tainted)")
        return

    # Provenance check: trace MDL back through IoAllocateMdl
    mdl_prov = found_state.globals.get('mdl_provenance', ())
    for entry in mdl_prov:
        # Support both legacy 3-tuple and current 4-tuple (with probe_access_mode)
        if len(entry) == 4:
            mdl_addr, source_addr, api_name, probe_mode = entry
        else:
            mdl_addr, source_addr, api_name = entry
            probe_mode = None

        if not found_state.solver.satisfiable(
                extra_constraints=[MemoryDescriptorList == mdl_addr]):
            continue

        # Suppress: UserMode-probed MDL can only map user-space VAs, not physical memory.
        # USB bulk/SCSI passthrough drivers legitimately use this pattern — not exploitable.
        if probe_mode == 1:
            print(f"[!] MDL was UserMode-probed (via {api_name}) — "
                  "cannot reach physical/kernel memory, suppressing Boom!")
            return

        if source_addr.symbolic and is_ioctl_tainted(source_addr):
            if check_narrow_constraints(found_state, source_addr, "MDL.SourceAddr"):
                return
            print("[+] MDL created from user-controlled address: "
                  f"SourceAddr={source_addr} (via {api_name}) ..")
            print("[+] Boom! RWPrimitive: MmMapLockedPages - "
                  "arbitrary ReadWrite (MDL chain vulnerable)")
            return


def MmGetPhysicalAddress_analysis(found_state):
    """MmGetPhysicalAddress(BaseAddress)"""
    prototype = mycc.guess_prototype((0,))
    BaseAddress, = mycc.get_args(found_state, prototype)

    if is_ioctl_tainted(BaseAddress):
        print("[+] Boom! RWPrimitive: MmGetPhysicalAddress - "
              f"arbitrary Read (BaseAddress={BaseAddress}, address disclosure)")


def HalTranslateBusAddress_analysis(found_state):
    """HalTranslateBusAddress(InterfaceType, BusNumber, BusAddress, AddressSpace, TranslatedAddress)"""
    prototype = mycc.guess_prototype((0, 0, 0, 0, 0))
    InterfaceType, BusNumber, BusAddress, AddressSpace, TranslatedAddress = mycc.get_args(
        found_state, prototype
    )

    if is_ioctl_tainted(BusAddress):
        print("[+] Boom! RWPrimitive: HalTranslateBusAddress - "
              f"arbitrary ReadWrite (BusAddress={BusAddress})")


# ---------------------------------------------------------------------------
# Process-control sink analysis functions
# Category "ProcessControl": direct process/thread termination and suspension.
# Category "ProcessInjection": cross-process memory manipulation (code injection).
# ---------------------------------------------------------------------------

def ZwTerminateProcess_analysis(found_state):
    """ZwTerminateProcess(ProcessHandle, ExitStatus)"""
    prototype = mycc.guess_prototype((0, 0))
    ProcessHandle, _ExitStatus = mycc.get_args(found_state, prototype)
    if is_ioctl_tainted(ProcessHandle):
        print("[+] Boom! ProcessControl: ZwTerminateProcess - "
              f"arbitrary process termination (ProcessHandle tainted)")


def ZwTerminateThread_analysis(found_state):
    """ZwTerminateThread(ThreadHandle, ExitStatus)"""
    prototype = mycc.guess_prototype((0, 0))
    ThreadHandle, _ExitStatus = mycc.get_args(found_state, prototype)
    if is_ioctl_tainted(ThreadHandle):
        print("[+] Boom! ProcessControl: ZwTerminateThread - "
              f"arbitrary thread termination (ThreadHandle tainted)")


def ZwSuspendProcess_analysis(found_state):
    """ZwSuspendProcess(ProcessHandle)"""
    prototype = mycc.guess_prototype((0,))
    ProcessHandle, = mycc.get_args(found_state, prototype)
    if is_ioctl_tainted(ProcessHandle):
        print("[+] Boom! ProcessControl: ZwSuspendProcess - "
              f"arbitrary process suspension (ProcessHandle tainted)")


def ZwSuspendThread_analysis(found_state):
    """ZwSuspendThread(ThreadHandle, PreviousSuspendCount)"""
    prototype = mycc.guess_prototype((0, 0))
    ThreadHandle, _PrevCount = mycc.get_args(found_state, prototype)
    if is_ioctl_tainted(ThreadHandle):
        print("[+] Boom! ProcessControl: ZwSuspendThread - "
              f"arbitrary thread suspension (ThreadHandle tainted)")


def ZwAllocateVirtualMemory_analysis(found_state):
    """ZwAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect)"""
    prototype = mycc.guess_prototype((0, 0, 0, 0, 0, 0))
    ProcessHandle, _BaseAddr, _ZeroBits, _RegionSize, _AllocType, _Protect = \
        mycc.get_args(found_state, prototype)
    if is_ioctl_tainted(ProcessHandle):
        print("[+] Boom! ProcessInjection: ZwAllocateVirtualMemory - "
              f"cross-process memory allocation (ProcessHandle tainted)")


def ZwProtectVirtualMemory_analysis(found_state):
    """ZwProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection)"""
    prototype = mycc.guess_prototype((0, 0, 0, 0, 0))
    ProcessHandle, BaseAddress, _NumBytes, _NewProtect, _OldProtect = \
        mycc.get_args(found_state, prototype)
    if is_ioctl_tainted(ProcessHandle):
        print("[+] Boom! ProcessInjection: ZwProtectVirtualMemory - "
              f"cross-process page protection change (ProcessHandle tainted)")
    elif is_ioctl_tainted(BaseAddress):
        print("[+] Boom! ProcessInjection: ZwProtectVirtualMemory - "
              f"arbitrary page protection change (BaseAddress tainted)")


def ZwUnmapViewOfSection_analysis(found_state):
    """ZwUnmapViewOfSection(ProcessHandle, BaseAddress)"""
    prototype = mycc.guess_prototype((0, 0))
    ProcessHandle, BaseAddress = mycc.get_args(found_state, prototype)
    if is_ioctl_tainted(ProcessHandle):
        print("[+] Boom! ProcessInjection: ZwUnmapViewOfSection - "
              f"cross-process section unmapping (ProcessHandle tainted)")
    elif is_ioctl_tainted(BaseAddress):
        print("[+] Boom! ProcessInjection: ZwUnmapViewOfSection - "
              f"arbitrary section unmapping (BaseAddress tainted)")


class HookIoCreateDevice(angr.SimProcedure):
    def run(self, DriverObject, DeviceExtensionSize, DeviceName, DeviceType, DeviceCharacteristics, Exclusive,
            DeviceObject):
        devobjaddr = next_base_addr()
        self.state.globals['device_object_addr'] = devobjaddr
        #print("HookIoCreateDevice: Placing device object at {:08x}!".format(devobjaddr))
        #logging.debug("HookIoCreateDevice: Placing device object at %s!", devobjaddr)
        device_object = claripy.BVS('device_object', 8 * 0x400)
        self.state.memory.store(devobjaddr, device_object)
        self.state.mem[devobjaddr].DEVICE_OBJECT.Flags = 0
        self.state.mem[DeviceObject].PDEVICE_OBJECT = devobjaddr

        new_device_extension_addr = next_base_addr()
        self.state.globals['device_extension_addr'] = new_device_extension_addr
        #print("HookIoCreateDevice: Placing device extension at {:08x}!".format(new_device_extension_addr))
        #logging.debug("HookIoCreateDevice: Placing device extension at %s!", new_device_extension_addr)
        device_extension = claripy.BVV(0, 8 * self.state.solver.eval_one(DeviceExtensionSize))
        self.state.memory.store(new_device_extension_addr, device_extension)
        self.state.mem[devobjaddr].DEVICE_OBJECT.DeviceExtension = new_device_extension_addr

        return 0


class HookIoCreateSymbolicLink(angr.SimProcedure):
    def run(self, SymbolicLinkName, DeviceName):
        return 0


class HookZwOpenSection(angr.SimProcedure):
    def run(self, SectionHandle, DesiredAccess, ObjectAttributes):
        new_handle = claripy.BVS('handle_ZwOpenSection', self.state.arch.bits)
        self.state.memory.store(SectionHandle, new_handle, endness=self.state.arch.memory_endness)

        object_name_struct = self.state.mem[ObjectAttributes].OBJECT_ATTRIBUTES.ObjectName.deref
        try:
            object_name = object_name_struct.Buffer.deref.wstring.concrete
        except:
            object_name = "<unknown>"

        self.state.globals['open_section_handles'] += ((new_handle, object_name),)
        self.state.globals['open_handles'] += (
            (new_handle, "ZwOpenSection", self.state.addr),
        )
        return 0


def read_ptr(state, addr):
    return state.memory.load(addr, state.arch.bits, endness=state.arch.memory_endness)


def write_ptr(state, addr, ptr):
    return state.memory.store(addr, ptr, endness=state.arch.memory_endness)

def opportunistically_eval_one(state, value, msg_on_multi):
    conc_vals = state.solver.eval_upto(value, 2)
    if len(conc_vals) > 1:
        print(msg_on_multi)
        print(f"Concretizing to {hex(conc_vals[0])}")
        state.solver.add(value == conc_vals[0])
    return conc_vals[0]

class HookRtlInitUnicodeString(angr.SimProcedure):
    def run(self, DestinationString, SourceString):
        try:
            string_orig = self.state.mem[SourceString].wstring.resolved
        except:
            string_orig = claripy.Concat(claripy.BVS("symbolic_init_unicode_string", 8 * 10), claripy.BVV(0, 16))

        byte_length = string_orig.length // 8
        new_buffer = next_base_addr(size=byte_length + 0x20)
        self.state.memory.store(new_buffer, string_orig)

        unistr = self.state.mem[DestinationString].struct._UNICODE_STRING

        self.state.memory.store(DestinationString, claripy.BVV(0, unistr._type.size))
        unistr.Length = byte_length - 2
        unistr.MaximumLength = byte_length
        unistr.Buffer = new_buffer

        # IPython.embed()

        return 0

class HookRtlCopyUnicodeString(angr.SimProcedure):
    def run(self, DestinationString, SourceString):
        memcpy = angr.procedures.SIM_PROCEDURES['libc']['memcpy']
        src_unistr = self.state.mem[SourceString].struct._UNICODE_STRING
        src_len = src_unistr.Length

        dst_unistr = self.state.mem[DestinationString].struct._UNICODE_STRING
        dst_maxi_len = src_unistr.MaximumLength

        conc_src_len = opportunistically_eval_one(
            self.state,
            src_len.resolved,
            f"Symbolic CopyUnicodeString source size...???? {src_unistr=} size={src_len=}")
        conc_dst_max_len = opportunistically_eval_one(
            self.state,
            dst_maxi_len.resolved,
            f"Symbolic CopyUnicodeString source maximum length...???? {dst_unistr=} size={dst_maxi_len=}")

        self.inline_call(memcpy, dst_unistr.Buffer.resolved, src_unistr.Buffer.resolved, min(conc_src_len, conc_dst_max_len))

        return 0


class HookExAllocatePool(angr.SimProcedure):
    def run(self, pool_type, size):
        conc_sizes = self.state.solver.eval_upto(size, 2)
        if len(conc_sizes) > 1:
            print(f"Symbolic ExAllocatePool size...???? {pool_type=} {size=}")
            print(f"Concretizing to {hex(conc_sizes[0])}")
            self.state.solver.add(size == conc_sizes[0])

        addr = next_base_addr(conc_sizes[0])
        return addr

class HookExAllocatePoolWithTag(angr.SimProcedure):
    def run(self, pool_type, size, tag):
        conc_sizes = self.state.solver.eval_upto(size, 2)
        if len(conc_sizes) > 1:
            print(f"Symbolic ExAllocatePoolWithTag size...???? {pool_type=} {size=} {tag=}")
            print(f"Concretizing to {hex(conc_sizes[0])}")
            self.state.solver.add(size == conc_sizes[0])

        addr = next_base_addr(conc_sizes[0])
        return addr


class HookObReferenceObjectByHandle(angr.SimProcedure):

    def run(self, Handle, DesiredAccess, ObjectType, AccessMode, Object, HandleInformation):
        print("JASimproc")
        return 0


# --- Handle tracking SimProcedures ---

class HookZwClose(angr.SimProcedure):
    def run(self, Handle):
        remaining = []
        for entry in self.state.globals.get('open_handles', ()):
            stored_handle, api_name, creation_pc = entry
            if self.state.solver.satisfiable(
                extra_constraints=[stored_handle == Handle]
            ):
                if api_name == "ZwOpenSection":
                    self.state.globals['open_section_handles'] = tuple(
                        e for e in self.state.globals.get('open_section_handles', ())
                        if not self.state.solver.satisfiable(
                            extra_constraints=[e[0] == Handle]
                        )
                    )
            else:
                remaining.append(entry)
        self.state.globals['open_handles'] = tuple(remaining)
        return 0


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
        self.state.memory.store(
            Handle, handle_bvs,
            endness=self.state.arch.memory_endness
        )
        # Only track for HandleLeak/HandleExposure if the Object pointer is
        # tainted by IOCTL input.  Drivers that call ObOpenObjectByPointer on
        # their own internal device objects (not user-supplied pointers) would
        # otherwise generate false-positive HandleLeak reports.
        if is_ioctl_tainted(Object):
            self.state.globals['open_handles'] += (
                (handle_bvs, "ObOpenObjectByPointer", self.state.addr),
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


class HookZwOpenEvent(angr.SimProcedure):
    def run(self, EventHandle, DesiredAccess, ObjectAttributes):
        handle_bvs = claripy.BVS(
            f'handle_ZwOpenEvent_{self.state.addr:#x}',
            self.state.arch.bits
        )
        self.state.memory.store(
            EventHandle, handle_bvs,
            endness=self.state.arch.memory_endness
        )
        self.state.globals['open_handles'] += (
            (handle_bvs, "ZwOpenEvent", self.state.addr),
        )
        return 0


class HookZwOpenMutant(angr.SimProcedure):
    def run(self, MutantHandle, DesiredAccess, ObjectAttributes):
        handle_bvs = claripy.BVS(
            f'handle_ZwOpenMutant_{self.state.addr:#x}',
            self.state.arch.bits
        )
        self.state.memory.store(
            MutantHandle, handle_bvs,
            endness=self.state.arch.memory_endness
        )
        self.state.globals['open_handles'] += (
            (handle_bvs, "ZwOpenMutant", self.state.addr),
        )
        return 0


class HookZwOpenSemaphore(angr.SimProcedure):
    def run(self, SemaphoreHandle, DesiredAccess, ObjectAttributes):
        handle_bvs = claripy.BVS(
            f'handle_ZwOpenSemaphore_{self.state.addr:#x}',
            self.state.arch.bits
        )
        self.state.memory.store(
            SemaphoreHandle, handle_bvs,
            endness=self.state.arch.memory_endness
        )
        self.state.globals['open_handles'] += (
            (handle_bvs, "ZwOpenSemaphore", self.state.addr),
        )
        return 0


class HookZwOpenSymbolicLinkObject(angr.SimProcedure):
    def run(self, LinkHandle, DesiredAccess, ObjectAttributes):
        handle_bvs = claripy.BVS(
            f'handle_ZwOpenSymbolicLinkObject_{self.state.addr:#x}',
            self.state.arch.bits
        )
        self.state.memory.store(
            LinkHandle, handle_bvs,
            endness=self.state.arch.memory_endness
        )
        self.state.globals['open_handles'] += (
            (handle_bvs, "ZwOpenSymbolicLinkObject", self.state.addr),
        )
        return 0


class HookZwOpenTimer(angr.SimProcedure):
    def run(self, TimerHandle, DesiredAccess, ObjectAttributes):
        handle_bvs = claripy.BVS(
            f'handle_ZwOpenTimer_{self.state.addr:#x}',
            self.state.arch.bits
        )
        self.state.memory.store(
            TimerHandle, handle_bvs,
            endness=self.state.arch.memory_endness
        )
        self.state.globals['open_handles'] += (
            (handle_bvs, "ZwOpenTimer", self.state.addr),
        )
        return 0


# --- RW primitive sink SimProcedure hooks ---

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
        return 1


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
        return


class HookZwSetValueKey(angr.SimProcedure):
    def run(self, KeyHandle, ValueName, TitleIndex, Type, Data, DataSize):
        return 0


# --- Process-control sink hooks ---
# These return STATUS_SUCCESS so symbolic execution can continue past the call.

class HookZwTerminateProcess(angr.SimProcedure):
    def run(self, ProcessHandle, ExitStatus):
        return 0


class HookZwTerminateThread(angr.SimProcedure):
    def run(self, ThreadHandle, ExitStatus):
        return 0


class HookZwSuspendProcess(angr.SimProcedure):
    def run(self, ProcessHandle):
        return 0


class HookZwSuspendThread(angr.SimProcedure):
    def run(self, ThreadHandle, PreviousSuspendCount):
        return 0


class HookZwAllocateVirtualMemory(angr.SimProcedure):
    def run(self, ProcessHandle, BaseAddress, ZeroBits, RegionSize,
            AllocationType, Protect):
        alloc_addr = next_base_addr()
        self.state.memory.store(
            BaseAddress, claripy.BVV(alloc_addr, self.state.arch.bits),
            endness=self.state.arch.memory_endness
        )
        return 0


class HookZwProtectVirtualMemory(angr.SimProcedure):
    def run(self, ProcessHandle, BaseAddress, NumberOfBytesToProtect,
            NewAccessProtection, OldAccessProtection):
        return 0


class HookZwUnmapViewOfSection(angr.SimProcedure):
    def run(self, ProcessHandle, BaseAddress):
        return 0


# --- MDL chain tracking hooks ---

class HookIoAllocateMdl(angr.SimProcedure):
    def run(self, VirtualAddress, Length, SecondaryBuffer, ChargeQuota, Irp):
        mdl_addr = next_base_addr()
        mdl_data = claripy.BVS('mdl_data', 8 * 0x40)
        self.state.memory.store(mdl_addr, mdl_data)
        self.state.globals['mdl_provenance'] = \
            self.state.globals.get('mdl_provenance', ()) + (
                (mdl_addr, VirtualAddress, 'IoAllocateMdl', None),  # 4th = probe_access_mode
            )
        return mdl_addr


class HookMmBuildMdlForNonPagedPool(angr.SimProcedure):
    def run(self, MemoryDescriptorList):
        return


class HookMmProbeAndLockPages(angr.SimProcedure):
    """VOID MmProbeAndLockPages(PMDL MemoryDescriptorList, KPROCESSOR_MODE AccessMode,
    LOCK_OPERATION Operation)

    Records AccessMode (0=KernelMode, 1=UserMode) against the matching MDL in
    mdl_provenance. UserMode-probed MDLs can only map user-space virtual addresses —
    they cannot reach physical memory or kernel addresses — so MmMapLockedPages_analysis
    suppresses Boom! for any MDL whose probe_access_mode == 1.
    """
    def run(self, MemoryDescriptorList, AccessMode, Operation):
        # Extract concrete AccessMode value
        try:
            modes = self.state.solver.eval_upto(AccessMode, 2)
            if len(modes) != 1:
                return  # symbolic AccessMode — conservative: leave as None, do not suppress
            concrete_mode = modes[0]
        except Exception:
            return

        # Find the matching MDL in provenance and update its probe_access_mode
        old = self.state.globals.get('mdl_provenance', ())
        new = []
        for entry in old:
            mdl_addr, source_addr, api_name, existing_mode = entry
            try:
                match = self.state.solver.satisfiable(
                    extra_constraints=[MemoryDescriptorList == mdl_addr])
            except Exception:
                match = False
            if match and existing_mode is None:
                new.append((mdl_addr, source_addr, api_name, concrete_mode))
            else:
                new.append(entry)
        self.state.globals['mdl_provenance'] = tuple(new)


# --- Taint checking and vulnerability detection helpers ---

def is_ioctl_tainted(bv):
    """Check if a bitvector's symbolic variables are tainted by IOCTL input."""
    if not bv.symbolic:
        return False
    return any(
        'ioctl_inbuf' in v or 'ioctl_type3_inbuf' in v
        for v in bv.variables
    )


def check_narrow_constraints(found_state, bvs, name="arg"):
    """Check if a symbolic value is constrained to a narrow range.

    Returns True if the value should be suppressed (too narrowly constrained
    to be reliably exploitable — likely hardware-specific or validation-locked).
    Returns False if the value appears to have meaningful freedom.

    Threshold: <=2 solutions → suppress; 3-4 solutions → warn only; >=5 → pass.
    """
    if not bvs.symbolic:
        return True  # concrete — not symbolic at all, trivially narrow
    vals = found_state.solver.eval_upto(bvs, 5)
    if len(vals) <= 2:
        print(f"[!] {name} constrained to {len(vals)} value(s) "
              f"{[hex(v) for v in vals]} — likely hardware-specific, suppressing Boom!")
        return True   # suppress Boom!
    if len(vals) <= 4:
        print(f"[!] Note: {name} is constrained to {len(vals)} values: "
              f"{[hex(v) for v in vals]} -- may be a false positive")
    return False  # do not suppress


def check_handle_leaks(found_state):
    """Check if any handles opened during IOCTL dispatch were not closed.

    Limitation: this only fires on execution paths that reach an existing sink
    (the path passed to this function). Handles leaked on paths that do NOT
    reach any sink are not detected by this analysis.
    """
    open_handles = found_state.globals.get('open_handles', ())
    for handle_bvs, api_name, creation_pc in open_handles:
        print(f"[+] Boom! HandleLeak: {api_name} handle not closed "
              f"(opened at {creation_pc:#x})")


def check_handle_exposure(found_state, irp_addr):
    """Check if any handle values were written to the IOCTL output buffer."""
    open_handles = found_state.globals.get('open_handles', ())
    if not open_handles:
        return

    try:
        output_buf_addr = found_state.mem[irp_addr].IRP.AssociatedIrp.SystemBuffer.resolved
        output_content = found_state.memory.load(output_buf_addr, 0x200)
    except Exception:
        return

    output_vars = output_content.variables
    for handle_bvs, api_name, creation_pc in open_handles:
        handle_vars = handle_bvs.variables
        if handle_vars & output_vars:
            print(f"[+] Boom! HandleExposure: {api_name} handle written "
                  f"to output buffer (opened at {creation_pc:#x})")


def print_constraint(found_path):

    constraints = found_path.solver.constraints
    #logging.info("Constraints:")
    for constraint in constraints:
        constraint_str = "%s" % constraint
        if "InputBufferLength" in constraint_str:
            print("[+] Input Buffer Size: ", constraint)
            #logging.info("[+] Input Buffer Size: %s", constraint)

        if "inbuf" in constraint_str:
            print("[+] Input Buffer: ", constraint)
            #logging.info("[+] IOCTL: %s", constraint)

        if "OutputBufferLength" in constraint_str:
            print("[+] Output Buffer Size: ", constraint)
            #logging.info("[+] Output Buffer Size: %s", constraint)

    #print("ELSE: ", constraints)


# Super fancy, mind boggling state explosion detector
class ExplosionDetector(angr.exploration_techniques.ExplorationTechnique):
    def __init__(self, stashes=('active', 'deferred', 'errored', 'cut'), threshold=1000):
        super(ExplosionDetector, self).__init__()
        self._stashes = stashes
        self._threshold = threshold
        self.timed_out = Event()
        self.timed_out_bool = False
        self.state_exploded_bool = False

    def step(self, simgr, stash='active', **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)
        total = 0

        if len(simgr.unconstrained) > 0:
            #l.debug("Nuking unconstrained")
            # import ipdb; ipdb.set_trace()
            print("Nuking unconstrained states..")
            simgr.move(from_stash='unconstrained', to_stash='_Drop', filter_func=lambda _: True)

        if self.timed_out.is_set():
            #l.critical("Timed out, %d states: %s" % (total, str(simgr)))
            print("Timed out, %d states: %s" % (total, str(simgr)))
            self.timed_out_bool = True
            for st in self._stashes:
                if hasattr(simgr, st):
                    simgr.move(from_stash=st, to_stash='_Drop', filter_func=lambda _: True)

        for st in self._stashes:
            if hasattr(simgr, st):
                total += len(getattr(simgr, st))

        if total >= self._threshold:
            #l.critical("State explosion detected, over %d states: %s" % (total, str(simgr)))
            print("State explosion detected, over %d states: %s" % (total, str(simgr)))
            self.state_exploded_bool = True
            for st in self._stashes:
                if hasattr(simgr, st):
                    simgr.move(from_stash=st, to_stash='_Drop', filter_func=lambda _: True)

        return simgr

def find_utf_16le_str(data, string):
    cursor = 0
    found = collections.deque()
    device_name = ""
    while cursor < len(data):
        cursor = data.find(string, cursor)
        if cursor == -1:
            break
        terminator = data.find(b'\x00\x00', cursor)
        if (terminator - cursor) % 2:
            terminator += 1
        match = data[cursor:terminator].decode('utf-16le')
        if match not in found:
            device_name = match
            found.append(match)
        cursor += len(string)

    return device_name


def find_device_names(path):
    with open(path, 'rb') as f:
        data = f.read()
        names = []
        for dd in DOS_DEVICES:
            names.append(find_utf_16le_str(data, dd))

        if len(names) == 0:
            print("\nNo Device Name has been found")
            #logging.info("No Device Name has been found")

        else:
            name = []
            for i in names:
                if i:
                    for j in i[::-1]:
                        if j != "\\":
                            name.append(j)
                        else:
                            name.reverse()
                            break

                    dd_name = "\\\\\\\\.\\\\" + "".join(name)
                    print("\nDriver DEVICE_NAME: ", dd_name)
                    #logging.info("Driver DEVICE_NAME: %s", dd_name)



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--directed',
        default=False,
        action='store_true',
        help='Whether to use directed symbolic execution'
    )
    parser.add_argument('driver_path', type=Path, help='The path to the driver to analyze')
    ARGS = parser.parse_args()

    proj = angr.Project(ARGS.driver_path, auto_load_libs=False)
    # Custom CC hooking for the SimProcs
    if proj.arch.name == archinfo.ArchX86.name:
        mycc = angr.calling_conventions.SimCCStdcall(proj.arch)
    else:
        mycc = angr.calling_conventions.SimCCMicrosoftAMD64(proj.arch)
    proj.hook_symbol("ZwOpenSection", HookZwOpenSection(cc=mycc))
    proj.hook_symbol("RtlInitUnicodeString", HookRtlInitUnicodeString(cc=mycc))
    proj.hook_symbol("RtlCopyUnicodeString", HookRtlCopyUnicodeString(cc=mycc))
    proj.hook_symbol("IoCreateDevice", HookIoCreateDevice(cc=mycc))
    proj.hook_symbol("IoCreateSymbolicLink", HookIoCreateSymbolicLink(cc=mycc))
    proj.hook_symbol("ExAllocatePool", HookExAllocatePool(cc=mycc))
    proj.hook_symbol("ExAllocatePoolWithTag", HookExAllocatePoolWithTag(cc=mycc))
    proj.hook_symbol('memmove', angr.procedures.SIM_PROCEDURES['libc']['memcpy']())
    # proj.hook_symbol("ObReferenceObjectByHandle", HookObReferenceObjectByHandle(cc=mycc))

    # Handle tracking hooks
    proj.hook_symbol("ZwClose", HookZwClose(cc=mycc))
    proj.hook_symbol("ZwCreateSection", HookZwCreateSection(cc=mycc))
    proj.hook_symbol("ZwOpenProcess", HookZwOpenProcess(cc=mycc))
    proj.hook_symbol("ZwOpenThread", HookZwOpenThread(cc=mycc))
    proj.hook_symbol("ZwDuplicateObject", HookZwDuplicateObject(cc=mycc))
    proj.hook_symbol("ObOpenObjectByPointer", HookObOpenObjectByPointer(cc=mycc))
    proj.hook_symbol("ZwOpenKey", HookZwOpenKey(cc=mycc))
    proj.hook_symbol("ZwCreateKey", HookZwCreateKey(cc=mycc))
    proj.hook_symbol("ZwOpenFile", HookZwOpenFile(cc=mycc))
    proj.hook_symbol("ZwCreateFile", HookZwCreateFile(cc=mycc))
    proj.hook_symbol("ZwOpenEvent", HookZwOpenEvent(cc=mycc))
    proj.hook_symbol("ZwOpenMutant", HookZwOpenMutant(cc=mycc))
    proj.hook_symbol("ZwOpenSemaphore", HookZwOpenSemaphore(cc=mycc))
    proj.hook_symbol("ZwOpenSymbolicLinkObject", HookZwOpenSymbolicLinkObject(cc=mycc))
    proj.hook_symbol("ZwOpenTimer", HookZwOpenTimer(cc=mycc))

    # RW primitive sink hooks
    proj.hook_symbol("MmCopyMemory", HookMmCopyMemory(cc=mycc))
    proj.hook_symbol("MmMapIoSpaceEx", HookMmMapIoSpaceEx(cc=mycc))
    proj.hook_symbol("ZwWriteVirtualMemory", HookZwWriteVirtualMemory(cc=mycc))
    proj.hook_symbol("NtWriteVirtualMemory", HookZwWriteVirtualMemory(cc=mycc))
    proj.hook_symbol("ZwReadVirtualMemory", HookZwReadVirtualMemory(cc=mycc))
    proj.hook_symbol("NtReadVirtualMemory", HookZwReadVirtualMemory(cc=mycc))
    proj.hook_symbol("MmMapLockedPagesSpecifyCache", HookMmMapLockedPagesSpecifyCache(cc=mycc))
    proj.hook_symbol("MmMapLockedPages", HookMmMapLockedPages(cc=mycc))
    proj.hook_symbol("MmGetPhysicalAddress", HookMmGetPhysicalAddress(cc=mycc))
    proj.hook_symbol("HalTranslateBusAddress", HookHalTranslateBusAddress(cc=mycc))
    proj.hook_symbol("READ_PORT_UCHAR", HookReadPortUChar(cc=mycc))
    proj.hook_symbol("READ_PORT_USHORT", HookReadPortUShort(cc=mycc))
    proj.hook_symbol("READ_PORT_ULONG", HookReadPortULong(cc=mycc))
    proj.hook_symbol("WRITE_PORT_UCHAR", HookWritePort(cc=mycc))
    proj.hook_symbol("WRITE_PORT_USHORT", HookWritePort(cc=mycc))
    proj.hook_symbol("WRITE_PORT_ULONG", HookWritePort(cc=mycc))
    proj.hook_symbol("ZwSetValueKey", HookZwSetValueKey(cc=mycc))

    # Process-control sink hooks
    proj.hook_symbol("ZwTerminateProcess",    HookZwTerminateProcess(cc=mycc))
    proj.hook_symbol("ZwTerminateThread",     HookZwTerminateThread(cc=mycc))
    proj.hook_symbol("ZwSuspendProcess",      HookZwSuspendProcess(cc=mycc))
    proj.hook_symbol("ZwSuspendThread",       HookZwSuspendThread(cc=mycc))
    proj.hook_symbol("ZwAllocateVirtualMemory", HookZwAllocateVirtualMemory(cc=mycc))
    proj.hook_symbol("ZwProtectVirtualMemory",  HookZwProtectVirtualMemory(cc=mycc))
    proj.hook_symbol("ZwUnmapViewOfSection",    HookZwUnmapViewOfSection(cc=mycc))

    # MDL chain hooks
    proj.hook_symbol("IoAllocateMdl", HookIoAllocateMdl(cc=mycc))
    proj.hook_symbol("MmBuildMdlForNonPagedPool", HookMmBuildMdlForNonPagedPool(cc=mycc))
    proj.hook_symbol("MmProbeAndLockPages", HookMmProbeAndLockPages(cc=mycc))

    # cfg = proj.analyses.CFGEmulated(keep_state=False, normalize=True, starts=[ioctl_func_addr])

    driver_type = find_driver_type(proj)

    DOS_DEVICES = ['\\DosDevices\\'.encode('utf-16le'), '\\??\\'.encode('utf-16le')]


    if driver_type == "wdm":

        start_time = time.time()

        find_device_names(ARGS.driver_path)

        targets = check_imports(proj)

        if targets:
            ioctl_handler_addr, driver_base_state = find_ioctl_handler(proj)
            #ioctl_handler_addr = 0x1400045A0
            if ioctl_handler_addr is not None:
                irp_addr = 0x1337000  # Must match find_ioctls()

                if MMMAPIOSPACE:
                    mmmap_addr = int(targets["MmapIoSpace"])
                    found_path, ioctl_code = find_ioctls(proj, driver_base_state, ioctl_handler_addr, mmmap_addr)

                    if ioctl_code:
                        print("[+] IOCTL for MmapIoSpace: ", hex(ioctl_code))
                        MmMapIoSpace_analysis(found_path)
                        print_constraint(found_path)
                        check_handle_leaks(found_path)
                        check_handle_exposure(found_path, irp_addr)

                if ZWMAPVIEWOFSECTION:
                    zwmap_addr = int(targets["ZwMapViewOfSection"])
                    found_path, ioctl_code = find_ioctls(proj, driver_base_state, ioctl_handler_addr, zwmap_addr)

                    if ioctl_code:
                        print("[+] IOCTL for ZwMapViewOfSection: ", hex(ioctl_code))
                        ZwMapViewOfSection_analysis(found_path)
                        print_constraint(found_path)
                        check_handle_leaks(found_path)
                        check_handle_exposure(found_path, irp_addr)

                if ZWOPENPROCESS:
                    zwopen_addr = int(targets["ZwOpenProcess"])
                    found_path, ioctl_code = find_ioctls(proj, driver_base_state, ioctl_handler_addr, zwopen_addr)

                    if ioctl_code:
                        print("[+] IOCTL for ZwOpenProcess: ", hex(ioctl_code))
                        ZwOpenProcess_analysis(found_path)
                        print_constraint(found_path)
                        check_handle_leaks(found_path)
                        check_handle_exposure(found_path, irp_addr)

                # --- Extended RW primitive sinks (all keyed off RW_SINKS dict) ---

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
                        found_path, ioctl_code = find_ioctls(
                            proj, driver_base_state, ioctl_handler_addr,
                            RW_SINKS[_api])
                        if ioctl_code:
                            print(f"[+] IOCTL for {_api}: {hex(ioctl_code)}")
                            _fn(found_path)
                            print_constraint(found_path)
                            check_handle_leaks(found_path)
                            check_handle_exposure(found_path, irp_addr)

                # ZwRead/WriteVirtualMemory: check both Zw and Nt prefixed variants
                for _zw, _nt, _fn in [
                    ('ZwReadVirtualMemory',  'NtReadVirtualMemory',  ZwReadVirtualMemory_analysis),
                    ('ZwWriteVirtualMemory', 'NtWriteVirtualMemory', ZwWriteVirtualMemory_analysis),
                ]:
                    _api = _zw if _zw in RW_SINKS else (_nt if _nt in RW_SINKS else None)
                    if _api:
                        found_path, ioctl_code = find_ioctls(
                            proj, driver_base_state, ioctl_handler_addr,
                            RW_SINKS[_api])
                        if ioctl_code:
                            print(f"[+] IOCTL for {_api}: {hex(ioctl_code)}")
                            _fn(found_path)
                            print_constraint(found_path)
                            check_handle_leaks(found_path)
                            check_handle_exposure(found_path, irp_addr)

                # MDL-based mapping (both variants share one analysis function)
                for _api in ['MmMapLockedPagesSpecifyCache', 'MmMapLockedPages']:
                    if _api in RW_SINKS:
                        found_path, ioctl_code = find_ioctls(
                            proj, driver_base_state, ioctl_handler_addr,
                            RW_SINKS[_api])
                        if ioctl_code:
                            print(f"[+] IOCTL for {_api}: {hex(ioctl_code)}")
                            MmMapLockedPages_analysis(found_path)
                            print_constraint(found_path)
                            check_handle_leaks(found_path)
                            check_handle_exposure(found_path, irp_addr)

                # Port I/O
                for _api in ['READ_PORT_UCHAR', 'READ_PORT_USHORT', 'READ_PORT_ULONG']:
                    if _api in RW_SINKS:
                        found_path, ioctl_code = find_ioctls(
                            proj, driver_base_state, ioctl_handler_addr,
                            RW_SINKS[_api])
                        if ioctl_code:
                            print(f"[+] IOCTL for {_api}: {hex(ioctl_code)}")
                            ReadPortAnalysis(found_path, _api.split('_')[-1])
                            print_constraint(found_path)
                            check_handle_leaks(found_path)
                            check_handle_exposure(found_path, irp_addr)

                for _api in ['WRITE_PORT_UCHAR', 'WRITE_PORT_USHORT', 'WRITE_PORT_ULONG']:
                    if _api in RW_SINKS:
                        found_path, ioctl_code = find_ioctls(
                            proj, driver_base_state, ioctl_handler_addr,
                            RW_SINKS[_api])
                        if ioctl_code:
                            print(f"[+] IOCTL for {_api}: {hex(ioctl_code)}")
                            WritePortAnalysis(found_path, _api.split('_')[-1])
                            print_constraint(found_path)
                            check_handle_leaks(found_path)
                            check_handle_exposure(found_path, irp_addr)

                # --- Process-control sinks (ProcessControl + ProcessInjection) ---
                # Detects EDR/AV killing (ZwTerminateProcess), suspension (ZwSuspendProcess),
                # and cross-process code injection primitives (ZwAllocateVirtualMemory, etc.)
                _PROCESS_CTRL_SINKS = {
                    'ZwTerminateProcess':      ZwTerminateProcess_analysis,
                    'ZwTerminateThread':       ZwTerminateThread_analysis,
                    'ZwSuspendProcess':        ZwSuspendProcess_analysis,
                    'ZwSuspendThread':         ZwSuspendThread_analysis,
                    'ZwAllocateVirtualMemory': ZwAllocateVirtualMemory_analysis,
                    'ZwProtectVirtualMemory':  ZwProtectVirtualMemory_analysis,
                    'ZwUnmapViewOfSection':    ZwUnmapViewOfSection_analysis,
                }
                for _api, _fn in _PROCESS_CTRL_SINKS.items():
                    if _api in PROCESS_CONTROL_SINKS:
                        found_path, ioctl_code = find_ioctls(
                            proj, driver_base_state, ioctl_handler_addr,
                            PROCESS_CONTROL_SINKS[_api])
                        if ioctl_code:
                            print(f"[+] IOCTL for {_api}: {hex(ioctl_code)}")
                            _fn(found_path)
                            print_constraint(found_path)
                            check_handle_leaks(found_path)
                            check_handle_exposure(found_path, irp_addr)

        print("--- %s seconds ---" % (time.time() - start_time))
