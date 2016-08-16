function run_function(f, timeline, modules, name::Union{Symbol,AbstractString}, args::Vector)
    # Find the function ip
    (h, base, sym)  = Gallium.lookup_sym(timeline, modules, name)
    addr = Gallium.compute_symbol_value(h, base, sym)
    run_function(f, timeline, addr, args)
end

run_function(f, timeline, modules, name, args::Union{Integer,Ptr}) = run_function(f, timeline, modules, name, [args])

const args_regs = [:rdi, :rsi, :rdx, :rcx, :r8, :r9]
function run_function(f, timeline, addr::Union{Integer,RemotePtr}, args::Vector)
    diversion = prepare_remote_execution(timeline)
    icxx"$diversion->set_visible_execution(true);"
    
    addr = UInt64(addr)
    
    # Pick an arbitrary task with the same tgid as our current task to run our
    # expression
    task = icxx"""
        for (auto &t : $diversion->tasks())
            if (t.second->tgid() == $(current_task(timeline))->tgid())
                return t.second;
        return (rr::Task *)nullptr;
    """
    regs = icxx"$task->regs();"
    
    # Set up the call frame
    Gallium.set_ip!(regs, addr)
    new_rsp = Gallium.get_dwarf(regs, :rsp)-250
    new_rsp -= (new_rsp % 16)
    new_rsp += 8
    Gallium.set_dwarf!(regs, :rsp, new_rsp)
    
    # Set return address to 0
    Gallium.store!(task, Gallium.RemotePtr{UInt64}(new_rsp), UInt64(0))
    
    # Set up arguments
    for (i,val) in enumerate(args)
        i > length(args_regs) && error("Too many arguments")
        Gallium.set_dwarf!(regs, args_regs[i], UInt64(val))
    end

    # Writes registers back to task
    icxx"$task->set_regs($regs);"
    
    # Alright, let's go
    while true
        res = icxx"$diversion->diversion_step($task);"
        if icxx"$res.status != rr::DiversionSession::DIVERSION_CONTINUE;" ||
            icxx"$res.break_status.signal != 0;"
            break
        end
    end
    
    f(task)
end

# Remote C execution
include("remoteir.jl")

@cxxm "uint64_t GalliumCallbacks::allocateMem(uint32_t kind, uint64_t Size, uint64_t Align)" begin
    global code_mem, ro_mem, rw_mem
    if kind == icxx"llvm::sys::Memory::MF_EXEC | llvm::sys::Memory::MF_READ;"
        code_mem += code_mem % Align
        ret = code_mem
        code_mem += Size
        return UInt64(ret)
    elseif kind == icxx"llvm::sys::Memory::MF_READ;"
        ro_mem += ro_mem % Align
        ret = ro_mem
        ro_mem += Size
        return UInt64(ret)
    elseif kind == icxx"llvm::sys::Memory::MF_READ | llvm::sys::Memory::MF_WRITE;"
        rw_mem += rw_mem % Align
        ret = rw_mem
        rw_mem += Size
        return UInt64(ret)
    else
        error("Unknown kind")
    end
end

@cxxm "void GalliumCallbacks::writeMem(uint64_t remote, uint8_t *localaddr, size_t size)" begin
    session = unsafe_pointer_to_objref(icxx"$this->session;")
    Gallium.store!(session,RemotePtr{UInt8}(remote),
        unsafe_wrap(Array, localaddr, size, false))
end

function lookup_external_symbol(modules, name)::UInt64
    global data_buffer_start
    name == "data_buffer_start" && return data_buffer_start
    h,base,sym = Gallium.lookup_sym(timeline, modules, name)
    ret = ObjFileBase.compute_symbol_value(h, base, sym)
    return ret
end


# Now allocate some memory for the JIT
function create_remote_jit(timeline, near_addr)
    always_free_addresses = icxx"""
        rr::TraceReader reader{$(current_session(timeline))->trace_reader()};
        reader.rewind();
        rr::ReplaySession::always_free_address_space(reader);
    """

    start_addr = icxx"""
        for (auto range : $always_free_addresses) {
            if (std::abs((intptr_t)(range.start().as_int() - $(UInt64(near_addr)))) < INT32_MAX/2) {
                return range.start().as_int();
            } else if (std::abs((intptr_t)(range.end().as_int() - 0x1000 - $(UInt64(near_addr)))) < INT32_MAX/2) {
                return range.end().as_int() -  0x40000;
            }
        }
        return (uint64_t)0;
    """
    global code_mem, ro_mem, rw_mem
    region_size = 0x10000 # 16 pages
    code_mem = start_addr
    icxx"""
    rr::AutoRemoteSyscalls remote($(current_task(current_session(timeline))));
    remote.infallible_mmap_syscall($code_mem, $region_size,
        PROT_EXEC | PROT_READ,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
    """
    ro_mem = start_addr + region_size
    icxx"""
    rr::AutoRemoteSyscalls remote($(current_task(current_session(timeline))));
    remote.infallible_mmap_syscall($ro_mem, $region_size,
        PROT_READ,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
    """
    rw_mem = start_addr + 2region_size
    icxx"""
    rr::AutoRemoteSyscalls remote($(current_task(current_session(timeline))));
    remote.infallible_mmap_syscall($rw_mem, $region_size,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
    """
    stack_mem = 0x700001000
    icxx"""
    rr::AutoRemoteSyscalls remote($(current_task(current_session(timeline))));
    remote.infallible_mmap_syscall($stack_mem, $region_size,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
    """

    memm = icxx"""
    GalliumCallbacks callbacks;
    callbacks.session = $(pointer_from_objref(timeline));
    new RCMemoryManager(std::move(callbacks));
    """
    callbacks = icxx"&$memm->Client;"
    jit = icxx"new RemoteJIT(*llvm::EngineBuilder().selectTarget(), $memm);"
    jit, callbacks
end

cxxinclude(joinpath(dirname(@__FILE__),"FunctionMover.cpp"))
TargetClang = Cxx.new_clang_instance(false)

function allocate_code(callbacks, code)
    addr = icxx"$callbacks->allocateMem(
        llvm::sys::Memory::MF_EXEC | llvm::sys::Memory::MF_READ,
        $(sizeof(code)), 0x16);"
    icxx"$callbacks->writeMem($addr,(uint8_t*)$(pointer(code)),$(sizeof(code)));"
    addr
end

function rewrite_instruction(inst, end_ip)
    # Adjust RIP-relative mov
    length(inst) == 7 || return inst
    # REX.W(R)
    ((inst[1] & 0b11111011) == 0b01001000) || return inst
    # opcode
    (inst[2] == 0x8b) || return inst
    # MODRM, mod = 0b00, r/m = 0b101
    ((inst[3] & 0b11000111) == 0b00000101) || return inst
    # Ok, we have a RIP-relative MOV
    addr = UInt64(end_ip+reinterpret(Int32, inst[4:7])[])
    # Instead encode an absolute MOV
    reg = (inst[3]&0b111000) >> 3
    [
        # mov $abs, %reg
        inst[1]; 0xb8+reg; reinterpret(UInt8,[addr]);
        # move (%reg), %reg
        inst[1]; 0x8b; (reg<<3)|reg
    ]
end

function rewrite_instructions(insts, start_ip)
    rewritten_insts = UInt8[]
    current_end_ip = start_ip
    while current_end_ip < start_ip+length(insts)
        next_inst = extract_next_inst(insts[(1+current_end_ip-start_ip):end])
        current_end_ip += length(next_inst)
        next_inst = rewrite_instruction(next_inst, current_end_ip)
        append!(rewritten_insts, next_inst)
    end
    rewritten_insts
end

Base.unsafe_string(ref::vcpp"llvm::StringRef") =
    unsafe_string(icxx"$ref.data();", icxx"$ref.size();")
function run_func(timeline, jit, callbacks,
        fname::Union{pcpp"clang::Decl",pcpp"clang::FunctionDecl"}, retT=Void, TargetClang = TargetClang, args = Any[])
    run_func(timeline, jit, callbacks, 
        unsafe_string(icxx"cast<clang::NamedDecl>($fname)->getName();"),
        retT, TargetClang, args)
end

function run_func(timeline, jit, callbacks,
        fname::pcpp"llvm::Function", retT=Void, TargetClang = TargetClang, args = Any[])
    run_func(timeline, jit, callbacks, 
        unsafe_string(icxx"$fname->getName();"), retT, TargetClang, args)
end


function run_func(timeline, jit, callbacks, fname, retT=Void, TargetClang = TargetClang, args=Any[])
    shadowmod = Cxx.instance(TargetClang).shadow
    targetmod = icxx"""new llvm::Module("Target Module", $shadowmod->getContext());"""
    icxx"""$targetmod->setDataLayout($shadowmod->getDataLayout());"""
    
    mover = icxx"new FunctionMover2($targetmod);"
    
    F = icxx"$shadowmod->getFunction($(pointer(fname)));"
    @assert F != C_NULL
    icxx"MapFunction($F, $mover);"

    icxx"""
    $jit->addModule(std::unique_ptr<llvm::Module>($targetmod));
    """
    
    addr = icxx"""$jit->findSymbol($(pointer(fname)), false).getAddress();"""
    @assert UInt64(addr) != 0
    
    run_function(timeline, UInt64(addr), args) do task
        regs = icxx"$task->regs();"
        x = Gallium.ip(regs)
        @assert UInt64(x) == 0
        sizeof(retT) == 0 && return retT.instance
        reinterpret(retT, [Gallium.get_dwarf(regs, :rax)])[]
    end
end

function trace_func(jit, callbacks, fname, entry_func, exit_func = "")
    h,base,sym = Gallium.lookup_sym(timeline, modules, fname)
    hook_addr = ObjFileBase.compute_symbol_value(h, base, sym)
    
    shadowmod = Cxx.instance(TargetClang).shadow
    targetmod = icxx"""new llvm::Module("Target Module", $shadowmod->getContext());"""
    icxx"""$targetmod->setDataLayout($shadowmod->getDataLayout());"""
    
    mover = icxx"new FunctionMover2($targetmod);"
    
    F = icxx"$shadowmod->getFunction($(pointer(entry_func)));"
    @assert F != 0
    icxx"MapFunction($F, $mover);"

    if !isempty(exit_func)
        F = icxx"$shadowmod->getFunction($(pointer(exit_func)));"
        @assert F != 0
        icxx"MapFunction($F, $mover);"    
    end

    icxx"""
    $jit->addModule(std::unique_ptr<llvm::Module>($targetmod));
    """
    
    entry_hook = icxx"""$jit->findSymbol($(pointer(entry_func))).getAddress();"""
    exit_hook = isempty(exit_func) ? UInt64(0) :
        icxx"""$jit->findSymbol($(pointer(exit_func))).getAddress();"""

    hook_template = Gallium.Hooking.hook_asm_template(UInt64(0),
        UInt64(0); call = false)

    orig_bytes = Gallium.load(task, RemotePtr{UInt8}(hook_addr), length(hook_template)+15)
    nbytes = Gallium.Hooking.determine_nbytes_to_replace(length(hook_template), orig_bytes)

    ret_jmp_addr = isempty(exit_func) ? UInt64(0) : allocate_code(callbacks, [
        Gallium.Hooking.return_hook_template(0x700011000, exit_hook);
    ])

    jmp_addr = allocate_code(callbacks, [
        Gallium.Hooking.instrument_jmp_template(0x700011000,entry_hook,ret_jmp_addr);
        Gallium.Hooking.hook_tail_template(
            rewrite_instructions(orig_bytes[1:nbytes],UInt(hook_addr)),
            UInt(hook_addr)+nbytes)
    ])

    hook_template = Gallium.Hooking.hook_asm_template(UInt64(hook_addr),
        UInt64(jmp_addr); call = false)

    replacement = [hook_template; zeros(UInt8,nbytes-length(hook_template))]
    Gallium.store!(task, RemotePtr{UInt8}(hook_addr), replacement)

end
