using ASTInterpreter

function triple_for_sess(sess)
    if isa(Gallium.getarch(sess), Gallium.X86_64.X86_64Arch)
        return "x86_64-linux-gnu"
    else
        return "i386-linux-gnu"
    end
end

function ASTInterpreter.execute_command(state, stack, ::Val{:disas}, command)
    parts = split(command, ' ')
    stacktop = 0
    if length(parts) > 1
        ip = parse(Int, parts[2], 16)
    else
        x = isa(stack, Gallium.NativeStack) ? stack.stack[end] : stack
        stacktop = (x.stacktop?0:1); ip = x.ip
    end
    base, loc, insts = get_insts(state.top_interp.session, state.top_interp.modules, ip)
    disasm_around_ip(STDOUT, insts, UInt64(ip-loc-base-stacktop);
        ipbase=base+loc, circular = false, triple = triple_for_sess(state.top_interp.session))
    return false
end

task_single_step!(timeline) = Gallium.single_step!(timeline)

function ASTInterpreter.execute_command(state, stack::Union{Gallium.NativeStack,Gallium.CStackFrame}, ::Val{:si}, command)
    task_single_step!(state.top_interp.session)
    update_stack_same_frame!(state)
    return true
end

function compute_current_line_range(state, stack)
    mod, base, ip = Gallium.modbaseip_for_stack(state, stack)
    linetab, lip = Gallium.obtain_linetable(state, stack)
    sm = start(linetab)
    local current_entry
    local newentry
    # Start by finding the entry that we're in
    while true
        newentry, sm = next(linetab, sm)
        newentry.address > lip && break
        current_entry = newentry
    end
    range = origrange = current_entry.address:(newentry.address-1)
    # Merge any subsequent entries at the same line
    while newentry.line == current_entry.line
        newentry, sm = next(linetab, sm)
        range = first(origrange):(newentry.address-1)
    end
    range += UInt64(ip-lip)
    range
end

function ASTInterpreter.execute_command(state, stack::Union{Gallium.NativeStack,Gallium.CStackFrame}, ::Val{:n}, command)
    session = state.top_interp.session
    range = compute_current_line_range(state, stack)
    step_over(session, range)
    update_stack_same_frame!(state)
    return true
end

function ASTInterpreter.execute_command(state, stack::Union{Gallium.NativeStack,Gallium.CStackFrame}, ::Val{:ip}, command)
    x = isa(stack, Gallium.NativeStack) ? stack.stack[end] : stack
    println(x.ip)
    return false
end

function ASTInterpreter.execute_command(state, stack::Union{Gallium.NativeStack,Gallium.CStackFrame}, ::Val{:nb}, command)
    session = state.top_interp.session
    # First determine the ip of the next branch
    x = isa(stack, Gallium.NativeStack) ? stack.stack[end] : stack
    base, loc, insts = get_insts(session, state.top_interp.modules, x.ip)
    ctx = DisAsmContext()
    Offset = UInt(x.ip - loc - base)
    branchip = 0
    while Offset <= sizeof(insts)
        (Inst, InstSize) = getInstruction(insts, Offset; ctx = ctx)
        if mayAffectControlFlow(Inst,ctx)
            branchip = base + loc + Offset
            break
        end
        Offset += InstSize
        free(Inst)
    end
    @assert branchip != 0
    bp = Gallium.breakpoint(session, branchip)
    task_step_until_bkpt!(session)
    Gallium.disable(bp)
    update_stack_same_frame!(state)
    return true
end

function ASTInterpreter.print_status(state, x::Gallium.CStackFrame; kwargs...)
    session = state.top_interp.session
    modules = state.top_interp.modules
    print("Stopped in function ")
    found, symb = symbolicate_frame(session, modules, x)
    println(symb)
    
    if x.line != 0
        code = ASTInterpreter.readfileorhist(x.file)
        if code !== nothing
            ASTInterpreter.print_sourcecode(
                code, x.line, x.declfile, x.declline)
            return
        end
    end
    ipoffset = 0
    ipbase = x.ip
    if found
        base, loc, insts = get_insts(session, modules, ipbase)
        ipbase = base+loc
        ipoffset = UInt64(x.ip-loc-base-(x.stacktop?0:1))
    else
        insts = Gallium.load(session, Gallium.RemotePtr{UInt8}(x.ip), 40)
    end
    try
        # Try disassembling at the start of the function, highlighting the
        # current ip.
        disasm_around_ip(STDOUT, insts, ipoffset; ipbase=ipbase, triple = triple_for_sess(state.top_interp.session))
    catch
        warn("Failed to obtain instructions from object files. Incorrect unwind info?")
        # This could have failed for a variety of reasons (missing unwind info,
        # self modifying code, etc). If so, get the instructions directly
        # from the target
        insts = Gallium.load(session, Gallium.RemotePtr{UInt8}(x.ip), 40)
        ipoffset = 0
        disasm_around_ip(STDOUT, insts, ipoffset; ipbase=ipbase, triple = triple_for_sess(state.top_interp.session))
    end
end

cxx"""#include <cxxabi.h>"""
function demangle(name)
    startswith(name,"_Z") || return name
    status = Ref{Cint}()
    bufsize = Ref{Csize_t}(0)
    str = icxx"""
        abi::__cxa_demangle($(pointer(name)),nullptr,
        &$bufsize, &$status);
    """
    @assert status[] == 0
    ret = unsafe_string(str)
    Libc.free(str)
    ret
end

function symbolicate_frame(session, modules, x)
    found = false
    symb = "Unknown Function"
    try
        found, symb = Gallium.Unwinder.symbolicate(session, modules, UInt64(x.ip))
        symb = demangle(symb)
        !found && (symb = "Most likely $symb")
    catch err
        (!isa(err, ErrorException) || !contains(err.msg, "found")) && rethrow(err)
    end
    found, symb
end

function ASTInterpreter.print_frame(state, io, num, x::Gallium.CStackFrame)
    session = state.top_interp.session
    modules = state.top_interp.modules
    print(io, "[$num] ")
    found, symb = symbolicate_frame(session, modules, x)
    print(io, symb, " ")
    if x.line != 0
      print(io, " at ",x.file,":",x.line)
    end
    println(io)
end

function ASTInterpreter.execute_command(state, stack, ::Val{:c}, command)
    try
        Gallium.continue!(state.top_interp.session; only_current_tgid = true)
    catch err
        !isa(err, InterruptException) && rethrow(err)
    end
    update_stack!(state)
    return true
end

function ASTInterpreter.execute_command(state, stack::Union{Gallium.CStackFrame,Gallium.NativeStack}, ::Val{:reg}, command)
    ns = state.top_interp
    @assert isa(ns, Gallium.NativeStack)
    RC = ns.RCs[end-(state.level-1)]
    regname = Symbol(split(command,' ')[2])
    inverse_map = isa(Gallium.getarch(state.top_interp.session),Gallium.X86_64.X86_64Arch) ?
        Gallium.X86_64.inverse_dwarf : Gallium.X86_32.inverse_dwarf
    if !haskey(inverse_map, regname)
        print_with_color(:red, STDOUT, "No such register\n")
        return false
    end
    show(UInt(Gallium.get_dwarf(RC, inverse_map[regname])))
    println(); println()
    return false
end

function ASTInterpreter.execute_command(state, stack::Union{Gallium.CStackFrame,Gallium.NativeStack}, ::Val{:unwind}, command)
    ns = state.top_interp
    newRC = Gallium.Unwinder.unwind_step(ns.session, ns.modules, ns.RCs[end-(state.level-1)])[2]
    @show newRC
    return false
end

function ASTInterpreter.execute_command(state, stack::Union{Gallium.CStackFrame,Gallium.NativeStack}, ::Val{:symbolicate}, command)
    session = state.top_interp.session
    modules = state.top_interp.modules
    x = isa(stack, Gallium.NativeStack) ? stack.stack[end] : stack
    approximate, name = Gallium.Unwinder.symbolicate(session, modules, UInt64(x.ip))
    name = demangle(name)
    println(approximate ? "Most likely " : "", name)
    return false
end

function ASTInterpreter.execute_command(state, stack::Union{Gallium.CStackFrame,Gallium.NativeStack}, ::Val{:modules}, command)
    modules = state.top_interp.modules
    modules = sort(collect(modules), by = x->x[1])
    for (base, mod) in modules
        show(UInt64(base)); print('-'); show(UInt64(base)+mod.sz); println()
    end
    return false
end

function ASTInterpreter.execute_command(state, stack::Union{Gallium.CStackFrame,Gallium.NativeStack}, ::Val{:finish}, command)
    ns = state.top_interp
    session = state.top_interp.session
    @assert isa(ns, Gallium.NativeStack)
    parentRC = ns.RCs[end-(state.level)]
    theip = Gallium.ip(parentRC)
    step_to_address(session, theip)
    update_stack!(state)
    return true
end

function ASTInterpreter.execute_command(state, stack::Union{Gallium.CStackFrame,Gallium.NativeStack}, ::Val{:b}, command)
    session = state.top_interp.session
    modules = state.top_interp.modules
    symbol = Symbol(split(command,' ')[2])
    bp = Gallium.breakpoint(session, modules, symbol)
    show(bp)
    return false
end


function dwarf2Cxx(dbgs, dwarfT)
    if DWARF.tag(dwarfT) == DWARF.DW_TAG_pointer_type || 
            DWARF.tag(dwarfT) == DWARF.DW_TAG_array_type
        dwarfT = get(DWARF.extract_attribute(dwarfT,DWARF.DW_AT_type))
        return Cxx.pointerTo(Cxx.instance(RemoteClang), dwarf2Cxx(dbgs, dwarfT.value))
    else
        name = DWARF.extract_attribute(dwarfT,DWARF.DW_AT_name)
        name = bytestring(get(name).value,StrTab(dbgs.debug_str))
        return cxxparse(Cxx.instance(RemoteClang),name,true)
    end
end

function iterate_frame_variables(state, stack, found_cb, not_found_cb)
    mod, base, theip = Gallium.modbaseip_for_stack(state, stack)
    lip = Gallium.compute_ip(Gallium.dhandle(mod),base,theip)
    dbgs = debugsections(Gallium.dhandle(mod))
    ns = state.top_interp
    @assert isa(ns, Gallium.NativeStack)
    RC = ns.RCs[end-(state.level-1)]
    
    Gallium.iterate_variables(RC, found_cb, not_found_cb, dbgs, lip)
end
    

function realize_remote_value(T, val, getreg)
    if isa(val, DWARF.Expressions.MemoryLocation)
        val = Gallium.load(timeline, RemotePtr{T}(val.i))
    elseif isa(val, DWARF.Expressions.RegisterLocation)
        val = reinterpret(T, [getreg(val.i)])[]
    end
    val
end

function ASTInterpreter.execute_command(state, stack::Union{Gallium.CStackFrame,Gallium.NativeStack}, ::Val{:vars}, command)
    function found_cb(dbgs, vardie, getreg, name, val)
        dwarfT = get(DWARF.extract_attribute(vardie,DWARF.DW_AT_type))
        try 
            T = Cxx.juliatype(dwarf2Cxx(dbgs, dwarfT.value))
            val = realize_remote_value(T, val, getreg)
        end
        @show (name, val)
    end
    iterate_frame_variables(state, stack, found_cb, (dbgs, vardie, name)->nothing)
    
    return false
end
