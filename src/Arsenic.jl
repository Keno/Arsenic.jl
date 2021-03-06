module Arsenic
  
    using Gallium
    using Cxx
    using DataStructures
    using DWARF
    using DWARF: CallFrameInfo
    using ObjFileBase
    using ObjFileBase: handle
    using ELF
    using COFF

    function get_insts(session, modules, ip)
        base, mod = Gallium.find_module(session, modules, UInt(ip))
        modrel = UInt(UInt(ip)-base)
        if isa(mod, Gallium.SyntheticModule)
            bounds = mod.get_proc_bounds(session, ip)
            insts = Gallium.load(session, Gallium.RemotePtr{UInt8}(base+first(bounds)),
              length(bounds))
            return base, first(bounds), insts
        end
        if isnull(mod.xpdata)
            loc, fde = Gallium.Unwinder.find_fde(mod, modrel)
            seekloc = loc
            cie = CallFrameInfo.realize_cie(fde)
            nbytes = UInt(CallFrameInfo.fde_range(fde, cie))
        else
            entry = Gallium.Unwinder.find_seh_entry(mod, modrel)
            loc = entry.start
            # Need to translate from virtual to file addresses. Hardcode 0xa00 for
            # now.
            seekloc = loc - 0xa00
            nbytes = entry.stop - entry.start
        end
        if ObjFileBase.isrelocatable(handle(mod))
            # For JIT frames, base is the start of .text, so we need to add that
            # offset back
            text = first(filter(x->sectionname(x)==
                ObjFileBase.mangle_sname(handle(mod),"text"),Sections(handle(mod))))
            seekloc += sectionoffset(text)
        elseif isa(handle(mod), ELF.ELFHandle)
            # In weird executables, the executable segment may not be at offset 0
            phs = ELF.ProgramHeaders(handle(mod))
            idx = findfirst(p->p.p_type==ELF.PT_LOAD &&
                               ((p.p_flags & ELF.PF_X) != 0), phs)
            seekloc += phs[idx].p_offset
        elseif isa(handle(mod), COFF.COFFHandle)
            text = ObjFileBase.deref(first(filter(x->sectionname(x)==
                ObjFileBase.mangle_sname(handle(mod),"text"),Sections(handle(mod)))))
            seekloc -= text.VirtualAddress
            seekloc += text.PointerToRawData
        end
        seek(handle(mod), seekloc)
        insts = read(handle(mod), UInt8, nbytes)
        base, loc, insts
    end
    
    function compute_stack(modules, session::Gallium.Ptrace.Session)
        regs = Gallium.getregs(session)
        stack, RCs = Gallium.stackwalk(regs, session, modules, rich_c = true, collectRCs = true)
        Gallium.NativeStack(stack,RCs,modules,session)
    end
    
    function compute_stack(modules, session::Gallium.FakeMemorySession, RC)
        stack, RCs = Gallium.stackwalk(RC, session, modules, rich_c = true, collectRCs = true)
        Gallium.NativeStack(stack,RCs,modules,session)
    end
    
    # We should be in the same frame, fast path stack unwinding
    function update_stack_same_frame!(state, session = state.top_interp.session)
        regs = Gallium.getregs(session)
        modules = state.top_interp.modules
        oldstack, oldRCs = state.top_interp.stack, state.top_interp.RCs
        (length(oldRCs) == 1) &&
            return update_stack!(state, session)
        (ok, oneupRC) = try
            Gallium.Unwinder.unwind_step(session, modules, regs; stacktop = true, ip_only = false)
        catch err
            @show err
            return update_stack!(state, session)
        end
        parentsmatch = Gallium.ip(oldRCs[end-1]) == Gallium.ip(oneupRC) &&
            Gallium.get_dwarf(oldRCs[end-1], :rsp) == Gallium.get_dwarf(oneupRC, :rsp)
        (!ok || !parentsmatch) && return update_stack!(state, session)
        stack, RCs = copy(oldstack), copy(oldRCs)
        ok, frame = Gallium.frameinfo(regs, session, modules; rich_c = true)
        !ok && return update_stack!(state, session)
        stack[end] = get(frame)
        RCs[end] = regs
        state.interp = state.top_interp = Gallium.NativeStack(stack,RCs,modules,session)
    end

    function update_stack!(state, session = state.top_interp.session)
        state.interp = state.top_interp = compute_stack(state.top_interp.modules, session)
    end
    update_stack!(state::Void, _ = nothing) = nothing

    include("disassembler.jl")
    include("stepping.jl")
    include("remoteexec.jl")
    is_linux() && isfile(Pkg.dir("RR","src","RR.jl")) && include("arrsenic.jl")
    include("interface.jl")
end # module
