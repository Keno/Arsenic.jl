module Arsenic
  
    using Gallium
    using Cxx
    using DataStructures
    using DWARF
    using DWARF: CallFrameInfo
    using ObjFileBase
    using ObjFileBase: handle

    function get_insts(session, modules, stack)
        stack = isa(stack, Gallium.NativeStack) ? stack.stack[end] : stack
        base, mod = Gallium.find_module(session, modules, UInt(stack.ip))
        modrel = UInt(UInt(stack.ip)-base)
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

    function update_stack!(state, session = state.top_interp.session)
        state.interp = state.top_interp = compute_stack(state.top_interp.modules, session)
    end
    update_stack!(state::Void, _ = nothing) = nothing

    include("disassembler.jl")
    include("stepping.jl")
    include("remoteexec.jl")
    include("interface.jl")
end # module
