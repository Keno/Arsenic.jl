function iterate_instructions(f, session)
    regs = Gallium.getregs(session)
    addr = UInt64(Gallium.ip(regs))
    ctx = DisAsmContext()
    cont = true
    while cont
        insts = Gallium.load(session, RemotePtr{UInt8}(addr), 15)
        (Inst, InstSize) = getInstruction(insts, 0; ctx = ctx)
        cont = f(addr, Inst, ctx)
        addr += InstSize
        free(Inst)
        Inst = nothing
    end
end

function NextBranchAddr(session)
    addr = 0
    iterate_instructions(session) do where, Inst, ctx
        mayBranch(Inst, ctx) && return false
        addr = where
        return true
    end
    return addr
end

function LastInstrInRange(session, range)
    addr = 0
    iterate_instructions(session) do where, Inst, ctx
        where > last(range) && return false
        addr = where
        return true
    end
    return addr
end


task_step_until_bkpt!(session) = Gallium.step_until_bkpt!(session)

function step_to_address(session, addr)
    bp = Gallium.breakpoint(session, addr)
    task_step_until_bkpt!(session)
    Gallium.disable(bp)
    nothing
end

function step_over(session, range)
    while true
        nba = NextBranchAddr(session)
        isbranch = true
        if !(nba ∈ range)
            nba = LastInstrInRange(session, range)
            isbranch = false
        end
        bp = Gallium.breakpoint(session, nba)
        # get_frame
        while true
            task_step_until_bkpt!(session)
            #comp = compare_frames(frame, timeline)
            #if older
            #    Gallium.disable(bp)
            #    return
            #elseif younger
            #    continue
            #else
            #    break
            #end
            break
        end
        # Ok, we've arrived at our breakpoint in the same frame
        Gallium.disable(bp)
        # We're at an instruction that may step out of the range. Single
        # step and see where we are
        Gallium.single_step!(session)
        (UInt64(Gallium.ip(session)) ∈ range) && continue
        break
    end
end
