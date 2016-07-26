using RR

"""
Attempt to reverse step until the entry to the current function.
"""
function ASTInterpreter.execute_command(state, stack::Union{Gallium.NativeStack,Gallium.CStackFrame}, ::Val{:rf}, command)
    RR.silence!(timeline)
    
    # Algorithm:
    # 1. Determine the location of the function entry point.
    # 2. Determine how to compute the CFA, both here and at the function entry
    #    point.
    # 3. Continue unless the CFA matches
    
    # Determine module
    stack = isa(stack, Gallium.NativeStack) ? stack.stack[end] : stack
    mod, base, ip = Gallium.modbaseip_for_stack(state, stack)
    modrel = UInt(ip - base)
    loc, fde = Gallium.Unwinder.find_fde(mod, modrel)
    
    # Compute CFI
    ciecache = nothing
    isa(mod, Module) && (ciecache = mod.ciecache)
    cie::DWARF.CallFrameInfo.CIE, ccoff = realize_cieoff(fde, ciecache)
    target_delta = modrel - loc
    
    entry_rs = CallFrameInfo.evaluate_program(fde, UInt(0), cie = cie, ciecache = ciecache, ccoff=ccoff)
    here_rs =  CallFrameInfo.evaluate_program(fde, target_delta, cie = cie, ciecache = ciecache, ccoff=ccoff)

    # Compute the CFA here
    regs = icxx"$(current_task(current_session(timeline)))->regs();"
    here_cfa = Gallium.Unwinder.compute_cfa_addr(current_task(current_session(timeline)), regs, here_rs)
    here_rsp = Gallium.get_dwarf(regs, :rsp)
    
    # Set a breakpoint at function entry
    bp = Gallium.breakpoint(timeline, base + loc)
    
    # Reverse continue until the breakpoint is hit at a matching CFA, or until
    # we're at a breakpoint higher up the stack (which would imply that we missed it)
    while true
        RR.reverse_continue!(timeline)
        # TODO: Check that we're at the right breakpoint
        new_regs = icxx"$(current_task(current_session(timeline)))->regs();"
        new_cfa = Gallium.Unwinder.compute_cfa_addr(current_task(current_session(timeline)), new_regs, entry_rs)
        if here_cfa == new_cfa
            break
        elseif Gallium.get_dwarf(new_regs, :rsp) > here_rsp
            println("WARNING: May have missed function call.")
            break
        end
    end
    Gallium.disable(bp)
    
    # Step once more to get out of the function
    RR.reverse_single_step!(current_session(timeline),current_task(current_session(timeline)),timeline)
    
    update_stack!(state)
    return true
end

function ASTInterpreter.execute_command(state, stack, ::Val{:when}, command)
    show(STDOUT, UInt64(icxx"$(current_task(current_session(timeline)))->tick_count();"))
    println(STDOUT); println(STDOUT)
    return false
end

using TerminalExtensions; using Gadfly; using Colors
const repl_theme = Gadfly.Theme(
    panel_fill=colorant"black", default_color=colorant"orange", major_label_color=colorant"white",
    minor_label_color=colorant"white", key_label_color=colorant"white", key_title_color=colorant"white",
    line_width=1mm
   )
eval(Gadfly,quote
   function writemime(io::IO, ::MIME"image/png", p::Plot)
       draw(PNG(io, Compose.default_graphic_width,
                Compose.default_graphic_height), p)
   end
end)

function collect_mark_ticks()
    map(unsafe_load,icxx"""
    std::vector<uint64_t> ticks;
    for(auto it : $timeline->reverse_exec_checkpoints) {
        ticks.push_back(it.first.ptr->key.ticks);
    }
    ticks;
    """)
end

function collect_mark_ticks(marks)
    ticks = UInt[]
    for mark in marks
        push!(ticks, icxx"$(mark.mark).ptr->proto.key.ticks;")
    end
    ticks
end

immutable TimelineEvent
    t::Int
    label::Symbol
end

start_time(timeline) = TimelineEvent(0, :start)
end_time(timeline) = TimelineEvent(RR.count_total_ticks(timeline), :end)
const timeline_default_colors = [colorant"orange",colorant"green",colorant"purple",colorant"blue"]
function timeline_layers(events; timeline_id = 0, pointfilterset=[])
    y = [timeline_id for _ in 1:length(events)]
    filterids = find(x->!(x.label in pointfilterset),events)
    [layer(x=map(x->x.t, events[filterids]),
        y=y[filterids],
        color = map(x->x.label, events[filterids]), Geom.point),
        layer(x=map(x->x.t, events),
            y=y, Geom.line)]
end

function plot_timeline(events, colors = timeline_default_colors; timeline_id = 0)
    display(
    plot(timeline_layers(events, timeline_id = timeline_id)...,
        repl_theme,Guide.xlabel("Time"),
        Guide.ylabel("Timeline"),
        Scale.color_discrete_manual(colors...))
    )
end

function ASTInterpreter.execute_command(state, stack, ::Val{:timeline}, command)
    me = TimelineEvent(UInt64(icxx"$(current_task(current_session(timeline)))->tick_count();"),
        :me)
    ticks = []
    contains(command, "internal") && (ticks = collect_mark_ticks())
    ticks = [TimelineEvent(t, :internal_tick) for t in ticks]
    explicit_ticks = [TimelineEvent(t, :explicit_tick) for t in collect_mark_ticks(mark_stack)]
    colors = [colorant"orange",colorant"green",colorant"purple"]
    (length(ticks) != 0) && unshift!(colors, colorant"blue")
    display(plot_timeline([ticks; start_time(timeline);
        me; end_time(timeline); explicit_ticks], colors))
    println("The timeline is intact.")
    return false
end

immutable AnnotatedMark
    mark
    annotation::String
end

const mark_stack = AnnotatedMark[]
function ASTInterpreter.execute_command(state, stack, ::Val{:mark}, command)
    push!(mark_stack,AnnotatedMark(icxx"$timeline->mark();",command[5:end]))
    return false
end

using JLD
"""
List all marks.
"""
function ASTInterpreter.execute_command(state, stack, ::Val{:marks}, command)
    subcmds = split(command," ")[2:end]
    if isempty(subcmds) || subcmds[1] == "list"
        for (i,mark) in enumerate(mark_stack)
            println("[$i] Mark (",mark.annotation,")")
        end
    elseif subcmds[1] == "save"
        annotations = map(x->x.annotation,mark_stack)
        marks = map(x->reinterpret(UInt8,[icxx"$(x.mark)->ptr.proto".data]),mark_stack)
        @save "marks.jld" annotations marks
    elseif subcmds[1] == "load"
        @load "marks.jld" annotations marks
        pms = map(x->cxxt"rr::ReplayTimeline::ProtoMark"{312}(reinterpret(NTuple{312,UInt8},x)[]),marks)
        println("Recreating marks. One moment please...")
        for (annotation, pm) in zip(annotations, pms)
            RR.seek(timeline, pm)
            push!(mark_stack,AnnotatedMark(icxx"$timeline->mark();",annotation))
        end
    else
        print_with_color(:red, "Unknown subcommand\n")
    end
    return false
end


using ProgressMeter
import RR: when
when() = when(current_session(timeline))
function ASTInterpreter.execute_command(state, stack, ::Val{:timejump}, command)
    subcmd = split(command)[2:end]
    if startswith(subcmd[1],"@")
        n = parse(Int, subcmd[1][2:end])
        icxx"$timeline->seek_to_mark($(mark_stack[n].mark));"
        icxx"$timeline->apply_breakpoints_and_watchpoints();"
        #global stack_remap = compute_remap()
        println("We have arrived.")
        update_stack!(state)
        return true
    end
    n = parse(Int, subcmd[1])
    me = when()
    target = me + n
    p = Progress(n, 1, "Time travel in progress (forwards)...", 50)
    function check_for_breakpoint(res)
        if icxx"$res.break_status.breakpoint_hit;"
            regs = icxx"$(current_task(current_session(timeline)))->regs();"
            if RR.process_lowlevel_conditionals(Location(timeline, Gallium.ip(regs)), regs)
                println("Interrupted by breakpoint.")
                update_stack!(state)
                return true
            end
        end
        false
    end
    while when() < target
        # Step past any breakpoints
        if RR.at_breakpoint(timeline)
            RR.emulate_single_step!(timeline, current_vm()) || RR.single_step!(timeline)
        end
        res = RR.step!(current_session(timeline), target)
        if icxx"$res.break_status.approaching_ticks_target;"
            break
        end
        check_for_breakpoint(res) && return true
        icxx"$timeline->maybe_add_reverse_exec_checkpoint(rr::ReplayTimeline::LOW_OVERHEAD);"
        now = when()
        now != me && ProgressMeter.update!(p, Int64(now) - Int(me))
    end
    while when() < target
        res = RR.single_step!(timeline)
        check_for_breakpoint(res) && return true
        now = when()
        now != me && ProgressMeter.update!(p, Int64(now) - Int(me))
    end
    icxx"$timeline->apply_breakpoints_and_watchpoints();"
    println("We have arrived.")
    update_stack!(state)
    return true
end

function prepare_remote_execution(timeline::RR.ReplayTimeline)
    session = icxx"$(current_session(timeline))->clone_diversion();"
end

function prepare_remote_execution(session::RR.ReplaySession)
    session = icxx"$session->clone_diversion();"
end
