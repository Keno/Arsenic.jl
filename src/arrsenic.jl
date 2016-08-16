using RR
using RR: current_session
using ASTInterpreter

"""
Attempt to reverse step until the entry to the current function.
"""
function ASTInterpreter.execute_command(state, stack::Union{Gallium.NativeStack,Gallium.CStackFrame}, ::Val{:rf}, command)
    timeline = state.top_interp.session
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
    target_tuid = RR.tuid(current_task(timeline))
    while true
        RR.reverse_continue!(timeline)
        if !(RR.tuid(current_task(timeline)) == target_tuid)
            continue
        end
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

"""
Reverse continue until a breakpoint is hit
"""
function ASTInterpreter.execute_command(state, stack::Union{Gallium.NativeStack,Gallium.CStackFrame}, ::Val{:rc}, command)
    timeline = state.top_interp.session
    RR.silence!(timeline)
    target_tgid = icxx"$(current_task(timeline))->tgid();"
    while true
        RR.reverse_continue!(timeline)
        if icxx"$(current_task(timeline))->tgid();" != target_tgid
            continue
        end
        break
    end
    update_stack!(state)
    return true    
end
    

function task_step_until_bkpt!(timeline::Union{RR.ReplayTimeline, RR.ReplaySession, RR.ReplayTask})
    target_tgid = icxx"$(current_task(timeline))->tgid();"
    while true
        Gallium.step_until_bkpt!(timeline)
        if icxx"$(current_task(timeline))->tgid();" != target_tgid
            continue
        end
        break
    end
end

function ASTInterpreter.execute_command(state, stack, ::Val{:when}, command)
    timeline = state.top_interp.session
    print(STDOUT, "Ticks: ")
    show(STDOUT, UInt64(icxx"$(current_task(current_session(timeline)))->tick_count();"))
    println(STDOUT);
    print(STDOUT, "Time: ", global_time(timeline))
    println(STDOUT)
    return false
end

using Colors
#=
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
=#

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
    timeline = state.top_interp.session
    push!(mark_stack,AnnotatedMark(icxx"$timeline->mark();",command[5:end]))
    return false
end

using JLD
"""
Manipulate marks.
"""
function ASTInterpreter.execute_command(state, stack, ::Val{:marks}, command)
    subcmds = split(command," ")[2:end]
    if isempty(subcmds) || subcmds[1] == "list"
        for (i,mark) in enumerate(mark_stack)
            println("[$i] Mark (",mark.annotation,")")
        end
    elseif subcmds[1] == "save"
        annotations = map(x->x.annotation,mark_stack)
        marks = map(x->reinterpret(UInt8,[icxx"$(x.mark).ptr->proto;".data]),mark_stack)
        @save "marks.jld" annotations marks
    elseif subcmds[1] == "load"
        timeline = state.top_interp.session
        @load "marks.jld" annotations marks
        pms = map(x->cxxt"rr::ReplayTimeline::ProtoMark"{312}(reinterpret(NTuple{312,UInt8},x)[]),marks)
        println("Recreating marks. One moment please...")
        for (annotation, pm) in zip(annotations, pms)
            RR.seek(timeline, pm)
            push!(mark_stack,AnnotatedMark(icxx"$timeline->mark();",annotation))
        end
        update_stack!(state)
        return true
    else
        print_with_color(:red, "Unknown subcommand\n")
    end
    return false
end


using ProgressMeter
import RR: when
when(timeline::RR.ReplayTimeline) = when(current_session(timeline))
global_time(timeline) = icxx"$(current_task(timeline))->trace_time();"
function ASTInterpreter.execute_command(state, stack, ::Val{:timejump}, command)
    timeline = state.top_interp.session
    subcmd = split(command)[2:end]
    local target_is_event = false
    if startswith(subcmd[1],"@")
        n = parse(Int, subcmd[1][2:end])
        icxx"$timeline->seek_to_mark($(mark_stack[n].mark));"
        icxx"$timeline->apply_breakpoints_and_watchpoints();"
        #global stack_remap = compute_remap()
        println("We have arrived.")
        update_stack!(state)
        return true
    elseif startswith(subcmd[1], "e")
        target = parse(Int, subcmd[1][2:end])
        me = global_time(timeline)
        n = target - me
        target_is_event = true
    else
        me = when(timeline)
        target = me + n
        n = parse(Int, subcmd[1])
    end
    p = Progress(n, 1, "Time travel in progress (forwards)...", 50)
    function check_for_breakpoint(res)
        if icxx"$res.break_status.breakpoint_hit == true;"
            regs = icxx"$(current_task(current_session(timeline)))->regs();"
            if RR.process_lowlevel_conditionals(Location(timeline, Gallium.ip(regs)), regs)
                println("Interrupted by breakpoint.")
                update_stack!(state)
                return true
            end
        end
        false
    end
    while (target_is_event ? global_time(timeline) : when(timeline)) < target
        # Step past any breakpoints
        if RR.at_breakpoint(timeline)
            RR.emulate_single_step!(timeline, current_vm()) || RR.single_step!(timeline)
        end
        res = RR.step!(current_session(timeline), target; target_is_event = target_is_event)
        if !target_is_event && icxx"$res.break_status.approaching_ticks_target;"
            break
        end
        check_for_breakpoint(res) && return true
        icxx"$timeline->maybe_add_reverse_exec_checkpoint(rr::ReplayTimeline::LOW_OVERHEAD);"
        now = (target_is_event ? global_time(timeline) : when(timeline))
        now != me && ProgressMeter.update!(p, Int64(now) - Int(me))
    end
    if !target_is_event
        while when() < target
            res = RR.single_step!(timeline)
            check_for_breakpoint(res) && return true
            now = when()
            now != me && ProgressMeter.update!(p, Int64(now) - Int(me))
        end
    end
    icxx"$timeline->apply_breakpoints_and_watchpoints();"
    println("We have arrived.")
    update_stack!(state)
    return true
end

function ASTInterpreter.execute_command(state, stack, ::Val{:maps}, command)
    timeline = state.top_interp.session
    pid = icxx"$(current_task(timeline))->real_tgid();"
    print(readstring("/proc/$pid/maps"))
    return false
end

function ASTInterpreter.execute_command(state, stack, ::Val{:map}, command)
    timeline = state.top_interp.session
    parts = split(command, ' ')
    if length(parts) > 1
        ip = parse(Int, parts[2], 16)
    else
        ip = (isa(stack, Gallium.NativeStack) ? stack.stack[end] : stack).ip
    end
    pid = icxx"$(current_task(timeline))->real_tgid();"
    println(first(filter(map->UInt64(ip) ∈ map[1], Gallium.Ptrace.MapsIterator("/proc/$pid/maps")))[3])
    return false
end

function ASTInterpreter.execute_command(state, stack, ::Val{:gdb}, command)
    icxx"rr::GdbServer::emergency_debug($(current_task(state.top_interp.session)));"
    false
end


function ASTInterpreter.execute_command(state, stack, ::Val{:execjump}, command)
    target_pid = parse(Int, split(command,' ')[2])
    timeline = state.top_interp.session
    println("Time travel in progress (forwards)... Please wait.")
    while icxx"$(current_task(timeline))->tgid();" != target_pid ||
            !icxx"$(current_task(timeline))->execed();"
        # Step past any breakpoints
        if RR.at_breakpoint(timeline)
            RR.emulate_single_step!(timeline, current_vm()) || RR.single_step!(timeline)
        end
        res = RR.step!(current_session(timeline))
        icxx"$timeline->maybe_add_reverse_exec_checkpoint(rr::ReplayTimeline::LOW_OVERHEAD);"
    end
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

function prepare_remote_execution(task::RR.ReplayTask)
    session = prepare_remote_execution(icxx"&$task->session();")
end

function compute_stack(modules, session::RR.ReplayTimeline)
    task = current_task(current_session(session))
    did_fixup, regs = RR.fixup_RC(task, icxx"$task->regs();")
    stack, RCs = Gallium.stackwalk(regs, task, modules, rich_c = true, collectRCs = true)
    if length(stack) != 0
        stack[end].stacktop = !did_fixup
    end
    Gallium.NativeStack(stack,RCs,modules,session)
end

function ASTInterpreter.execute_command(state, stack, ::Val{:task}, command)
    timeline = state.top_interp.session
    modules = state.top_interp.modules
    subcommand = split(command, " ")[2:end]
    if subcommand[1] == "list"
        icxx"""
            for (auto &task : $(current_session(timeline))->tasks())
                $:(println(IOContext(STDOUT,:modules=>modules),
                    icxx"return task.second;"); nothing);
        """
        println(STDOUT)
    elseif subcommand[1] == "select"
        n = parse(Int, subcommand[2])
        (n < 1 || n > icxx"$(current_session(timeline))->tasks().size();") &&
            (print_with_color(:red, STDERR, "Not a valid task"); return false)
        it = icxx"$(current_session(timeline))->tasks().begin();"
        while n > 1
            icxx"++$it;";
            n -= 1
        end
        update_stack!(state, icxx"$it->second;")
        return true
    end
    return false
end

function Gallium.retrieve_obj_data(session::Union{RR.ReplayTimeline, RR.ReplaySession, RR.ReplayTask}, modules, ip)
    run_function(session, modules, :jl_get_dobj_data, ip) do task
        regs = icxx"$task->regs();"
        @assert UInt(Gallium.ip(regs)) == 0
        array_ptr = Gallium.get_dwarf(regs, :rax)
        data_ptr = Gallium.load(task, RemotePtr{RemotePtr{UInt8}}(array_ptr))
        data_size = Gallium.load(task, RemotePtr{Csize_t}(array_ptr+8))
        Gallium.load(task, data_ptr, data_size)
    end
end

function Gallium.retrieve_section_start(session::Union{RR.ReplayTimeline, RR.ReplaySession, RR.ReplayTask}, modules, ip)
    isempty(Gallium.lookup_syms(session, modules, :jl_get_section_start)) &&
        return RemotePtr{Void}(0)
    run_function(session, modules, :jl_get_section_start, ip) do task
        regs = icxx"$task->regs();"
        (UInt(Gallium.ip(regs)) == 0) || return RemotePtr{Void}(0)
        addr = Gallium.get_dwarf(regs, :rax)
        RemotePtr{Void}(addr)
    end
end

Gallium.retrieve_obj_data(task::RR.ReplayTask, ip) =
    Gallium.retrieve_obj_data(icxx"&$task->session();", ip)

Gallium.retrieve_section_start(task::RR.ReplayTask, ip) =
    Gallium.retrieve_section_start(icxx"&$task->session();", ip)

## `rr ps` reimplementation


function find_exit_code(pid, events, current_event, tid_to_pid)
    for (i,e) in enumerate(events[current_event:end])
        # Get the view before this event
        current_tid_to_pid = versioned_view(tid_to_pid, current_event+i-2)
        if icxx"$e.type() == rr::TraceTaskEvent::EXIT;" &&
                current_tid_to_pid[icxx"$e.tid();"] == pid &&
                count(tid->tid==pid, values(current_tid_to_pid)) == 1
            status = icxx"$e.exit_status();"
            icxx"$status.type() == rr::WaitStatus::EXIT;" &&
                return icxx"$status.exit_code();"
            assert(icxx"$status.type() == rr::WaitStatus::FATAL_SIGNAL;")
            return icxx"-$status.fatal_sig();";
        end
    end
    return icxx"-SIGKILL;"
end

# TODO: Replace by proper implementation from DataStructures
type VersionedDict{Key,Value,Version}
    versions::Vector{Tuple{Version,Dict{Key,Value}}}
    current_version::Version
    VersionedDict() = new(Vector{Tuple{Version,Dict{Key,Value}}}(),0)
end
function advance!(dict::VersionedDict, new_version)
    if new_version < dict.current_version
        error("Versions may only be advanced forward")
    end
    dict.current_version = new_version
end
function Base.setindex!{K,V,VER}(dict::VersionedDict{K,V,VER}, value, key)
    if isempty(dict.versions) || dict.versions[end][1] != dict.current_version
        new_dict = isempty(dict.versions) ? Dict{K,V}() : copy(dict.versions[end][2])
        push!(dict.versions, (dict.current_version, new_dict))
    end
    setindex!(dict.versions[end][2], value, key)
    dict
end
Base.getindex(dict::VersionedDict, key) = dict.versions[end][2][key]
function Base.delete!(dict::VersionedDict, key)
    if isempty(dict.versions) || dict.versions[end][1] != dict.current_version
        new_dict = isempty(dict.versions) ? Dict{K,V}() : copy(dict.versions[end][2])
        push!(dict.versions, (dict.current_version, new_dict))
    end
    delete!(dict.versions[end][2], key)
end

function versioned_view(dict::VersionedDict, key)
    dict.versions[findlast(x->x[1]<=key, dict.versions)][2]
end

function update_tid_to_pid_map!(tid_to_pid, e)
    if icxx"$e.type() == rr::TraceTaskEvent::CLONE;"
        if icxx"($e.clone_flags() & CLONE_THREAD) != 0;"
            # thread clone. Record thread's pid.
            tid_to_pid[icxx"$e.tid();"] = tid_to_pid[icxx"$e.parent_tid();"];
        else
            # Some kind of fork. This task is its own pid.
            tid_to_pid[icxx"$e.tid();"] = icxx"$e.tid();"
        end
    elseif icxx"$e.type() == rr::TraceTaskEvent::EXIT;"
        delete!(tid_to_pid, icxx"$e.tid();")
    end
end

function find_cmd_line(pid, events, current_event, tid_to_pid)
    for (i,e) in enumerate(events[current_event:end])
        # Get the view before this event
        current_tid_to_pid = versioned_view(tid_to_pid, current_event+i-2)
        if icxx"$e.type() == rr::TraceTaskEvent::EXEC;" &&
                current_tid_to_pid[icxx"$e.tid();"] == pid
            return current_event + i -1
        elseif icxx"$e.type() == rr::TraceTaskEvent::EXIT;" &&
                current_tid_to_pid[icxx"$e.tid();"] == pid
            return -1;
        end
    end
    -1
end

"""
A reimplementation of `rr ps`
"""
function ASTInterpreter.execute_command(state, stack, ::Val{:ps}, command)
    events = cxxt"rr::TraceTaskEvent"[]
    timeline = state.top_interp.session
    session = current_session(timeline)
    trace = icxx"rr::TraceReader{$session->trace_reader()};"
    icxx"$trace.rewind();"
    while icxx"$trace.good();"
        push!(events, icxx"$trace.read_task_event();")
    end
    isempty(events) || icxx"$(first(events)).type() != rr::TraceTaskEvent::EXEC;" &&
        error("Invalid trace")

    # tid_to_pid is a versi
    tid_to_pid = VersionedDict{cxxt"pid_t",cxxt"pid_t",Int}()
    initial_tid = icxx"$(first(events)).tid();"
    tid_to_pid[initial_tid] = initial_tid;
    for (i, e) in enumerate(events)
        advance!(tid_to_pid, i)
        update_tid_to_pid_map!(tid_to_pid, e)
    end

    print("$initial_tid\t--\t")
    println(join(map(unsafe_string,collect(icxx"$(first(events)).cmd_line();")),' '))

    for (i, e) in enumerate(events)
        if icxx"$e.type() == rr::TraceTaskEvent::CLONE;" &&
                icxx"!($e.clone_flags() & CLONE_THREAD);"
            tid = icxx"$e.tid();"
            pid = versioned_view(tid_to_pid,i)[tid]
            parent_pid = versioned_view(tid_to_pid,i)[icxx"$e.parent_tid();"]
            print("$tid\t$parent_pid\t",find_exit_code(pid, events, i, tid_to_pid)," ")
            idx = find_cmd_line(pid, events, i, tid_to_pid)
            println(idx == -1 ? "(forked but did not exec)" :
                join(map(unsafe_string,collect(icxx"$(events[idx]).cmd_line();")),' '))
        end
    end
    return false
end

function ASTInterpreter.execute_command(state, stack::Union{Gallium.NativeStack,Gallium.CStackFrame}, ::Val{:rsi}, command)
    timeline = state.top_interp.session
    task = isa(stack, Gallium.NativeStack) ? stack.session : current_task(current_session(timeline))
    isa(task, RR.ReplayTimeline) && (task = current_task(current_session(task)))
    RR.reverse_single_step!(current_session(timeline),task,timeline)
    update_stack!(state)
    return true
end
