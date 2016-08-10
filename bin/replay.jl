#!/home/kfischer/julia/julia
using Gallium
using Arsenic
using RR
sess, modules = RR.replay(length(ARGS) >= 1 ? ARGS[1] : "")
if !isdefined(Base, :active_repl)
    term = Base.Terminals.TTYTerminal(get(ENV, "TERM", @static is_windows() ? "" : "dumb"), STDIN, STDOUT, STDERR)
    active_repl = Base.REPL.LineEditREPL(term, true)
    eval(Base,:(active_repl = $active_repl))
    eval(Base,:(have_color = true))
    eval(Base,:(is_interactive = true))
end
modules = Gallium.MultiASModules{RR.AddressSpaceUid}(Dict{RR.AddressSpaceUid, Any}()) do session
    imageh = Gallium.read_exe(session)
    Gallium.LazyJITModules(
        Gallium.GlibcDyldModules.load_library_map(session, imageh;
            current_ip = Gallium.ip(Gallium.getregs(current_task(session)))), 0)
end
ASTInterpreter.RunDebugREPL(Arsenic.compute_stack(modules, sess))
#exit(0)
