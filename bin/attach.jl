#!/home/kfischer/julia/julia
using Gallium
using Arsenic
pid = parse(Int,ARGS[1])
sess, modules = Gallium.Ptrace.attach(pid)
if !isdefined(Base, :active_repl)
    term = Base.Terminals.TTYTerminal(get(ENV, "TERM", @static is_windows() ? "" : "dumb"), STDIN, STDOUT, STDERR)
    active_repl = Base.REPL.LineEditREPL(term, true)
    eval(Base,:(active_repl = $active_repl))
    eval(Base,:(have_color = true))
    eval(Base,:(is_interactive = true))
end
ASTInterpreter.RunDebugREPL(Arsenic.compute_stack(modules, sess))
exit(0)
