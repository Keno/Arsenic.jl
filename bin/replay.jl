#!/home/kfischer/julia/julia
using Gallium
using Arsenic
using RR
using Cxx
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
    auxv = map(unsafe_load,icxx"$(current_task(session))->vm()->saved_auxv();")
    image_slide = Gallium.GlibcDyldModules.compute_entry_ptr(session, auxv) - imageh.file.header.e_entry
    glibcmodules = Gallium.GlibcDyldModules.load_library_map(session, imageh, image_slide;
        current_ip = Gallium.ip(Gallium.getregs(current_task(session))))
    # Check for the presence of wine or wine preloader symbols, and if present
    # also add the windows symbol source
    symtab = ObjFileBase.Symbols(ObjFileBase.handle(imageh))
    strtab = ObjFileBase.StrTab(symtab)
    idx = findfirst(symtab) do x
        name = String(ObjFileBase.symname(x, strtab = strtab))
        name == "wld_start" || name == "wine_init"
    end
    if idx != 0
        push!(glibcmodules.sources, Gallium.WinDyldModules.WinRemoteSource())
    end
    Gallium.LazyJITModules(glibcmodules, 0)
end
stack = Arsenic.compute_stack(modules, sess)
#ASTInterpreter.RunDebugREPL(stack)
#exit(0)
