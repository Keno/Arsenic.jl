using Arsenic
using PerfEvents
using Gallium
using ObjFileBase
using ProfileView

eval(Gallium, :(allow_bad_unwind = false))

buf = IOBuffer(readbytes("perf.data"))
handle = PerfEvents.readmeta(buf)

attr = first(PerfEvents.AttrIterator(handle))

# tid -> modules
modules = Dict{UInt32, Dict{Gallium.RemotePtr{Void}, Any}}()
kernel_modules = Dict{Gallium.RemotePtr{Void}, Any}()

samples = Any[]

for record in PerfEvents.RecordIterator(handle)
  if record.event_type == PerfEvents.PERF_RECORD_MMAP || 
     record.event_type == PerfEvents.PERF_RECORD_MMAP2
    local tid, red, fname
    if record.event_type == PerfEvents.PERF_RECORD_MMAP
      tid, rec, fname = record.record
    else
      tid, rec, _, fname = record.record      
    end
    start = Gallium.RemotePtr{Void}(rec.start)
    if tid.pid == (-1 % UInt32)
      # Kernel Space
      if startswith(fname, "[kernel.kallsyms]")
        kernel_modules[start] = Gallium.LinuxKernelModule(rec.len)
      else
        # Dynamic kernel module - Skip for now
      end
    else
      contains(fname, "[vdso]") && continue
      @show fname
      !haskey(modules, tid.tid) && (modules[tid.tid] = Dict{RemotePtr{Void}, Any}())
      h = try
        ObjFileBase.readmeta(IOBuffer(open(Base.Mmap.mmap,fname)))
      catch
        println("Skipping $fname")
        continue
      end
      modules[tid.tid][start] = Gallium.GlibcDyldModules.mod_for_h(h, start, fname)
    end
  elseif record.event_type == PerfEvents.PERF_RECORD_SAMPLE
    push!(samples, record)
  end
end

# Add kernel modules to every address space
for m in values(modules)
  merge!(m, kernel_modules)
end

# Perf RC -> Gallium RC
function make_RC(sample_dict, attr)
    RC = Gallium.X86_64.BasicRegs()
    regs = sample_dict[PerfEvents.PERF_SAMPLE_REGS_USER]
    reg_idx = 1
    for i = 0:63
      if ((UInt64(1) << i) & attr.sample_regs_user) != 0
        dwarfno = Gallium.X86_64.inverse_dwarf[PerfEvents.perf_regs_numbering[i]]
        if dwarfno in Gallium.X86_64.basic_regs
            Gallium.set_dwarf!(RC, dwarfno, regs[reg_idx])
        end
        reg_idx += 1
      end
    end
    RC
end

modules = Gallium.MultiASModules{UInt32}((args...)->error("Unable to synthesize new AS"), modules);

# traces
for tid in keys(modules.modules_by_as)
  cache = Gallium.Unwinder.CFICache(100_000)
  traces = reduce(vcat,map(samples) do sample
    sd = PerfEvents.extract_sample_kinds(sample.record, attr)
    sd[PerfEvents.PERF_SAMPLE_TID].tid != tid && return UInt64[]
    callchain = collect(filter(x->!PerfEvents.is_perf_context_ip(x) && x != 0,
        sd[PerfEvents.PERF_SAMPLE_CALLCHAIN]))
    if haskey(sd, PerfEvents.PERF_SAMPLE_STACK_USER) &&
        haskey(sd, PerfEvents.PERF_SAMPLE_REGS_USER) &&
        !isempty(sd[PerfEvents.PERF_SAMPLE_REGS_USER])
      RC = make_RC(sd, attr)
      stack = sd[PerfEvents.PERF_SAMPLE_STACK_USER]
      stack_start_addr = Gallium.get_dwarf(RC, :rsp)
      session = Gallium.FakeMemorySession(
        Tuple{UInt64,Vector{UInt8}}[(stack_start_addr,stack)],
        Gallium.X86_64.X86_64Arch(), tid)
      ips = UInt64[]
      try
        Gallium.rec_backtrace(RC, session, modules, false, cache) do RC
            push!(ips,Gallium.ip(RC))
            return true
        end
        append!(callchain, ips)
      catch e
        @show e
      end
    end
    push!(callchain, 0)
    callchain
  end)

  lidict = Dict([ip =>
    StackFrame[StackFrame(Symbol(
      Arsenic.demangle(Gallium.symbolicate(modules.modules_by_as[tid], ip)[2])),Symbol(""),0,
      Nullable{LambdaInfo}(), true, false, ip)]
    for ip in filter(x->x != 0, unique(traces))])

  @show (tid, count(x->x==0, traces))
  ProfileView.view(traces, lidict=lidict, C=true)
  #ProfileView.svgwrite("trace-$tid.svg", traces, lidict, C=true)
  #ProfileView.svgwrite("out.svg", traces, lidict, C = true)
end
