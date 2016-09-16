using Arsenic
using PerfEvents
using Gallium
using ObjFileBase
using ProfileView

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

# traces
for tid in keys(modules)
  traces = reduce(vcat,map(samples) do sample
    sd = PerfEvents.extract_sample_kinds(sample.record, attr)
    sd[PerfEvents.PERF_SAMPLE_TID].tid != tid && return UInt64[]
    push!(collect(filter(x->!PerfEvents.is_perf_context_ip(x) && x != 0,
        sd[PerfEvents.PERF_SAMPLE_CALLCHAIN])),0)
  end)

  lidict = Dict([ip =>
    StackFrame[StackFrame(Symbol(
      Arsenic.demangle(Gallium.symbolicate(modules[tid], ip)[2])),Symbol(""),0,
      Nullable{LambdaInfo}(), true, false, ip)]
    for ip in filter(x->x != 0, unique(traces))])

  @show (tid, count(x->x==0, traces))
  ProfileView.svgwrite("trace-$tid.svg", traces, lidict, C=true)
  #ProfileView.svgwrite("out.svg", traces, lidict, C = true)
end
