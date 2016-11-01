const IJulia = 1
using Arsenic
using PerfEvents
using Gallium
using ObjFileBase
using ProfileView

Profile.init(;n = 10^9, delay = 0.001)

eval(Gallium, :(allow_bad_unwind = false))
eval(Base, :(have_color = true))

buf = IOBuffer(readbytes(length(ARGS) >= 1 ? ARGS[1] : "perf.data"))
handle = PerfEvents.readmeta(buf)

attr = first(PerfEvents.AttrIterator(handle))

immutable ASID
  tid::Int32
  serial::Int32
end

# ASID -> modules
modules = Dict{ASID, Dict{Gallium.RemotePtr{Void}, Any}}()
kernel_modules = Dict{Gallium.RemotePtr{Void}, Any}()

samples = Dict{ASID, Vector{Any}}()

active_asids = Dict{Int32, ASID}()
last_serial = 0

num_samples = 0

PerfEvents.sorted_record_chunks(handle) do chunk
  @show chunk.chunk
  global last_serial
  global num_samples
  for record in chunk
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
        asid = haskey(active_asids, tid.tid) ? active_asids[tid.tid] : (active_asids[tid.tid] = ASID(tid.tid, last_serial += 1))
        !haskey(modules, asid) && (modules[asid] = Dict{RemotePtr{Void}, Any}())
        try
          h = ObjFileBase.readmeta(IOBuffer(open(Base.Mmap.mmap,fname)))
          modules[asid][start] = Gallium.GlibcDyldModules.mod_for_h(h, start, fname)
        catch
          println("Skipping $fname")
          continue
        end
      end
    elseif record.event_type == PerfEvents.PERF_RECORD_COMM &&
      (record.misc & PerfEvents.PERF_RECORD_MISC_COMM_EXEC) != 0
      tid, _ = record.record
      active_asids[tid.tid] = ASID(tid.tid, last_serial += 1)
    elseif record.event_type == PerfEvents.PERF_RECORD_SAMPLE
      sd = PerfEvents.extract_sample_kinds(record.record, attr)
      tid = sd[PerfEvents.PERF_SAMPLE_TID]
      asid = haskey(active_asids, tid.tid) ? active_asids[tid.tid] : (active_asids[tid.tid] = ASID(tid.tid, last_serial += 1))
      num_samples += 1
      push!(haskey(samples, asid) ? samples[asid] : (samples[asid] = Vector{Any}()), record)
    end
  end
end

@show num_samples

# Dump modules
for (asid, mods) in modules
  println("Modules for asid $asid:")
  sl = [(start, Gallium.compute_mod_size(mod), mod) for (start, mod) in mods]
  sort!(sl, by=x->x[1])
  last_end = 0
  for (start, length) in sl
      fname = ""
      start = UInt64(start)
      rep(x) = "0x$(hex(x,2sizeof(UInt64)))"
      if start > last_end
        print_with_color(:red, "$(rep(last_end)):$(rep(start))\n")
      end
      last_end = start+length
      print_with_color(:green, "$(rep(start)):$(rep(last_end)) ")
      println(fname)
  end
end

# Add kernel modules to every address space
for m in values(modules)
  isempty(m) && continue # Skip ones that don't have any userspasce modules
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


modules = Gallium.MultiASModules{ASID}((args...)->error("Unable to synthesize new AS"), modules);

# traces
for asid in keys(samples)
  isempty(samples[asid]) && continue
  (!haskey(modules.modules_by_as,asid) || isempty(modules.modules_by_as[asid])) && continue
  cache = Gallium.Unwinder.CFICache(100_000)
  traces = reduce(vcat,map(samples[asid]) do sample
    sd = PerfEvents.extract_sample_kinds(sample.record, attr)
    callchain = collect(filter(x->!PerfEvents.is_perf_context_ip(x) && x != 0,
        sd[PerfEvents.PERF_SAMPLE_CALLCHAIN]))
    if haskey(sd, PerfEvents.PERF_SAMPLE_STACK_USER) &&
        haskey(sd, PerfEvents.PERF_SAMPLE_REGS_USER) &&
        !isempty(sd[PerfEvents.PERF_SAMPLE_REGS_USER])
      RC = make_RC(sd, attr.attr)
      stack = sd[PerfEvents.PERF_SAMPLE_STACK_USER]
      stack_start_addr = Gallium.get_dwarf(RC, :rsp)
      session = Gallium.FakeMemorySession(
        Tuple{UInt64,Vector{UInt8}}[(stack_start_addr,stack)],
        Gallium.X86_64.X86_64Arch(), asid)
      ips = UInt64[]
      try
        Gallium.rec_backtrace(RC, session, modules, false, cache) do RC
            push!(ips,Gallium.ip(RC))
            return true
        end
        append!(callchain, ips)
      catch e
        PerfEvents.dump_sample_dict(STDOUT, sd)
        println("In asid $asid: $e")
      end
    end
    push!(callchain, 0)
    callchain
  end)
  @show traces
  fs = (ip =>
    StackFrame[StackFrame(Symbol(
      Arsenic.demangle(Gallium.symbolicate(modules.modules_by_as[asid], ip)[2])),Symbol(""),0,
      Nullable{LambdaInfo}(), true, false, ip)]
    for ip in filter(x->x != 0, unique(traces)))
  local lidict
  @profile lidict = Dict(fs)

  @show (asid, count(x->x==0, traces))
  #ProfileView.view(traces, lidict=lidict, C=true)
  ProfileView.svgwrite("trace-$(asid.tid).svg", traces, lidict, C=true)
  #ProfileView.svgwrite("out.svg", traces, lidict, C = true)
end

ProfileView.svgwrite("self-profile.svg")
