using DWARF
using DataStructures

"""
Show the five instructions surrounding ipoffset (two before, two after), with an
indicator which instruction is at ipoffset.
"""
function disasm_around_ip(io, insts, ipoffset; ipbase = 0, circular = true)
    Offset = 0
    ctx = DisAsmContext()
    const InstInfo = Tuple{Int,Bool,AbstractString}
    buf = circular ? CircularBuffer{InstInfo}(5) : Vector{InstInfo}()
    targetn = typemax(Int64)
    ipinstoffset = 0
    while Offset < sizeof(insts) && targetn > 0
        (Inst, InstSize) = getInstruction(insts, Offset; ctx = ctx)
        lastoffset = Offset
        Offset += InstSize
        iobuf = IOContext(IOBuffer(),:disasmctx=>ctx)
        print(iobuf, Inst)
        push!(buf, (lastoffset, mayAffectControlFlow(Inst,ctx),
            takebuf_string(iobuf.io)))
        targetn -= 1
        if circular && Offset > ipoffset && targetn > 2 # Two more
            ipinstoffset = lastoffset
            targetn = 2
        end
        free(Inst)
    end
    for i = 1:length(buf)
        off, branch, inst = buf[i]
        attarget = off == ipinstoffset
        p = string(attarget ? "=> " : "   ",
            "0x",hex(UInt64(ipbase+off),2sizeof(UInt64)),"<+",off,">:",
            inst)
        if attarget
            print_with_color(:yellow, io, p)
        elseif branch
            print_with_color(:red, io, p)
        else
            print(io, p)
        end
        println(io)
    end
end

# From DIDebug
cxx"""
#include "llvm/MC/SubtargetFeature.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/MC/MCInstrInfo.h"
using namespace llvm;
"""

immutable DisAsmContext
  MAI::pcpp"llvm::MCAsmInfo"
  MRI::pcpp"llvm::MCRegisterInfo"
  MII::pcpp"llvm::MCInstrInfo"
  MOFI::pcpp"llvm::MCObjectFileInfo"
  MCtx::pcpp"llvm::MCContext"
  MSTI::pcpp"llvm::MCSubtargetInfo"
  DisAsm::pcpp"llvm::MCDisassembler"
  MIP::pcpp"llvm::MCInstPrinter"
end

function DisAsmContext()
  TripleName = icxx"""
    llvm::InitializeNativeTargetAsmParser();
    llvm::InitializeNativeTargetDisassembler();

    // Get the host information
    std::string TripleName;
    if (TripleName.empty())
        TripleName = sys::getDefaultTargetTriple();
    TripleName;
  """

  TheTarget = icxx"""
    std::string err;
    TargetRegistry::lookupTarget($TripleName, err);
  """

  MAI  = icxx" $TheTarget->createMCAsmInfo(*$TheTarget->createMCRegInfo($TripleName),$TripleName); "
  MII  = icxx" $TheTarget->createMCInstrInfo(); "
  MRI  = icxx" $TheTarget->createMCRegInfo($TripleName); "
  MOFI = icxx" new MCObjectFileInfo; "
  MCtx = icxx" new MCContext($MAI, $MRI, $MOFI); "
  MSTI = icxx"""
    Triple TheTriple(Triple::normalize($TripleName));
    $MOFI->InitMCObjectFileInfo(TheTriple, Reloc::Default, CodeModel::Default, *$MCtx);
    SubtargetFeatures Features;
    Features.getDefaultSubtargetFeatures(TheTriple);
    std::string MCPU = sys::getHostCPUName();
    $TheTarget->createMCSubtargetInfo($TripleName, MCPU, Features.getString());
  """

  DisAsm = icxx" $TheTarget->createMCDisassembler(*$MSTI, *$MCtx); "

  MIP = icxx"""
      int AsmPrinterVariant = $MAI->getAssemblerDialect();
      $TheTarget->createMCInstPrinter(
          Triple($TripleName), AsmPrinterVariant, *$MAI, *$MII, *$MRI);
  """

  DisAsmContext(MAI, MRI, MII, MOFI, MCtx, MSTI, DisAsm, MIP)
end

function getInstruction(data::Vector{UInt8}, offset; ctx = DisAsmContext())
  Inst = icxx" new MCInst; "
  InstSize = icxx"""
    uint8_t *Base = (uint8_t*)$(convert(Ptr{Void},pointer(data)));
    uint64_t Total = $(sizeof(data));
    uint64_t Offset = $offset;
    uint64_t LoadAddress = 0;
    uint64_t InstSize;
    MCDisassembler::DecodeStatus S;
    S = $(ctx.DisAsm)->getInstruction(*$Inst, InstSize,
        ArrayRef<uint8_t>(Base+Offset, Total-Offset),
          LoadAddress + Offset, /*REMOVE*/ nulls(), nulls());
    switch (S) {
      case MCDisassembler::SoftFail:
      case MCDisassembler::Fail:
        delete $Inst;
        return (uint64_t)0;
      case MCDisassembler::Success:
        return InstSize;
    }
  """
  if InstSize == 0
    error("Invalid Instruction")
  end
  (Inst, InstSize)
end

function mayAffectControlFlow(inst, ctx)
  icxx"""
    $(ctx.MII)->get($inst->getOpcode()).mayAffectControlFlow(*$inst,*$(ctx.MRI));
  """
end

function mayBranch(inst, ctx)
  icxx"""
    $(ctx.MII)->get($inst->getOpcode()).isBranch();
  """
end

#=
function disassembleInstruction(f::Function, data::Vector{UInt8}, offset; ctx = DisAsmContext())
  icxx"""
    uint8_t *Base = (uint8_t*)$(convert(Ptr{Void},pointer(data)));
    uint64_t Total = $(sizeof(data));
    uint64_t Offset = $offset;
    uint64_t LoadAddress = 0;
    uint64_t InstSize;
    MCInst Inst;
    MCDisassembler::DecodeStatus S;
    S = $(ctx.DisAsm)->getInstruction(Inst, InstSize,
        ArrayRef<uint8_t>(Base+Offset, Total-Offset),
          LoadAddress + Offset, /*REMOVE*/ nulls(), nulls());
    switch (S) {
      case MCDisassembler::SoftFail:
      case MCDisassembler::Fail:
        return 0;
      case MCDisassembler::Success:
        :(f(icxx"&Inst;"); nothing);
        return InstSize;
    }
  """
end
=#

function Base.show(io::IO, Inst::pcpp"llvm::MCInst")
  ctx = isa(io,IOContext) && haskey(io, :disasmctx) ?
    get(io, :disasmctx, nothing) : DisAsmContext()
  print(io,String(icxx"""
  std::string O;
  raw_string_ostream OS(O);
  ($(ctx.MIP))->printInst(($Inst), OS, "", *$(ctx.MSTI));
  OS.flush();
  O;
  """))
end

free(x::pcpp"llvm::MCInst") = icxx" delete $x; "

function loclist2rangelist{T}(list::DWARF.LocationList{T})
  rangelist = Array(UnitRange{T},0)
  for entry in list.entries
    push!(rangelist, entry.first:entry.last)
  end
  rangelist
end

function rangelists(dbgs)
  seek(dbgs.oh, sectionoffset(dbgs.debug_loc))
  lists = Array(Vector{UnitRange{UInt64}},0)
  while position(dbgs.oh) < sectionoffset(dbgs.debug_loc)+sectionsize(dbgs.debug_loc)
      push!(lists,loclist2rangelist(read(dbgs.oh, DWARF.LocationList{UInt64})))
  end
  lists
end

function rangelist(dbgs, offset)
    seek(dbgs.oh, sectionoffset(dbgs.debug_loc)+offset)
    loclist2rangelist(read(dbgs.oh, DWARF.LocationList{UInt64}))
end

default_colors = [:blue, :red, :green, :yellow, :purple]
function disassemble2(data::Vector{UInt8}, instrange = nothing; io = STDOUT,
    ctx = DisAsmContext(), rloffset = 0, rangelists = [], colors = default_colors, offset = 0)
  Offset = instrange !== nothing ? first(instrange) - offset : 0
  while Offset < sizeof(data) && (instrange === nothing || Offset <= last(instrange)-offset)
    (Inst, InstSize) = getInstruction(data, Offset)
    print(io,"0x",hex(Offset+offset,2*sizeof(Offset)))
    print(io,":")
    str = repr(Inst; ctx = ctx)
    # This is bad, but I need things to line up
    lastt = findlast(str, '\t')
    rest = str[(lastt+1):end]
    print(io, str[1:lastt])
    if lastt == 1
      print(io,rest,'\t')
      rest = ""
    end
    printfield(io, rest, 25; align = :left)
    # Print applicable range lists
    for (i,rangelist) in enumerate(rangelists)
      print(io," ")
      found = false
      color = colors[mod1(i,length(colors))]
      for range in rangelist
        # If this is the start of a range
        if Offset+offset == first(range)+rloffset
          print_with_color(color,io,"x")
        # Or the last
        elseif last(range)+rloffset == Offset+offset+InstSize
          print_with_color(color,io,"x")
        elseif first(range)+rloffset <= Offset + offset < last(range)+rloffset
          print_with_color(color,io,"|")
        else
          continue
        end
        found = true
        break
      end
      found || print(io," ")
    end
    println(io)
    free(Inst)
    Inst = nothing
    Offset += InstSize
  end
end
function disassemble2(base, size; kwargs...)
    data = pointer_to_array(convert(Ptr{UInt8},base), (size,), false)
    disassemble2(data; kwargs...)
end

function extract_next_inst(insts::Vector{UInt8}, ctx = DisAsmContext())
  size = icxx"""
    uint64_t InstSize;
    uint8_t *Base = (uint8_t*)$(pointer(insts));
    uint64_t Total = $(sizeof(insts));
    uint64_t LoadAddress = 0;
    for (uint64_t Offset = 0; Offset < Total; Offset += InstSize)
    {
      MCInst Inst;
      MCDisassembler::DecodeStatus S;

      S = $(ctx.DisAsm)->getInstruction(Inst, InstSize,
          ArrayRef<uint8_t>(Base+Offset, Total-Offset),
            LoadAddress + Offset, /*REMOVE*/ nulls(), nulls());

      switch (S) {
      case MCDisassembler::SoftFail:
      case MCDisassembler::Fail:
        return (uint64_t)0;
      case MCDisassembler::Success:
          $(ctx.MIP)->printInst(&Inst, outs(), "", *$(ctx.MSTI));
        return InstSize;
      }
    }
    return (uint64_t)0;
  """
  insts[1:size]
end

function disassemble(insts::Vector{UInt8}, ctx = DisAsmContext())
  icxx"""
    uint64_t InstSize;
    uint8_t *Base = (uint8_t*)$(pointer(insts));
    uint64_t Total = $(sizeof(insts));
    uint64_t LoadAddress = 0;
    for (uint64_t Offset = 0; Offset < Total; Offset += InstSize)
    {
      MCInst Inst;
      MCDisassembler::DecodeStatus S;

      S = $(ctx.DisAsm)->getInstruction(Inst, InstSize,
          ArrayRef<uint8_t>(Base+Offset, Total-Offset),
            LoadAddress + Offset, /*REMOVE*/ nulls(), nulls());

      switch (S) {
      case MCDisassembler::SoftFail:
      case MCDisassembler::Fail:
        return false;
      case MCDisassembler::Success:
          $(ctx.MIP)->printInst(&Inst, outs(), "", *$(ctx.MSTI));
          outs() << "\n";
        break;
      }
    }
    return true;
  """
end
