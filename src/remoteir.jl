# Functionality for running LLVM IR remotely

using Cxx
cxx"""
    #define NDEBUG
    #include "llvm/ExecutionEngine/RuntimeDyld.h"
    #include "llvm/ExecutionEngine/Orc/ObjectLinkingLayer.h"
    #include "llvm/ExecutionEngine/Orc/IRCompileLayer.h"
    #include "llvm/ExecutionEngine/Orc/LambdaResolver.h"
    #include "llvm/Support/Memory.h"
    #include "llvm/IR/LegacyPassManager.h"
    #include "llvm/ExecutionEngine/ObjectMemoryBuffer.h"
"""

# Remote memory manager (from lli)
cxx"""
class GalliumCallbacks {
public:
    uint64_t allocateMem(uint32_t kind, uint64_t Size, uint64_t Align);
    void writeMem(uint64_t remote, uint8_t *local, size_t size);

public:
    void *session;
};
"""

cxx"""
/// Remote memory manager.
class RCMemoryManager : public llvm::RuntimeDyld::MemoryManager {
public:
  RCMemoryManager(GalliumCallbacks &&Client)
      : Client(Client) {
  }

  RCMemoryManager(RCMemoryManager &&Other)
      : Client(Other.Client),
        Unmapped(std::move(Other.Unmapped)),
        Unfinalized(std::move(Other.Unfinalized)) {}

  RCMemoryManager &operator=(RCMemoryManager &&Other) {
    Client = std::move(Other.Client);
    Unmapped = std::move(Other.Unmapped);
    Unfinalized = std::move(Other.Unfinalized);
    return *this;
  }

  ~RCMemoryManager() override {}

  uint8_t *allocateCodeSection(uintptr_t Size, unsigned Alignment,
                               unsigned SectionID,
                               StringRef SectionName) override {
    Unmapped.CodeAllocs.emplace_back(Size, Alignment);
    uint8_t *Alloc = reinterpret_cast<uint8_t *>(
        Unmapped.CodeAllocs.back().getLocalAddress());
    return Alloc;
  }

  uint8_t *allocateDataSection(uintptr_t Size, unsigned Alignment,
                               unsigned SectionID, StringRef SectionName,
                               bool IsReadOnly) override {
    std::vector<Alloc> &Allocs = IsReadOnly ?
        Unmapped.RODataAllocs : Unmapped.RWDataAllocs;
    Allocs.emplace_back(Size, Alignment);
    uint8_t *Alloc = reinterpret_cast<uint8_t *>(
        Allocs.back().getLocalAddress());
    return Alloc;
  }

  void registerEHFrames(uint8_t *Addr, uint64_t LoadAddr,
                        size_t Size) override {
    UnfinalizedEHFrames.push_back(
        std::make_pair(LoadAddr, static_cast<uint32_t>(Size)));
  }

  void deregisterEHFrames(uint8_t *Addr, uint64_t LoadAddr,
                          size_t Size) override {
  }

  virtual void notifyObjectLoaded(llvm::RuntimeDyld &Dyld,
                          const llvm::object::ObjectFile &Obj) override {
    std::vector<Alloc> *AllocLists[3] =
        {&Unmapped.CodeAllocs, &Unmapped.RODataAllocs, &Unmapped.RWDataAllocs};
    uint32_t AllocKinds[3] =
        {llvm::sys::Memory::MF_EXEC|llvm::sys::Memory::MF_READ,
         llvm::sys::Memory::MF_READ,
         llvm::sys::Memory::MF_READ|llvm::sys::Memory::MF_WRITE};
        
    for (int i = 0; i < 3; ++i) {
        std::vector<Alloc> &ObjAllocs = *AllocLists[i];
        // First count how much space we need
        uint64_t Addr = 0;
        for (auto &Alloc : ObjAllocs) {
            Addr = llvm::alignTo(Addr, Alloc.getAlign()) + Alloc.getSize();
        }
                
        // Now ask the remote to allocate this memory
        Addr = ObjAllocs.begin() == ObjAllocs.end() ? 0 :
            Client.allocateMem(AllocKinds[i],
            Addr, ObjAllocs.begin()->getAlign());
        
        // Now remap each section
        for (auto &Alloc : ObjAllocs) {
            Addr = llvm::alignTo(Addr, Alloc.getAlign());
            Dyld.mapSectionAddress(Alloc.getLocalAddress(), Addr);
            Alloc.setRemoteAddress(Addr);
            Addr += Alloc.getSize();
        }
    }
    Unfinalized.push_back(std::move(Unmapped));
  }

  bool finalizeMemory(std::string *ErrMsg = nullptr) override {
    for (auto &ObjAllocs : Unfinalized)
      for (auto Allocs : {&ObjAllocs.CodeAllocs, &ObjAllocs.RODataAllocs, &ObjAllocs.RWDataAllocs})
        for (auto &Alloc : *Allocs)
          Client.writeMem(Alloc.getRemoteAddress(),
                                  (uint8_t*)Alloc.getLocalAddress(), Alloc.getSize());
    Unfinalized.clear();
    
    // TODO: Maybe handle this
    UnfinalizedEHFrames.clear();
  
    return false;
  }

private:
  class Alloc {
  public:
    Alloc(uint64_t Size, unsigned Align)
        : Size(Size), Align(Align), Contents(new char[Size + Align - 1]) {}

    Alloc(Alloc &&Other)
        : Size(std::move(Other.Size)), Align(std::move(Other.Align)),
          Contents(std::move(Other.Contents)),
          RemoteAddr(std::move(Other.RemoteAddr)) {}

    Alloc &operator=(Alloc &&Other) {
      Size = std::move(Other.Size);
      Align = std::move(Other.Align);
      Contents = std::move(Other.Contents);
      RemoteAddr = std::move(Other.RemoteAddr);
      return *this;
    }

    uint64_t getSize() const { return Size; }

    unsigned getAlign() const { return Align; }

    char *getLocalAddress() const {
      uintptr_t LocalAddr = reinterpret_cast<uintptr_t>(Contents.get());
      LocalAddr = llvm::alignTo(LocalAddr, Align);
      return reinterpret_cast<char *>(LocalAddr);
    }

    void setRemoteAddress(uint64_t RemoteAddr) {
      this->RemoteAddr = RemoteAddr;
    }

    uint64_t getRemoteAddress() const { return RemoteAddr; }

  private:
    uint64_t Size;
    unsigned Align;
    std::unique_ptr<char[]> Contents;
    uint64_t RemoteAddr = 0;
  };

  struct ObjectAllocs {
    ObjectAllocs() = default;

    ObjectAllocs(ObjectAllocs &&Other)
        : CodeAllocs(std::move(Other.CodeAllocs)),
          RODataAllocs(std::move(Other.RODataAllocs)),
          RWDataAllocs(std::move(Other.RWDataAllocs)) {}

    ObjectAllocs &operator=(ObjectAllocs &&Other) {
      CodeAllocs = std::move(Other.CodeAllocs);
      RODataAllocs = std::move(Other.RODataAllocs);
      RWDataAllocs = std::move(Other.RWDataAllocs);
      return *this;
    }
    std::vector<Alloc> CodeAllocs, RODataAllocs, RWDataAllocs;
  };

  GalliumCallbacks Client;
  ObjectAllocs Unmapped;
  std::vector<ObjectAllocs> Unfinalized;
  std::vector<std::pair<uint64_t, uint32_t>> UnfinalizedEHFrames;
};
"""

cxx"""
  class RemoteJIT {
    typedef llvm::orc::ObjectLinkingLayer<> ObjLayerT;
    typedef llvm::orc::IRCompileLayer<ObjLayerT> CompileLayerT;
    typedef CompileLayerT::ModuleSetHandleT ModuleHandleT;
    typedef llvm::object::OwningBinary<llvm::object::ObjectFile> OwningObj;
  public:
    
    RemoteJIT(llvm::TargetMachine &TM, llvm::RuntimeDyld::MemoryManager *MemMgr)
      : TM(TM),
        DL(TM.createDataLayout()),
        ObjStream(ObjBufferSV),
        MemMgr(MemMgr),
        CompileLayer(
          ObjectLayer,
          [this](llvm::Module &M) {
              PM.run(M);
              std::unique_ptr<llvm::MemoryBuffer> ObjBuffer(
                  new llvm::ObjectMemoryBuffer(std::move(ObjBufferSV)));
              auto Obj = llvm::object::ObjectFile::createObjectFile(ObjBuffer->getMemBufferRef());
              return OwningObj(std::move(*Obj), std::move(ObjBuffer));
           })
        {
           if (TM.addPassesToEmitMC(PM, Ctx, ObjStream))
              llvm_unreachable("Target does not support MC emission.");
        }

        ModuleHandleT addModule(std::unique_ptr<llvm::Module> M)
        {
            // We need a memory manager to allocate memory and resolve symbols for this
            // new module. Create one that resolves symbols by looking back into the JIT.
            auto Resolver = llvm::orc::createLambdaResolver(
              [&](const std::string &Name) {
                // TODO: consider moving the FunctionMover resolver here
                // Step 0: ObjectLinkingLayer has checked whether it is in the current module
                // Step 1: See if it's something known to the ExecutionEngine
                if (auto Sym = findSymbol(Name, true))
                  return llvm::RuntimeDyld::SymbolInfo(Sym.getAddress(),
                                                 Sym.getFlags());
                // Step 2: Search the program symbols
                uint64_t addr = $:(lookup_external_symbol(modules, unsafe_string(icxx"return Name.c_str();"))::UInt64);
                if (addr)
                    return llvm::RuntimeDyld::SymbolInfo(addr, llvm::JITSymbolFlags::Exported);
                // Return failure code
                return llvm::RuntimeDyld::SymbolInfo(nullptr);
              },
              [](const std::string &S) { return nullptr; }
            );
            llvm::SmallVector<std::unique_ptr<llvm::Module>,1> Ms;
            Ms.push_back(std::move(M));
            auto modset = CompileLayer.addModuleSet(std::move(Ms), MemMgr,
                                                    std::move(Resolver));
            // Force LLVM to emit the module so that we can register the symbols
            // in our lookup table.
            CompileLayer.emitAndFinalize(modset);
            return modset;
        }
        
        llvm::orc::JITSymbol findSymbol(const std::string &Name, bool ExportedSymbolsOnly=true)
        {
          void *Addr = nullptr;
          // Search all previously emitted symbols
          return CompileLayer.findSymbol(Name, ExportedSymbolsOnly);
        }
        
        private:
        llvm::TargetMachine &TM;
        const llvm::DataLayout DL;
        llvm::legacy::PassManager PM;
        llvm::SmallVector<char, 4096> ObjBufferSV;
        llvm::raw_svector_ostream ObjStream;
        llvm::RuntimeDyld::MemoryManager *MemMgr;
        llvm::MCContext *Ctx;
        ObjLayerT ObjectLayer;
        CompileLayerT CompileLayer;
  };

"""
