#ifndef FUNCTIONMOVER_CPP
#define FUNCTIONMOVER_CPP

#include "llvm/Transforms/Utils/ValueMapper.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/IR/DebugInfo.h"

using namespace llvm;
extern TargetMachine *jl_TargetMachine;

extern "C" {
    extern void jl_error(const char *str);
}

class FunctionMover2 : public ValueMaterializer
{
public:
    FunctionMover2(llvm::Module *dest, DICompileUnit *TargetCU = nullptr, bool copyDependencies = true) :
        ValueMaterializer(), TargetCU(TargetCU), VMap(), destModule(dest), copyDependencies(true)
    {
    }
    SmallVector<Metadata *, 16> NewSPs;
    DICompileUnit *TargetCU;
    ValueToValueMapTy VMap;
    llvm::Module *destModule;
    bool copyDependencies;
    llvm::Function *clone_llvm_function2(llvm::Function *toClone)
    {
        Function *NewF = Function::Create(toClone->getFunctionType(),
                                          toClone->getLinkage(),
                                          toClone->getName(),
                                          this->destModule);
        ClonedCodeInfo info;
        Function::arg_iterator DestI = NewF->arg_begin();
        for (Function::const_arg_iterator I = toClone->arg_begin(), E = toClone->arg_end(); I != E; ++I) {
            DestI->setName(I->getName());    // Copy the name over...
            this->VMap[&*I] = &*DestI++;        // Add mapping to VMap
        }

        // Necessary in case the function is self referential
        this->VMap[&*toClone] = NewF;

        SmallVector<ReturnInst*, 8> Returns;
        llvm::CloneFunctionInto(NewF,toClone,this->VMap,true,Returns,"",NULL,NULL,this);

        return NewF;
    }

    void finalize()
    {
    }

    virtual Value *materialize (Value *V)
    {
        Function *F = dyn_cast<Function>(V);
        if (F) {
            if (F->isIntrinsic()) {
                return destModule->getOrInsertFunction(F->getName(),F->getFunctionType());
            }
            if ((F->isDeclaration() || F->getParent() != destModule) && copyDependencies) {
                // Try to find the function in any of the modules known to MCJIT
                Function *shadow = NULL;
                if (shadow != NULL && !shadow->isDeclaration()) {
                    Function *oldF = destModule->getFunction(F->getName());
                    if (oldF)
                        return oldF;
                    return clone_llvm_function2(shadow);
                }
                else if (!F->isDeclaration()) {
                    return clone_llvm_function2(F);
                }
            }
            // Still a declaration and still in a different module
            if (F->isDeclaration() && F->getParent() != destModule) {
                // Create forward declaration in current module
                return destModule->getOrInsertFunction(F->getName(),F->getFunctionType());
            }
        }
        else if (isa<GlobalVariable>(V)) {
            GlobalVariable *GV = cast<GlobalVariable>(V);
            assert(GV != NULL);
            GlobalVariable *oldGV = destModule->getGlobalVariable(GV->getName());
            if (oldGV != NULL)
                return oldGV;
            GlobalVariable *newGV = new GlobalVariable(*destModule,
                GV->getType()->getElementType(),
                GV->isConstant(),
                GlobalVariable::ExternalLinkage,
                NULL,
                GV->getName());
            newGV->copyAttributesFrom(GV);
            if (GV->isDeclaration())
                return newGV;
            std::map<Value*, void *>::iterator it;
            if (GV->hasInitializer()) {
                Value *C = MapValue(GV->getInitializer(),VMap,RF_None,NULL,this);
                newGV->setInitializer(cast<Constant>(C));
            }
            return newGV;
        }
        return NULL;
    };
};

llvm::Value *MapFunction(llvm::Function *f, FunctionMover2 *mover)
{
    llvm::Value *ret = llvm::MapValue(f,mover->VMap,llvm::RF_None,nullptr,mover);
    mover->finalize();
    return ret;
}
#endif //FUNCTIONMOVER_CPP
