#include <pass.h>
#include <sfi/sfi.h>
#include <llvm/IR/InlineAsm.h>

/*
#include "pointsto.h"
*/

using namespace llvm;

#undef DEBUG_TYPE
#define DEBUG_TYPE "sfi"
#define sfiPassLog(M) DEBUG(dbgs() << "SFIPass: " << M << "\n")

static cl::opt<bool>
SFIInstrWrites("sfi-writes",
    cl::desc("Instrument memory writes."),
    cl::init(true), cl::NotHidden);

static cl::opt<bool>
SFIInstrReads("sfi-reads",
    cl::desc("Instrument memory reads."),
    cl::init(true), cl::NotHidden);

static cl::opt<bool>
SFIInstrIntrinsics("sfi-intrinsics",
    cl::desc("Instrument memory instrinsics (e.g., memcpy)."),
    cl::init(true), cl::NotHidden);

static cl::opt<bool>
SFIInstrLibcallArgs("sfi-libcall-args",
    cl::desc("Instrument arguments to library calls."),
    cl::init(false), cl::NotHidden);

static cl::opt<std::string>
SFIFuncSection("sfi-func-section",
    cl::desc("Skip functions in the specified section."),
    cl::init("sfi_functions"), cl::NotHidden);

static cl::opt<std::string>
SFIType("sfi-type",
    cl::desc("Instrumentation type."),
    cl::init("soft"), cl::NotHidden);

static cl::opt<std::string>
SFIPoints("sfi-points",
    cl::desc("Instrumentation points."),
    cl::init("memall"), cl::NotHidden);

static cl::opt<std::string>
SFITraceFile("sfi-trace",
    cl::desc("Counter record for dynamic points-to"),
    cl::init(""), cl::NotHidden);

static cl::opt<std::string>
SFILibfuncFile("sfi-libfuncs",
    cl::desc("Library functions to instrument in libfunc mode"),
    cl::init(""), cl::NotHidden);

static cl::opt<unsigned>
SFISimcryptSize("sfi-cryptsim-size",
    cl::desc("Size in bytes of the simulated crypt area"),
    cl::init(0), cl::NotHidden);

STATISTIC(NumSFIInstr, 	"Num of SFI hooks inserted.");

namespace {
  uint64_t _pCounter = 0;

  class SFIInstr {
  protected:
    Module *M;
    DataLayout *DL;
    InlineFunctionInfo *inliningInfo;
    Function *beginHook;
    Function *endHook;
    std::string typeStr;
    sfi_type_e type;
    sfi_points_e points;
  public:
    SFIInstr(Module *M, std::string typeStr, sfi_type_e type, sfi_points_e points) {
        this->M = M;
        this->DL=new DataLayout(M);
#if LLVM_VERSION >= 37
        this->inliningInfo = new InlineFunctionInfo(NULL);
#else
        this->inliningInfo = new InlineFunctionInfo(NULL, DL);
#endif
        this->typeStr=typeStr;
        this->type=type;
        this->points=points;
        this->beginHook=M->getFunction("sfi_" + typeStr + "_begin");
        this->endHook=M->getFunction("sfi_" + typeStr + "_end");
    }

    virtual void handleLoadInst(LoadInst *LI) {
        handleInst(LI);
    }

    virtual void handleStoreInst(StoreInst *SI) {
        handleInst(SI);
    }

    virtual void handleLoadIntrinsic(MemTransferInst *MTI) {
        handleInst(MTI);
    }

    virtual void handleStoreIntrinsic(MemIntrinsic *MI) {
        handleInst(MI);
    }

    virtual void handleCallInst(CallInst *CI) {
        handleInst(CI);
    }

    virtual void handleReturnInst(ReturnInst *RI) {
        handleInst(RI);
    }

    virtual void handleIndCallInst(Instruction *I) {
        handleInst(I);
    }

    virtual void handleInst(Instruction *I) {
        assert(0 && "Not implemented");
    }

    virtual void handleFunctionEntry(Function *F) { }


    /*
     * Inline calls to sfi_*_begin and sfi_*_end. This is done afterwards,
     * instead of immidiately, so the optimizeBB function can more easily
     * see (and optimize) region changes.
     */
    void inlineSfiCalls(Function *F)
    {
        // Inline all sfi_*_begin/end calls
        bool has_changed;
        do
        {
            has_changed = false;
            for (inst_iterator it = inst_begin(F), E = inst_end(F); it != E; ++it) {
                Instruction *I = &(*it);
                CallInst *CI = dyn_cast<CallInst>(I);
                if (!CI)
                    continue;
                Function *F = CI->getCalledFunction();
                if (!F)
                    continue;
                if (F->getName() == "sfi_" + typeStr + "_begin" ||
                    F->getName() == "sfi_" + typeStr + "_end")
                {
                    InlineFunction(CI, *inliningInfo);
                    has_changed = true;
                    break;
                }
            }
        } while (has_changed);
    }
    virtual void postInstrumentation()
    {
        Module::FunctionListType &functionList = M->getFunctionList();
        for (Module::iterator it = functionList.begin(); it != functionList.end(); ++it)
        {
            Function *F = it;
            if (!std::string(F->getSection()).compare(SFIFuncSection))
                continue;
            inlineSfiCalls(F);
        }
    }
  };

  class RecInstr : public SFIInstr {
    public:
        RecInstr(Module *M, std::string typeStr, sfi_type_e type, sfi_points_e points)
            : SFIInstr(M, typeStr, type, points) {
            }
        virtual void handleInst(Instruction *I){
            std::vector<Type*> FTParams;
            std::vector<Value*> callParams;
            IntegerType *immTy = IntegerType::get(M->getContext(), 64);

            FTParams.push_back(immTy);
            FunctionType *asmFTs = FunctionType::get(Type::getVoidTy(M->getContext()), FTParams, false);
            InlineAsm *IAs = InlineAsm::get(asmFTs, ".byte 0xeb, 0xb, 0xde, 0xad, 0xde, 0xad; \n\t"
                    "movq $0, %rax \n\t", "i", true);

            ConstantInt *immVal = ConstantInt::get(immTy, _pCounter, false);
            callParams.push_back(immVal);
            CallInst* CI = PassUtil::createCallInstruction(IAs, callParams, "", I);
            InlineFunction(CI, *inliningInfo);
	    NumSFIInstr++;
        }
  };

  class InstrumentCallInstr : public SFIInstr {
    private:
        Function *hook;
    public:
        InstrumentCallInstr(Module *M, std::string typeStr, sfi_type_e type, sfi_points_e points)
            : SFIInstr(M, typeStr, type, points) {
                hook = M->getFunction("sfi_before_libcall");
                assert(hook && "cannot find function sfi_before_libcall");
            }
        virtual void handleReturnInst(ReturnInst *RI) { }
        virtual void handleCallInst(CallInst *CI){
            Function *F = CI->getCalledFunction();
            if (!F || F->isIntrinsic())
                return;

            /* Only look at external libs, ie only calls to stubs which are
             * later linked in. */
            if (F->getBasicBlockList().size())
                return;
            sfiPassLog("Inserting libfunc annotation " << F->getName());

            IRBuilder<> b(CI);
            Value *funcname = b.CreateGlobalStringPtr(F->getName());
            b.CreateCall(hook, funcname);
        }
  };

  class SFIPtrInstr : public SFIInstr {
  protected:
     Value* maskPtr(Value *ptrVal, Instruction *I) {
         CastInst *castedPtr = new BitCastInst(ptrVal, beginHook->getFunctionType()->getParamType(0), "", I);
         std::vector<Value*> hookParams;
         hookParams.push_back(castedPtr);
         CallInst* CI = PassUtil::createCallInstruction(beginHook, hookParams, "", I);
         castedPtr = new BitCastInst(CI, ptrVal->getType(), "", I);
         InlineFunction(CI, *inliningInfo);
	 NumSFIInstr++;
         return castedPtr;
     }
  public:
     SFIPtrInstr(Module *M, std::string typeStr, sfi_type_e type, sfi_points_e points)
     : SFIInstr(M, typeStr, type, points) {
         assert(beginHook && "Cannot find begin hook!");
     }

     virtual void handleLoadInst(LoadInst *LI) {
         LI->setOperand(0, maskPtr(LI->getOperand(0), LI));
     }

     virtual void handleStoreInst(StoreInst *SI) {
         SI->setOperand(1, maskPtr(SI->getOperand(1), SI));
     }

     virtual void handleLoadIntrinsic(MemTransferInst *MTI) {
         MTI->setSource(maskPtr(MTI->getRawSource(), MTI));
     }

     virtual void handleStoreIntrinsic(MemIntrinsic *MI) {
         MI->setDest(maskPtr(MI->getRawDest(), MI));
     }

     virtual void handleCallInst(CallInst *CI) {
	if (!SFIInstrLibcallArgs)
	    return;
	Function *F = CI->getCalledFunction();
        if (F && F->isIntrinsic())
            return;

        /* Only look at external libs, ie only calls to stubs which are
         * later linked in. */
        if (F && F->getBasicBlockList().size())
            return;

	// If we are here, then, it is either an indirect call or a lib call.
        if (F)
		sfiPassLog("Inserting libcall arguments masking " << F->getName());
	else
		sfiPassLog("Inserting arg masking for indirect an call in func:" << CI->getParent()->getName());

	for (unsigned i=0; i < CI->getNumArgOperands(); i++) {
		Value *V = CI->getArgOperand(i);
		if (V->getType()->isPointerTy()) {
			CI->setArgOperand(i, maskPtr(V, CI)); 
		}
	}
     }

  };

    class SFIDataInstr : public SFIInstr {
    protected:
        Function *memsetHook;
        Function *memcpyHook;

        CastInst *mkCast(Value *V, Type *T, Instruction *I)
        {
            Type *VT = V->getType();
            //sfiPassLog("mkCast " << *VT << " -> " << *T);
            CastInst *CI = NULL;
            if (VT->canLosslesslyBitCastTo(T))
                CI = new BitCastInst(V, T, "", I);
            else if (VT->isPointerTy() && T->isIntegerTy())
                CI = new PtrToIntInst(V, T, "", I);
            else if (VT->isIntegerTy() && T->isPointerTy())
                CI = new IntToPtrInst(V, T, "", I);
            else if (VT->isIntegerTy() && T->isIntegerTy())
            {
                if (VT->getIntegerBitWidth() > T->getIntegerBitWidth())
                    CI = new TruncInst(V, T, "", I);
                else
                    CI = new ZExtInst(V, T, "", I);
            }
            else if ((VT->isFloatTy() && T->isIntegerTy(32)) ||
                     (VT->isDoubleTy() && T->isIntegerTy(64)) ||
                     (VT->isIntegerTy(32) && T->isFloatTy()) ||
                     (VT->isIntegerTy(64) && T->isDoubleTy()))
                CI = new BitCastInst(V, T, "", I);
            else if (VT->isFloatingPointTy() && T->isIntegerTy())
                CI = new FPToUIInst(V, T, "", I);
            else if (VT->isIntegerTy() && T->isFloatingPointTy())
                CI = new UIToFPInst(V, T, "", I);
            else if (VT->isFloatingPointTy() && T->isPointerTy())
            {
                Type *Ttmp = Type::getInt64Ty(M->getContext());
                CI = new FPToUIInst(V, Ttmp, "", I);
                CI = mkCast(CI, T, I);
            }
            else
            {
                sfiPassLog("Cannot cast " << *VT << " to " << *T);
                //assert(!"Cannot cast");
                CI = CastInst::Create(CastInst::getCastOpcode(V, false, T, false), V, T, "", I);
                errs() << *CI << "\n";
            }
            return CI;
        }

        Value* encryptData(Value *V, Value *Vptr, Instruction *I) {
            CastInst *castedV = mkCast(V, beginHook->getFunctionType()->getParamType(0), I);
            CastInst *castedVptr = mkCast(Vptr, beginHook->getFunctionType()->getParamType(1), I);
            std::vector<Value*> hookParams;
            hookParams.push_back(castedV);
            hookParams.push_back(castedVptr);

            CallInst* CI = PassUtil::createCallInstruction(beginHook, hookParams, "", I);

            CastInst *casted = mkCast(CI, V->getType(), I);
            //InlineFunction(CI, *inliningInfo);
            return casted;
        }

        /* Loads retaddr from stack, calls F on it and stores it back on stack.
         * This code is all inserted before instruction I.
         */
        void modifyRetAddr(Function *F, Instruction *I)
        {
            FunctionType *FTl = FunctionType::get(F->getFunctionType()->getParamType(0), false);
            InlineAsm *IAl = InlineAsm::get(FTl, "mov 8(%rbp), $0", "=r,~{dirflag},~{fpsr},~{flags}", true);
            std::vector<Value*> paramsl;
            CallInst *CIl = CallInst::Create(IAl, paramsl, "", I);

            FunctionType *FTa = FunctionType::get(F->getFunctionType()->getParamType(1), false);
            InlineAsm *IAa = InlineAsm::get(FTa, "lea 8(%rbp), $0", "=r,~{dirflag},~{fpsr},~{flags}", true);
            std::vector<Value*> paramsa;
            CallInst *CIa = CallInst::Create(IAa, paramsa, "", I);

            std::vector<Value*> params;
            params.push_back(CIl);
            params.push_back(CIa);
            CallInst* CI = PassUtil::createCallInstruction(F, params, "", I);

            std::vector<Type*> FTyParamss;
            FTyParamss.push_back(FTl->getReturnType());
            FunctionType *FTs = FunctionType::get(Type::getVoidTy(M->getContext()), FTyParamss, false);
            InlineAsm *IAs = InlineAsm::get(FTs, "mov $0, 8(%rbp)", "r,~{dirflag},~{fpsr},~{flags}", true);
            std::vector<Value*> paramss;
            paramss.push_back(CI);
            CallInst *CIs = CallInst::Create(IAs, paramss, "", I);
        }
    public:
        SFIDataInstr(Module *M, std::string typeStr, sfi_type_e type, sfi_points_e points)
        : SFIInstr(M, typeStr, type, points) {
            this->memsetHook = M->getFunction("sfi_" + typeStr + "_memset");
            this->memcpyHook = M->getFunction("sfi_" + typeStr + "_memcpy");
            assert(beginHook && "Cannot find begin hook!");
            assert(memsetHook && "Cannot find memset hook!");
            assert(memcpyHook && "Cannot find memcpy hook!");
        }

        virtual void handleLoadInst(LoadInst *LI) {
            Instruction *Itmp = NULL;
            Value *LIV = LI;

            /* Reads from data in the binary should not be decrypted. */
            Value *po = LI->getPointerOperand();
            GEPOperator *GEP = dyn_cast<GEPOperator>(po);
            if (GEP)
            {
                po = GEP->getPointerOperand();
                GlobalVariable *tGV = dyn_cast<GlobalVariable>(po);
                if (tGV && tGV->isConstant())
                    return;
            }

#if LLVM_VERSION >= 37
            std::vector<User*> users(LIV->user_begin(), LIV->user_end());
#else
            std::vector<User*> users(LIV->use_begin(), LIV->use_end());
#endif
            CastInst *castedLI = mkCast(LI, endHook->getFunctionType()->getParamType(0), Itmp);
            CastInst *castedP = mkCast(LI->getPointerOperand(), endHook->getFunctionType()->getParamType(1), Itmp);
            castedLI->insertAfter(LI);
            castedP->insertAfter(castedLI);
            std::vector<Value*> hookParams;
            hookParams.push_back(castedLI);
            hookParams.push_back(castedP);
            CallInst* CI = PassUtil::createCallInstruction(endHook, hookParams, "", Itmp);
            CI->insertAfter(castedP);
            CastInst *casted = mkCast(CI, LIV->getType(), Itmp);
            casted->insertAfter(CI);
            for (auto i = users.begin(), e = users.end(); i != e; i++)
            {
                User *U = *i;
                U->replaceUsesOfWith(LI, casted);
            }

            //InlineFunction(CI, *inliningInfo);
	    NumSFIInstr++;
        }

        virtual void handleStoreInst(StoreInst *SI) {
            SI->setOperand(0, encryptData(SI->getOperand(0), SI->getPointerOperand(), SI));
        }

        virtual void handleCallInst(CallInst *CI) {
            Function *func = CI->getCalledFunction();
            if (points != ICALL)
                return;
            if (func)
                return;
            /* Filter out edge case where ind call is bitcast of
              * constant function (eg clang does this with implicit
              * declarations of functions). Same for inline asm. */
            Value *val = CI->getCalledValue()->stripInBoundsOffsets();
            if (dyn_cast<Function>(val) || dyn_cast<InlineAsm>(val))
                return;
            //errs() << "Ind call " << *CI << "\n";

            CI->setOperand(0, encryptData(CI->getOperand(0), CI->getOperand(0), CI));
            //errs() << "replaced with " << *CI << "\n";
            //errs() << *CI->getParent() << "\n";
        }

        virtual void handleReturnInst(ReturnInst *RI) {
            modifyRetAddr(endHook, RI);
        }

        virtual void handleLoadIntrinsic(MemTransferInst *MTI) {
        }

        virtual void handleStoreIntrinsic(MemIntrinsic *MI) {
            MemSetInst *MS = dyn_cast<MemSetInst>(MI);
            MemTransferInst *MT = dyn_cast<MemTransferInst>(MI);
            MemMoveInst *MM = dyn_cast<MemMoveInst>(MI);
            //sfiPassLog("StoreIntr " << *MI);
            if (MM)
                return;
            assert(!MM && "Memmoves not supported");

            Type *t = MI->getRawDest()->getType();
            if (dyn_cast<SequentialType>(t))
                t = dyn_cast<SequentialType>(t)->getElementType();

            if (MS)
            {
                FunctionType *FTy = memsetHook->getFunctionType();

                CastInst *castedPtr = mkCast(MI->getRawDest(), FTy->getParamType(0), MI);
                CastInst *castedLen = mkCast(MI->getLength(), FTy->getParamType(1), MI);
                Constant *bitsize = ConstantInt::get(FTy->getParamType(2), DL->getTypeSizeInBits(t));
                CastInst *castedVal = mkCast(MS->getValue(), FTy->getParamType(3), MI);
                std::vector<Value*> hookParams;
                hookParams.push_back(castedPtr);
                hookParams.push_back(castedLen);
                hookParams.push_back(bitsize);
                hookParams.push_back(castedVal);

                CallInst* CI = PassUtil::createCallInstruction(memsetHook, hookParams, "", (Instruction*)NULL);
                CI->insertAfter(MI);
	    	NumSFIInstr++;
            }
            else if (MT)
            {
                FunctionType *FTy = memcpyHook->getFunctionType();

                CastInst *castedDst = mkCast(MI->getRawDest(), FTy->getParamType(0), MI);
                CastInst *castedSrc = mkCast(MT->getRawSource(), FTy->getParamType(1), MI);
                CastInst *castedLen = mkCast(MI->getLength(), FTy->getParamType(2), MI);
                Constant *bitsize = ConstantInt::get(FTy->getParamType(3), DL->getTypeSizeInBits(t));
                std::vector<Value*> hookParams;
                hookParams.push_back(castedDst);
                hookParams.push_back(castedSrc);
                hookParams.push_back(castedLen);
                hookParams.push_back(bitsize);

                CallInst* CI = PassUtil::createCallInstruction(memcpyHook, hookParams, "", (Instruction*)NULL);
                CI->insertAfter(MI);
	    	NumSFIInstr++;
            }

            /*
            std::vector<User*> users(MI->use_begin(), MI->use_end());
            for (auto i = users.begin(), e = users.end(); i != e; i++)
            {
                User *U = *i;
                U->replaceUsesOfWith(MI, MI->getRawDest());
            }
            MI->eraseFromParent();
            */
        }

        virtual void handleFunctionEntry(Function *F)
        {
            if (F->empty())
                return;
            Instruction *firstIns = &F->front().front();

            modifyRetAddr(beginHook, firstIns);
        }
    };

    class SFIDomainInstr : public SFIInstr {
    protected:
        void changeDomain(int domain, Instruction *I) {
            //sfiPassLog("Inserting domain change to " << domain << " @ " << *I << " @ " << I->getParent()->getParent()->getName());

            std::vector<Value*> hookParams;
            hookParams.push_back(ConstantInt::get(Type::getInt32Ty(M->getContext()), domain));
            CallInst* CI1 = PassUtil::createCallInstruction(beginHook, hookParams, "", I);
            //InlineFunction(CI, *inliningInfo);
	    NumSFIInstr++;

            Instruction *I2 = NULL;
            std::vector<Value*> hookParams2;
            CallInst* CI2 = PassUtil::createCallInstruction(endHook, hookParams2, "", I2);
            if (dyn_cast<ReturnInst>(I))
                CI2->insertAfter(CI1);
            else
                CI2->insertAfter(I);
            //InlineFunction(CI2, *inliningInfo);
	    NumSFIInstr++;
        }

        /*
         * Optimizes a basicblock by merging regions which have no mem accesses
         * or so inbetween, thus eliminating needless switching of regions.
         * Returns true if the function needs to be called again: when a
         * modification to a BB is made, it cannot continue iterating over that
         * BB.
         */
        bool optimizeBB(BasicBlock *B)
        {
            uint64_t lastmap = -1;
            bool inMap = false;
            bool noMemSinceUnmap = false;
            Instruction *lastUnmap = NULL;

            for (BasicBlock::iterator i = B->begin(), e = B->end(); i != e; i++)
            {
                Instruction *I = i;
                LoadInst *LI = dyn_cast<LoadInst>(I);
                StoreInst *SI = dyn_cast<StoreInst>(I);
                MemIntrinsic *MI = dyn_cast<MemIntrinsic>(I);
                CallInst *CI = dyn_cast<CallInst>(I);
                if (LI || SI || MI)
                    noMemSinceUnmap = false;
                else if (CI)
                {
                    Function *F = CI->getCalledFunction();
                    if (!F)
                        continue;
                    if (F->getName() == "sfi_" + typeStr + "_begin")
                    {
                        assert(!inMap);
                        ConstantInt *v = dyn_cast<ConstantInt>(CI->getOperand(0));
                        uint64_t domain = v->getSExtValue();
                        inMap = true;
                        if (noMemSinceUnmap && domain == lastmap)
                        {
                            //sfiPassLog("Duplicate domain mapping found to " << lastmap);
                            lastUnmap->eraseFromParent();
                            I->eraseFromParent();
                            return true;
                        }
                        lastmap = domain;
                    }
                    else if (F->getName() == "sfi_" + typeStr + "_end")
                    {
                        assert(inMap);
                        inMap = false;
                        noMemSinceUnmap = true;
                        lastUnmap = I;
                    }
                    else
                    {
                        noMemSinceUnmap = false;
                    }
                }
            }
            return false;
        }
    public:
        SFIDomainInstr(Module *M, std::string typeStr, sfi_type_e type, sfi_points_e points)
        : SFIInstr(M, typeStr, type, points) {
            assert(beginHook && "Cannot find begin hook!");
            assert(endHook && "Cannot find end hook!");
        }

        virtual void handleInst(Instruction *I) {
            if (CallInst *CI = dyn_cast<CallInst>(I)) {
                Function *func = CI->getCalledFunction();

                if (points == ICALL)
                {
                    if (func)
                        return;
                    /* Filter out edge case where ind call is bitcast of
                     * constant function (eg clang does this with implicit
                     * declarations of functions). Same for inline asm. */
                    Value *val = CI->getCalledValue()->stripInBoundsOffsets();
                    if (dyn_cast<Function>(val) || dyn_cast<InlineAsm>(val))
                        return;
                    //errs() << "Ind call " << *CI << "\n";

                }
                else
                {
                    //if (func == NULL)
                        //return;
                    if (func && func->isIntrinsic())
                        return;
                    if (func && func->getName().startswith("sfi_"))
                        return;
                }
            }
            //if (ReturnInst *RI = dyn_cast<ReturnInst>(I))
                //return;
            changeDomain(0, I);
        }

        virtual void postInstrumentation()
        {
            // Optimize domain-based instrumentation (eg vmfunc) by removing
            // unnecessary switches back and forth.
            Module::FunctionListType &functionList = M->getFunctionList();
            for (Module::iterator it = functionList.begin(); it != functionList.end(); ++it)
            {
                Function *F = it;
                if (!std::string(F->getSection()).compare(SFIFuncSection))
                    continue;

                for (Function::iterator bbit = F->begin(); bbit != F->end(); bbit++)
                {
                    BasicBlock *B = bbit;
                    while (optimizeBB(B));
                }
                inlineSfiCalls(F);
            }
        }
    };

  class SFIPass : public ModulePass {
  public:
    static char ID;
    sfi_points_e points;
    sfi_type_e type;
    SFIInstr *instr;
    std::set<uint64_t> trace_set;
    std::set<std::string> libfunc_set;
    /*
    StaticPointsTo *pointsTo;
    */

    SFIPass() : ModulePass(ID) {
        /*
        if (SFIPoints == "mem")
            this->pointsTo = new PointsToDSA();
        */
    }

    void getAnalysisUsage(AnalysisUsage &U) const {
        /*
        if (SFIPoints == "mem")
            pointsTo->addRequired(U);
        */
    }

    bool instrPointsToMemInst(Instruction *I) {
        return this->trace_set.find(_pCounter) != this->trace_set.end();
        /*
        assert(points == MEM && "Points-to data can only be used by SFIPoints=mem mode");
        return pointsTo->instrPointsToTracked(I);
        */
    }

    bool instrIsLibcall(Instruction *I) {
        CallInst *CI = dyn_cast<CallInst>(I);
        if (!CI)
            return false;
        Function *F = CI->getCalledFunction();
        if (!F)
            return false;
        if (this->libfunc_set.find(F->getName()) != this->libfunc_set.end())
        {
            //sfiPassLog("Instrumenting " << *I);
            return true;
        }
        return false;
    }

    bool instrMemInst(Instruction *I, bool read) {
        if (points == MEM && !instrPointsToMemInst(I))
             return false;
        if (points == MEM_ALL || points == MEM)
             return (read && SFIInstrReads) || (!read && SFIInstrWrites);
        return false;
    }

    bool instrCFInst(Instruction *I, bool fwd) {
        if (points == MEM && instrPointsToMemInst(I))
             return true;
        if (points == CALL_RET)
             return true;
        if (points == ICALL)
             return fwd;
        if (points == LIBCALL && instrIsLibcall(I))
            return true;
        return false;
    }

    void handleInst(Instruction *I) {
        bool read=true;
        bool fwd=true;

        LoadInst *LI = dyn_cast<LoadInst>(I);
        if (LI) {
            _pCounter++;
            if (instrMemInst(LI, read))
                instr->handleLoadInst(LI);
            return;
        }
        StoreInst *SI = dyn_cast<StoreInst>(I);
        if (SI) {
            _pCounter++;
            if (instrMemInst(SI, !read))
                instr->handleStoreInst(SI);
            return;
        }
        MemIntrinsic *MI = dyn_cast<MemIntrinsic>(I);
        if (MI) {
            MemTransferInst *MTI = dyn_cast<MemTransferInst>(MI);
            if (MTI && instrMemInst(MTI, read))
                instr->handleLoadIntrinsic(MTI);
            if (instrMemInst(MI, !read))
                instr->handleStoreIntrinsic(MI);
            return;
        }
        CallInst *CI = dyn_cast<CallInst>(I);
        if (CI) {
            if (instrCFInst(CI, fwd))
                instr->handleCallInst(CI);
        }
        ReturnInst *RI = dyn_cast<ReturnInst>(I);
        if (RI) {
            if (instrCFInst(RI, !fwd))
                instr->handleReturnInst(RI);
        }
    }

    static SFIInstr* getSFIInstr(Module *M, std::string typeStr, sfi_type_e type, sfi_points_e points) {
        SFIInstr *instr = NULL;
        switch(type) {
        case SOFT:
        case MPX:
            instr = new SFIPtrInstr(M, typeStr, type, points);
        break;

        case VMFUNC:
        case MPK:
        case CRYPT:
            instr = new SFIDomainInstr(M, typeStr, type, points);
        break;

        /*
        case CRYPT:
            instr = new SFIDataInstr(M, typeStr, type, points);
        break;
        */

        case REC:
            instr = new RecInstr(M, typeStr, type, points);
        break;

        case INSTRLIBCALL:
            instr = new InstrumentCallInstr(M, typeStr, type, points);
        break;

        default:
            assert(0 && "Not implemented!");
        break;
        }
        return instr;
    }

    bool getTraceSet() {
        FILE *pFile;
        uint64_t num;

        pFile = fopen(SFITraceFile.c_str(), "r");
        if (pFile == NULL) {
            errs() << "Cannot open tracefile " << SFITraceFile << "\n";
            return false;
        }
        while (fscanf(pFile, "%lx", &num) == 1)
            this->trace_set.insert(num);
        fclose(pFile);
        return true;
    }

    bool getLibfuncSet() {
        FILE *pFile;
        char *line = NULL;
        size_t len = 0;

        pFile = fopen(SFILibfuncFile.c_str(), "r");
        if (pFile == NULL) {
            errs() << "Cannot open libfunc file " << SFILibfuncFile << "\n";
            return false;
        }
        while (getline(&line, &len, pFile) != -1)
        {
            line[strlen(line)-1] = '\0';
            sfiPassLog("Read libfunc " << line);
            this->libfunc_set.insert(std::string(line));
        }
        free(line);
        fclose(pFile);
        return true;
    }

    virtual bool runOnModule(Module &M) {
        // Fix up type and points
        type = sfi_type_from_str(SFIType.c_str());
        if (type + 1 == 0) {
            errs() << "Invalid type!\n";
            exit(1);
        }
        points = sfi_points_from_str(SFIPoints.c_str());
        if (points + 1 == 0) {
            errs() << "Invalid points!\n";
            exit(1);
        }
        if (type == CRYPT)
            SFIInstrReads = SFIInstrWrites = true;
        if (type == REC)
            points = MEM_ALL;
        if (sfi_type_is_mem_all(type))
            points = MEM_ALL;

        if (points == MEM && !getTraceSet())
            points = MEM_ALL;

        if (points == LIBCALL && !getLibfuncSet())
        {
            errs() << !"Need valid libfunc file for points=libcall\n";
            exit(1);
        }

        // Fix up tracking variables
        GlobalVariable* sfiTypeGV = M.getNamedGlobal("sfi_type");
        if(!sfiTypeGV) {
            errs() << "Error: no sfi_type variable found\n";
            exit(1);
        }
        sfiTypeGV->setInitializer(ConstantInt::get(M.getContext(), APInt(32, type)));

        GlobalVariable* sfiPointsGV = M.getNamedGlobal("sfi_points");
        if(!sfiPointsGV) {
            errs() << "Error: no sfi_points variable found\n";
            exit(1);
        }
        sfiPointsGV->setInitializer(ConstantInt::get(M.getContext(), APInt(32, points)));

        GlobalVariable* sfiSimcryptSizeGV = M.getNamedGlobal("sfi_cryptsim_size");
        if(!sfiSimcryptSizeGV ) {
            errs() << "Error: no sfi_cryptsim_size variable found\n";
            exit(1);
        }
        sfiSimcryptSizeGV->setInitializer(ConstantInt::get(M.getContext(), APInt(64, SFISimcryptSize)));

        /*
        if (points == MEM)
        {
            this->pointsTo->init((ModulePass *)this, &M, SFIFuncSection);
            this->pointsTo->findTrackingNodes();
        }
        */


        // Instrumentation
        this->instr = getSFIInstr(&M, SFIType, type, points);
        Module::FunctionListType &functionList = M.getFunctionList();
        for (Module::iterator it = functionList.begin(); it != functionList.end(); ++it) {
            Function *F = it;
            if (!std::string(F->getSection()).compare(SFIFuncSection))
                continue;

            if (points == CALL_RET)
                instr->handleFunctionEntry(F);

            for (inst_iterator it2 = inst_begin(F), E = inst_end(F); it2 != E; ++it2) {
                Instruction *I = &(*it2);
                handleInst(I);
            }
            //errs() << "F " << *F;
        }

        // Optimize inserted instrumentation further if need be.
        this->instr->postInstrumentation();
        return false;
    }
  };

}

char SFIPass::ID = 0;
RegisterPass<SFIPass> MP("sfi", "SFI Pass");
