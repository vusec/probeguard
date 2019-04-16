#ifndef CFI_H
#define CFI_H

#include <pass.h>
#if LLVM_VERSION >= 37
	#include <llvm/IR/Verifier.h>
	#include <llvm/IR/InstIterator.h>
	#define DEBUG_TYPE "cfi"
#else
	#include <llvm/Analysis/Verifier.h>
	#include <llvm/Support/InstIterator.h>
#endif

#define CFI_INIT_FUNC         		"cfi_shadow_init"
#define CFI_FWD_EDGE_CHECK_FUNC         "cfi_fwd_edge_check"
#define CFI_BK_EDGE_FUNC_ENTRY         	"cfi_bk_shadow_func_entry"
#define CFI_BK_EDGE_FUNC_EXIT         	"cfi_bk_shadow_func_exit"

using namespace llvm;

namespace llvm 
{

class CFIPass : public ModulePass {

  public:
	static char ID;

	CFIPass();

	virtual bool runOnModule(Module &M);

  private:
    Module *M;
    std::vector<CallInst*> insertedFwdChecks;
    std::vector<CallInst*> insertedBkCheckFuncEntries;
    std::vector<CallInst*> insertedBkCheckFuncExits;
    std::set<Function*> indirectlyCalledFuncs;
    std::set<CallInst*> indirectCallInsts;

    Function *cfiFwdEdgeCheckHook;
    Function *cfiBkEdgeFuncEntryHook;
    Function *cfiBkEdgeFuncExitHook;
    Function *cfiInitHook;

    void getHooks();
    bool insertCFIInitHook(Function *mainFunc);
    CallInst* insertFwdCFI(CallInst *CI, Instruction *nextInst);
    CallInst* insertBkFuncEntryHook(Instruction *nextInst);
    CallInst* insertBkFuncExitHook(ReturnInst *returnInst);
//    inline bool is_indirect_call(CallSite &CS);
    inline bool is_indirect_call(CallInst *CI);
    bool addFwdEdgeChecks();
    bool addBkEdgeChecks();
    void inlineTheChecks(std::vector<CallInst*> &insertedInsts);
};

}
#endif
