// Create hook insts before every call to malloc family and all indirect calls

#include <pass.h>
#if LLVM_VERSION >= 37
        #include <llvm/IR/Verifier.h>
        #include <llvm/IR/InstIterator.h>
        #define DEBUG_TYPE "rdefender"
#else
        #include <llvm/Analysis/Verifier.h>
        #include <llvm/Support/InstIterator.h>
#endif

#define RDEF_INIT_HOOK		"rdef_init"
using namespace llvm;

static cl::opt<std::string>
RdefFuncSectionOpt("rdefender-section",
    cl::desc("Skip functions in the specified section."),
    cl::init("rdefender_functions"), cl::NotHidden);

STATISTIC(NumRdefInitHooks, "Number of calls to rdef init hooks added.");

namespace llvm {

PASS_COMMON_INIT_ONCE();

class RDefenderPass : public ModulePass {

  public:
	static char ID;
	RDefenderPass();
	virtual bool runOnModule(Module &M);

  private:
	std::vector<std::string>  rdefInitTargets{"main"}; 
	Module *M;
	Function *rdefInitCallHook;
	std::set<Function *> initTargetFuncs;

	void getHooks();
	//CallInst* insertRdefInitHook(CallInst *CI);
	bool insertRdefInitHook(Function *F);
	CallInst* insertICallHook(CallInst *CI);
};

RDefenderPass::RDefenderPass() : ModulePass(RDefenderPass::ID) {}

void RDefenderPass::getHooks()
{
   Constant *hookFunc;

   hookFunc = M->getFunction(RDEF_INIT_HOOK);
   assert(hookFunc != NULL);
   rdefInitCallHook = cast<Function>(hookFunc);
   rdefInitCallHook->setCallingConv(CallingConv::Fast);
}
#if 0
CallInst* RDefenderPass::insertRdefInitHook(CallInst *CI)
{
  Function *calledFunction = CI->getCalledFunction();
  DEBUG(errs() << "Inserting rdef_init() hook before callinst to : " << calledFunction->getName() << "\n");

  std::vector<Value*> args;
  CallInst *insertedCI;
  insertedCI = PassUtil::createCallInstruction(rdefInitCallHook, args, "", CI);
  insertedCI->setCallingConv(CallingConv::Fast);
  return insertedCI;
}
#endif

bool RDefenderPass::insertRdefInitHook(Function *F)
{
  DEBUG(errs() << "Inserting rdef_init() hook at the beginning of : " << F->getName() << "\n");

  BasicBlock *firstBB = &F->getEntryBlock();
  assert(NULL != firstBB);
  Instruction *insertionPoint = firstBB->getFirstNonPHI(); 
  assert(NULL != insertionPoint);

  std::vector<Value*> args;
  CallInst *insertedCI;
  insertedCI = PassUtil::createCallInstruction(rdefInitCallHook, args, "", insertionPoint);
  assert(insertedCI != NULL);
  insertedCI->setCallingConv(CallingConv::Fast);
  return true;
}

bool RDefenderPass::runOnModule(Module &M)
{
   bool ret = false;
   this->M = &M;

   getHooks();
   DEBUG(errs() << "Got hook.\n");

   for(unsigned i=0; i < rdefInitTargets.size(); i++) {
	Function *F = M.getFunction(rdefInitTargets[i]);
	if (NULL != F) {
	   initTargetFuncs.insert(F);
	   ret = insertRdefInitHook(F);	
	}
   }
   DEBUG(errs() << "Target functions for inserting rdef_init()s loaded. size: " << initTargetFuncs.size() << "\n");

return ret;

#if 0
   for (Module::iterator it = M.getFunctionList().begin(); it != M.getFunctionList().end(); ++it) {
	Function *F = &(*it);
	if (!std::string(F->getSection()).compare(RdefFuncSectionOpt)) {

                        continue;
        }
        for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; I++) {
             Instruction *instr = &(*I);
             CallInst *CI = dyn_cast<CallInst>(instr);
	     if (NULL != CI) {
		Function *calledFunc = CI->getCalledFunction();
 		if (0 != initTargetFuncs.count(calledFunc)) {
		   if(NULL != insertRdefInitHook(CI)) {
			NumRdefInitHooks++;
			ret = true;
			DEBUG(errs() << "Inserted rdef_init() hook for " << calledFunc->getName() << "\n");
		   }
		}
	     }
	 }
   }
   return ret;
#endif
}

char RDefenderPass::ID = 0;
RegisterPass<RDefenderPass> RP("rdefender", "RDefender Pass - for reactive defense");

}
