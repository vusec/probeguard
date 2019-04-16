// Create hook insts before every call to malloc family and all indirect calls

#include <pass.h>
#if LLVM_VERSION >= 37
        #include <llvm/IR/Verifier.h>
        #include <llvm/IR/InstIterator.h>
        #define DEBUG_TYPE "allocguard"
#else
        #include <llvm/Analysis/Verifier.h>
        #include <llvm/Support/InstIterator.h>
#endif

#define AG_ALLOC_CALL_HOOK	"allocguard_call_check"
#define AG_CALLOC_HOOK		"allocguard_calloc_call_check"
#define AG_BRK_HOOK		"allocguard_brk_call_check"
#define AG_ICALL_HOOK		"allocguard_icall_check"
#define RDEF_SIZE_LIKE_ARGS_GV	"size_like_args"
using namespace llvm;

static cl::opt<std::string>
AGFuncSectionOpt("allocguard-section",
    cl::desc("Skip functions in the specified section."),
    cl::init("allocguard_functions"), cl::NotHidden);

STATISTIC(NumAllocHooks, "Number of calls to malloc family of functions found and hooked.");
STATISTIC(NumICallHooks, "Number of indirectly called functions found and hooked.");

namespace llvm {

PASS_COMMON_INIT_ONCE();

class AllocGuardPass : public ModulePass {

  public:
	static char ID;
	AllocGuardPass();
	virtual bool runOnModule(Module &M);

  private:
	std::map<std::string, unsigned>  allocFuncsInfo{{"malloc",	0}, {"calloc",	1}, 
							{"realloc",	1}, {"valloc",	0},
							{"brk", 	0}, {"sbrk",	0},
							{"memalign",	1}, {"posix_memalign", 2},
							{"mmap", 	1}, {"mmap64", 	1},
							{"mremap",	2}};
	Module *M;
	Function *agAllocCallHook;
	Function *agCallocHook;
	Function *agBrkHook;
	Function *agICallHook;
	std::set<Function *> allocFuncs;

	void getHooks();
	bool is_indirect_call(CallInst *CI);
	CallInst* insertAllocHook(CallInst *CI);
	CallInst* insertICallHook(CallInst *CI);
};

AllocGuardPass::AllocGuardPass() : ModulePass(AllocGuardPass::ID) {}

inline bool AllocGuardPass::is_indirect_call(CallInst *CI)
{
        Function *target = CI->getCalledFunction();
        if (target == NULL) {
                Value *calledValue = CI->getCalledValue();
                if (NULL == dyn_cast<InlineAsm>(calledValue)) {
                        return true;
                }
        }
        return false;
}

void AllocGuardPass::getHooks()
{
   Constant *hookFunc;

   hookFunc = M->getFunction(AG_ALLOC_CALL_HOOK);
   assert(hookFunc != NULL);
   agAllocCallHook = cast<Function>(hookFunc);
   agAllocCallHook->setCallingConv(CallingConv::Fast);
   
   hookFunc = M->getFunction(AG_CALLOC_HOOK);
   assert(hookFunc != NULL);
   agCallocHook = cast<Function>(hookFunc);
   agCallocHook->setCallingConv(CallingConv::Fast);
   
   hookFunc = M->getFunction(AG_BRK_HOOK);
   assert(hookFunc != NULL);
   agBrkHook = cast<Function>(hookFunc);
   agBrkHook->setCallingConv(CallingConv::Fast);
   
   hookFunc = M->getFunction(AG_ICALL_HOOK);
   assert(hookFunc != NULL);
   agICallHook = cast<Function>(hookFunc);
   agICallHook->setCallingConv(CallingConv::Fast);
}

CallInst* AllocGuardPass::insertICallHook(CallInst *CI)
{
  IntegerType *i64Type = IntegerType::get(this->M->getContext(), 64);
  PointerType* voidPtrTy = PointerType::get(IntegerType::get(this->M->getContext(), 8), 0);
  std::vector<Value *> args;

  Value *calledValue =  CI->getCalledValue();
  assert(NULL != calledValue);
  assert(calledValue->getType()->isPointerTy());
  CastInst *castedPtr = CastInst::CreatePointerCast(calledValue, voidPtrTy, "voidPtrCast", CI);
  args.push_back(castedPtr);

  // What about indirect calls to brk()? Argument is not int type?  --> Currently we dont handle it
  CallSite CS = PassUtil::getCallSiteFromInstruction(CI);
  std::vector<Value*> sizeLikeArgs;
  unsigned num_sizes = 0;
  for (CallSite::arg_iterator IA = CS.arg_begin(), EA = CS.arg_end(); IA != EA; IA++) {
     Value *arg = dyn_cast<Value>(*IA);
     assert(NULL != arg);
     if (arg->getType()->isIntegerTy()) {
	CastInst *castedArg = CastInst::CreateIntegerCast(arg, i64Type, false, "ArgCast", CI);
	sizeLikeArgs.push_back(castedArg);
	num_sizes++;
     }
  }
  
  ConstantInt *zeroConstantInt = ZERO_CONSTANT_INT(*(this->M)); 
  GlobalVariable *sizeLikeArgsGV = this->M->getNamedGlobal(RDEF_SIZE_LIKE_ARGS_GV);
  for (unsigned i=0; i < sizeLikeArgs.size(); i++) {
	std::vector<Value*> indices;
	ConstantInt *index = CONSTANT_INT(*(this->M), i);
	indices.push_back(zeroConstantInt);
	indices.push_back(index);
	GetElementPtrInst *gepInst = PassUtil::createGetElementPtrInstruction(sizeLikeArgsGV, indices, "gep sizeLikeArgs", CI);
	StoreInst *SI = new StoreInst(sizeLikeArgs[i], gepInst, false, CI);
  }

//####
  ConstantInt *constNumSizes = ConstantInt::get(this->M->getContext(), APInt(32, num_sizes, 10));
  args.push_back(constNumSizes);

  if (0 != args.size()) {
      CallInst *insertedCI = PassUtil::createCallInstruction(agICallHook, args, "", CI);
      insertedCI->setCallingConv(CallingConv::Fast);
      return insertedCI;
  }
  return NULL;
}

CallInst* AllocGuardPass::insertAllocHook(CallInst *CI)
{
  Function *calledFunc = CI->getCalledFunction();
  IntegerType *i64Type = IntegerType::get(this->M->getContext(), 64);

  DEBUG(errs() << "Inserting alloc hook for instr that calls : " << calledFunc->getName() << "\n");

  CallInst *insertedCI = NULL;
  std::vector<Value *> args;

  assert(NULL != calledFunc  && "Called function is NULL");
  if (0 == calledFunc->getName().compare("calloc")) {
	DEBUG(errs() << "Inserting hook for " << calledFunc->getName() << "\n");
	CastInst *castedArg1 = CastInst::CreateIntegerCast(CI->getArgOperand(0), i64Type, false, "ArgCast", CI);
	CastInst *castedArg2 = CastInst::CreateIntegerCast(CI->getArgOperand(1), i64Type, false, "ArgCast", CI);
	args.push_back(castedArg1);
	args.push_back(castedArg2);
	insertedCI = PassUtil::createCallInstruction(agCallocHook, args, "", CI);
   	insertedCI->setCallingConv(CallingConv::Fast);
	return insertedCI;
  }
  if (0 == calledFunc->getName().compare("brk")) {
	DEBUG(errs() << "Inserting hook for " << calledFunc->getName() << "\n");
	CastInst *castedArg = CastInst::CreateIntegerCast(CI->getArgOperand(0), i64Type, false, "ArgCast", CI);
	args.push_back(castedArg);
	insertedCI = PassUtil::createCallInstruction(agBrkHook, args, "", CI);
	return insertedCI;
  }

  DEBUG(errs() << "One of the normal alloc hooks.\n"); 
  assert(0 != allocFuncsInfo.count(calledFunc->getName()));
  unsigned sizeArgPos = allocFuncsInfo.find(calledFunc->getName())->second;
  DEBUG(errs() << "sizeArgPos for " << calledFunc->getName() << " is: " << sizeArgPos << "\n");
  CastInst *castedArg = CastInst::CreateIntegerCast(CI->getArgOperand(sizeArgPos), i64Type, false, "ArgCast", CI);
  assert(NULL != castedArg);
  args.push_back(castedArg);
  insertedCI = PassUtil::createCallInstruction(agAllocCallHook, args, "", CI);
  insertedCI->setCallingConv(CallingConv::Fast);
  return insertedCI;
}

bool AllocGuardPass::runOnModule(Module &M)
{
   bool ret = false;
   this->M = &M;

/*
   std::vector<std::string> allocFuncNames("malloc", "calloc", "realloc", "valloc", "brk", "sbrk", 
					   "memalign", "posix_memalign", "mmap", "mmap64");
*/

   for (std::map<std::string, unsigned>::iterator sI = allocFuncsInfo.begin(), sE = allocFuncsInfo.end(); sI != sE; sI++) {
	std::string allocFuncName = sI->first;
	Function *F = M.getFunction(allocFuncName);
	if (NULL != F) 
	   allocFuncs.insert(F);
   }
   DEBUG(errs() << "alloc functions loaded. size: " << allocFuncs.size() << "\n");

   getHooks();

   for (Module::iterator it = M.getFunctionList().begin(); it != M.getFunctionList().end(); ++it) {
	Function *F = &(*it);
	if (!std::string(F->getSection()).compare(AGFuncSectionOpt)) {
                        continue;
        }
        for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; I++) {
             Instruction *instr = &(*I);
             CallInst *CI = dyn_cast<CallInst>(instr);
	     if (NULL != CI) {
		Function *calledFunc = CI->getCalledFunction();
		if (NULL == calledFunc) {
			if (is_indirect_call(CI)) {
			   // handle indirect calls
			   if (NULL != insertICallHook(CI)) {
				NumICallHooks++;
				ret = true;
				DEBUG(errs() << "Inserted ICALL hook\n");
			   }
			}
			continue;
		}
		if (allocFuncs.count(calledFunc)) {
		   if(NULL != insertAllocHook(CI)) {
			NumAllocHooks++;
			ret = true;
			DEBUG(errs() << "Inserted Alloc hook for " << calledFunc->getName() << "\n");
		   }
		}
	     }
	 }
   }
   return ret;

}

char AllocGuardPass::ID = 0;
RegisterPass<AllocGuardPass> AP("allocguard", "Alloc Guard Pass");

}
