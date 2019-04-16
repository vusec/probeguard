
#include <cfi/cfi.h>

using namespace llvm;

static cl::opt<std::string>
CFIFuncSectionOpt("cfi-func-section",
    cl::desc("Skip functions in the specified section."),
    cl::init("cfi_functions"), cl::NotHidden);

STATISTIC(NumFwdChecks, "Number of CFI Forward Edge Check Emulation instructions inserted.");
STATISTIC(NumIndirectlyCalledFuncs, "Number of functions associated with indirect calls.");
//STATISTIC(NumIndirectCallInsts, "Number of call insts with indirect func addressing.");
STATISTIC(NumIndirectlyCalledExternFuncs, "Number of external functions associated with indirect calls.");
STATISTIC(NumBkCallChecksAdded, "Number of CFI Backward Edge Func entries inserted.");
STATISTIC(NumBkReturnChecksAdded, "Number of CFI Backward Edge Check Return checks inserted.");

namespace llvm {

PASS_COMMON_INIT_ONCE();

CFIPass::CFIPass() : ModulePass(CFIPass::ID) {}

bool CFIPass::runOnModule(Module &M) 
{
	bool ret = true;
	this->M = &M;
	getHooks();

	Function *mainFunc = M.getFunction("main");
	if (NULL == mainFunc) {
		errs() << "main() function not found.\n";
		return false;
	}
	
	DEBUG(errs() << "Adding fwd edge checks.\n");
	if (false == addFwdEdgeChecks()) {
		DEBUG(errs() << "WARNING: No fwd edge checks added. Something wrong?\n");
		ret=false;
	}

	DEBUG(errs() << "Adding bk edge checks.\n");
	if (false == addBkEdgeChecks()) {
		DEBUG(errs() << "WARNING: No backward edge checks added. Something wrong?\n");
		// no need to update ret, as its value - true or false, is what is already correct.
	}
	
	// place init hook at the entry of main func.
	assert (insertCFIInitHook(mainFunc) && "Error placing CFI init hook");

        DEBUG(errs() << "Inlining the CFI checks.\n");
	if (ret) {
		// inline everything that we added
		inlineTheChecks(insertedFwdChecks);
		inlineTheChecks(insertedBkCheckFuncEntries);
		inlineTheChecks(insertedBkCheckFuncExits);

	}

     return ret;
}

void CFIPass::getHooks() 
{
	Constant *hookFunc;
	
	hookFunc = M->getFunction(CFI_INIT_FUNC);
	assert(hookFunc != NULL);
	cfiInitHook = cast<Function>(hookFunc);
	cfiInitHook->setCallingConv(CallingConv::Fast);
	
	hookFunc = M->getFunction(CFI_FWD_EDGE_CHECK_FUNC);
	assert(hookFunc != NULL);
	cfiFwdEdgeCheckHook = cast<Function>(hookFunc);
	cfiFwdEdgeCheckHook->setCallingConv(CallingConv::Fast);

	hookFunc = M->getFunction(CFI_BK_EDGE_FUNC_ENTRY);
	assert(hookFunc != NULL);
	cfiBkEdgeFuncEntryHook = cast<Function>(hookFunc);
	cfiBkEdgeFuncEntryHook->setCallingConv(CallingConv::Fast);
	
	hookFunc = M->getFunction(CFI_BK_EDGE_FUNC_EXIT);
	assert(hookFunc != NULL);
	cfiBkEdgeFuncExitHook = cast<Function>(hookFunc);
	cfiBkEdgeFuncExitHook->setCallingConv(CallingConv::Fast);
}

bool CFIPass::insertCFIInitHook(Function *mainFunc)
{
  assert (NULL != mainFunc);
  BasicBlock *entryBlock = &mainFunc->getEntryBlock();
  Instruction *firstInstr = &(*entryBlock->getFirstInsertionPt());
  std::vector<Value*> args;
  CallInst *initHookCall = PassUtil::createCallInstruction(cfiInitHook, args, "", firstInstr);
  if (NULL == initHookCall) 
	return false;
  initHookCall->setCallingConv(CallingConv::Fast);
  return true;
}

CallInst* CFIPass::insertFwdCFI(CallInst *CI, Instruction *nextInst) 
{
	FunctionType *hookType = cfiFwdEdgeCheckHook->getFunctionType();
	DEBUG(errs() << "Num params: " << hookType->getNumParams() << "\n");
	for (unsigned i=0; i < hookType->getNumParams(); i++) {
		Type *iType = hookType->getParamType(i);
		DEBUG(errs() << "param " << i << " : " << iType->getTypeID() << "\n");
		i++;
	}
	std::vector<Value*> args;
	args.push_back(new PtrToIntInst(CI->getCalledValue(), IntegerType::get(this->M->getContext(), 64), "ptrtoint64",  nextInst));
	CallInst *callInstToHook = PassUtil::createCallInstruction(cfiFwdEdgeCheckHook, args, "", nextInst);
	callInstToHook->setCallingConv(CallingConv::Fast);
	return callInstToHook;
}

CallInst* CFIPass::insertBkFuncEntryHook(Instruction *nextInst) 
{
	std::vector<Value*> args1;
	ConstantInt* ci = llvm::ConstantInt::get(Type::getInt32Ty(this->M->getContext()), 0);
	args1.push_back(ci);
	CallInst *getRetAddrCallInst = PassUtil::createCallInstruction(Intrinsic::getDeclaration(this->M, Intrinsic::returnaddress), args1, "", nextInst);
	getRetAddrCallInst->setCallingConv(CallingConv::Fast);
	
	std::vector<Value*> args2;
        args2.push_back(new PtrToIntInst(getRetAddrCallInst, IntegerType::get(this->M->getContext(), 64), "ptrtoint64",  nextInst));
	CallInst *callInstToHook = PassUtil::createCallInstruction(cfiBkEdgeFuncEntryHook, args2, "", nextInst);
	callInstToHook->setCallingConv(CallingConv::Fast);
	return callInstToHook;
}

CallInst* CFIPass::insertBkFuncExitHook(ReturnInst *returnInst) 
{
	std::vector<Value*> args1;
	ConstantInt* ci = llvm::ConstantInt::get(Type::getInt32Ty(this->M->getContext()), 0);
	args1.push_back(ci);
	CallInst *getRetAddrCallInst = PassUtil::createCallInstruction(Intrinsic::getDeclaration(this->M, Intrinsic::returnaddress), args1, "", dyn_cast<Instruction>(returnInst));
	getRetAddrCallInst->setCallingConv(CallingConv::Fast);
	
	std::vector<Value*> args2;
        args2.push_back(new PtrToIntInst(getRetAddrCallInst, IntegerType::get(this->M->getContext(), 64), "ptrtoint64",  returnInst));
	CallInst *callInstToHook = PassUtil::createCallInstruction(cfiBkEdgeFuncExitHook, args2, "", dyn_cast<Instruction>(returnInst));
	callInstToHook->setCallingConv(CallingConv::Fast);
	return callInstToHook;
}

inline bool CFIPass::is_indirect_call(CallInst *CI) 
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

bool CFIPass::addFwdEdgeChecks() 
{
	for (Module::iterator it = M->getFunctionList().begin(); it != M->getFunctionList().end(); ++it) {
		Function *F  = &(*it);
		DEBUG(errs() << "[fwdedge] F: " << F->getName() << "S: " << F->getSection() << "\n");
		if (!std::string(F->getSection()).compare(CFIFuncSectionOpt)) {
			DEBUG(errs() << "[fwdedge] Skipping function: " << F->getName() << "\n");
			continue;
		}
		for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; I++) {
			Instruction *instr = &(*I);
			CallInst *CI = dyn_cast<CallInst>(instr);
			if (NULL != CI) {
				if (is_indirect_call(CI)) {
					DEBUG(errs() << "indirect call\n");
					CallInst *insertedCall = insertFwdCFI(CI, instr);
					insertedFwdChecks.push_back(insertedCall);
					NumFwdChecks++;
				}
			}
		}
	}
	if (0 < NumFwdChecks)
		return true;
	return false;
}

void CFIPass::inlineTheChecks(std::vector<CallInst*> &insertedInsts)
{
  DEBUG(errs() << "Inlining the inserted checks...\n");
#if LLVM_VERSION >= 37
    InlineFunctionInfo inlineFunctionInfo = InlineFunctionInfo(NULL);
#else
    DATA_LAYOUT_TY *DL = &getAnalysis<DATA_LAYOUT_TY>();
    InlineFunctionInfo inlineFunctionInfo = InlineFunctionInfo(NULL, DL);
#endif
  for (unsigned i=0; i < insertedInsts.size(); i++) {
	InlineFunction(insertedInsts[i], inlineFunctionInfo);
  }
  return;
}

bool CFIPass::addBkEdgeChecks() 
{
	bool ret = false;

	for (Module::iterator it = M->getFunctionList().begin(); it != M->getFunctionList().end(); ++it) {
		Function *F  = &(*it);
		if (NULL == F) continue;
		DEBUG(errs() << "[bkedge] F: " << F->getName() << "S: " << F->getSection() << "\n");
		if (F->isIntrinsic()) continue;
		if (F->empty()) continue;
		if (0 == std::string(F->getSection()).compare(CFIFuncSectionOpt)) {
			DEBUG(errs() << "[bkedge] Skipping function: " << F->getName() << "\n");
			continue;
		}

		BasicBlock *entryBlock = &F->getEntryBlock();
		if (NULL == entryBlock) {
			// skip external funcs
			continue;
		}
		DEBUG(errs() << "Processing func: " << F->getName() << "\n");
		// Add func entry hook
		if (!entryBlock->empty()) {
			Instruction *firstInstr = &(*entryBlock->getFirstInsertionPt());
			CallInst *insertedCall = insertBkFuncEntryHook(firstInstr);
			insertedBkCheckFuncEntries.push_back(insertedCall);
			NumBkCallChecksAdded++;
			DEBUG(errs() << " : added funcEntry hook call\n");
			ret = true;
		}
		// Add return hooks
		for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; I++) {
			Instruction *instr = &(*I);
			ReturnInst *retInstr = dyn_cast<ReturnInst>(instr);
			if (NULL != retInstr) {
				CallInst *insertedCall = insertBkFuncExitHook(retInstr);
				insertedBkCheckFuncExits.push_back(insertedCall);	
				NumBkReturnChecksAdded++;
				DEBUG(errs() << "\t added return hook call for return inst:" << retInstr->getName() << "\n");
				ret = true;
			}
		}
	}
  return ret;
}

char CFIPass::ID = 0;
RegisterPass<CFIPass> CP("cfi", "CFI Pass");

} // end of namespace

