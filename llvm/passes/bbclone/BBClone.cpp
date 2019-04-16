#include <debugify/Debugify.h>
#include <bbclone/BBClonePass.h>

using namespace llvm;

static cl::list<std::string>
mapOpt("bbclone-map",
    cl::desc("Specify all the comma-separated section_regex/function_regex/clone1_section/clone2_section tuples to define the functions to clone. A NULL clone*_section will assign no named section to the cloned functions."),
    cl::OneOrMore, cl::CommaSeparated, cl::NotHidden, cl::ValueRequired);

static cl::opt<std::string>
prefixOpt("bbclone-prefix",
    cl::desc("Specify the prefix to use for cloned functions."),
    cl::init("bbclone."), cl::NotHidden, cl::ValueRequired);

static cl::opt<std::string>
cloneFlagOpt("bbclone-flag",
    cl::desc("Specify the clone flag global variable/array (to switch between clone1 and clone2)."),
    cl::init("bbclone_flag"), cl::NotHidden, cl::ValueRequired);

static cl::opt<std::string>
cloneFlagsSizeOpt("bbclone-flag-size-varname",
    cl::desc("Specify the size variable for the array of bbclone-flags (per-function flags to switch between clone1 and clone2)."),
    cl::init("bbclone_flags_size"), cl::NotHidden, cl::ValueRequired);

static cl::opt<unsigned long long>
cloneFlagsArraySizeOpt("bbclone-flag-array-size",
    cl::desc("Specify size of the bbclone-flag array (Must specify for per-function flag behaviour)."),
    cl::init(0), cl::NotHidden, cl::ValueRequired);

static cl::opt<int>
cloneFlagValue1Opt("bbclone-flag-value1",
    cl::desc("Specify the clone flag value to execute clone1."),
    cl::init(0), cl::NotHidden, cl::ValueRequired);

static cl::opt<int>
cloneContainerFuncSectionOpt("bbclone-container-funcs-section",
    cl::desc("Specify the section (clone1_section or clone2_section) to place container functions in [ 1 or 2 ]."),
    cl::init(0), cl::NotHidden, cl::ValueRequired);

static cl::opt<bool>
cloneInline1Opt("bbclone-inline1",
    cl::desc("Force clone1 inlining."),
    cl::init(false), cl::NotHidden, cl::ValueRequired);

static cl::opt<bool>
cloneInline2Opt("bbclone-inline2",
    cl::desc("Force clone2 inlining."),
    cl::init(false), cl::NotHidden, cl::ValueRequired);

static cl::opt<bool>
cloneInlineLoopsOpt("bbclone-inline-loops",
    cl::desc("Force (extracted) loop inlining."),
    cl::init(true), cl::NotHidden, cl::ValueRequired);

static cl::list<std::string>
cloneExcludeCallstacksOpt("bbclone-exclude-callstacks-to",
    cl::desc("Specify all the comma-separated tuples to specify the functions whose callstacks should not be instrumented. Indirect calls are resolved according to the callee-mapper below (direct calls only by default)."),
    cl::ZeroOrMore, cl::CommaSeparated, cl::NotHidden, cl::ValueRequired);

static cl::opt<unsigned>
calleeMapperOpt("bbclone-callee-mapper",
    cl::desc("Specify the callee mapper type (from dsa_common.h)."),
    cl::init(DSAUtil::CM_DIRECTCALL_ANALYSIS), cl::NotHidden, cl::ValueRequired);

static cl::opt<std::string>
hookClone1Opt("bbclone-clone1-hookname",
      cl::desc("Specify the name of the hook to be placed in the clone1"),
      cl::init(""), cl::NotHidden, cl::ValueRequired);

static cl::opt<std::string>
hookClone2Opt("bbclone-clone2-hookname",
      cl::desc("Specify the name of the hook to be placed in the clone2"),
      cl::init(""), cl::NotHidden, cl::ValueRequired);

static cl::opt<std::string>
metadataNamespaceOpt("bbclone-metadata-namespace",
      cl::desc("Specify the metadata namespace to hold function IDs."),
      cl::init(BBCLONE_METADATA_NAMESPACE), cl::NotHidden, cl::ValueRequired);

static cl::opt<std::string>
probabilisticSelectionOpt("bbclone-clone2-probability",
      cl::desc("Enables probabilistic selection of clone1 or clone2 during execution. Specify 'p' for clone2"),
      cl::init(""), cl::NotHidden, cl::ValueRequired);

static cl::opt<int>
excludeVariadicFuncsOpt("bbclone-exclude-variadic-funcs",
      cl::desc("Opt to exclude variadic functions from being cloned and specify their section: [ 1 or 2 ]."),
      cl::init(1), cl::NotHidden, cl::ValueRequired);

static cl::opt<bool>
excludeVariadicDerivativesOpt("bbclone-exclude-all-variadic-derivatives",
    cl::desc("Opt to exclude even functions called using __var_list_tag* arguments. Use this only along with -bbclone-exclude-variadic-funcs."),
    cl::init(false), cl::NotHidden, cl::ValueRequired);

static cl::opt<bool>
logFlagsAccessedOpt("bbclone-log-flags-accessed",
    cl::desc("Record the flags accessed during execution."),
    cl::init(false), cl::NotHidden);

static cl::opt<std::string>
flagsInitValueMapOpt("bbclone-flags-init-mapfile",
    cl::desc("Path to map file containing initial values for flags array."),
    cl::init(""), cl::NotHidden);

/*
 * Example usage (ltckpt, strip required when instrumenting loops due to bugs in loop-extract):
 *  ./build.llvm [strip loop-extract] bbclone "bbclone-map=(^\$)|(^[^l].*\$)/^.*$/ltckpt_functions/NULL" bbclone-flag=sa_window__is_open bbclone-exclude-callstacks-to=sef_handle_message [bbclone-inline1=1] [bbclone-inline2=1] [debug-only=bbclone]
 */

STATISTIC(numClonedFunctions, "Number of functions cloned");
STATISTIC(numExcludedVariadicFunctions, "Number of variadic functions excluded from cloning");
STATISTIC(LogFlagsAccessCIPlaced, "Number of flag access logging call insts. placed");

namespace llvm {

PASS_COMMON_INIT_ONCE();
DSA_UTIL_INIT_ONCE();

//===----------------------------------------------------------------------===//
// Constructors, destructor, and operators
//===----------------------------------------------------------------------===//

BBClonePass::BBClonePass() : ModulePass(ID) {}

//===----------------------------------------------------------------------===//
// Public methods
//===----------------------------------------------------------------------===//


void BBClonePass::getAnalysisUsage(AnalysisUsage &AU) const
{
#if LLVM_VERSION < 37
    AU.addRequired<DATA_LAYOUT_TY>();
#endif
    DSAUtil::calleeMapper = (DSAUtil::CalleeMapperTy) (unsigned) calleeMapperOpt;
}

bool BBClonePass::runOnModule(Module &M) {

    if ( 0 != BBClonePass::PassRunCount)
    {
	DEBUG(errs() << "Not running this pass (bbclone) again.");
	return false;
    }

    moduleInit(M);

    /* Clone all the functions we can find. */
    getSkipFunctions();

    DEBUG(errs() << "bbclone-clone1-hookname: " << hookClone1Opt << "\n");
    DEBUG(errs() << "bbclone-clone2-hookname: " << hookClone2Opt << "\n");

    getHooks();
    cloneFunctions();

    /* Inline loops when requested. */
    if (cloneInlineLoopsOpt)
        inlineLoops();

    BBClonePass::PassRunCount++;
    return cloned;
}

void BBClonePass::moduleInit(Module &M)
{
    this->M = &M;
    this->cloned = false;
    this->havePerFunctionFlags = false;
    this->dsau.init(this, &M);

    if ("" != cloneFlagOpt) {
	    this->flagGV = M.getNamedGlobal(cloneFlagOpt);
	    if (!this->flagGV) {
		errs() << "Clone flag global variable " << cloneFlagOpt << " not found!\n";
		exit(1);
	    }

	    if (0 != cloneFlagsArraySizeOpt) { // per-function flags behaviour
	      if (false == initPerFunctionSwitching()) {
		errs() << "Failed initializing per-function flags data.\n";
		exit(1);
	      }
	      this->havePerFunctionFlags = true;
              this->logFlagsAccessed = false;
	      if (logFlagsAccessedOpt) {
                this->logFlagsAccessed = true;
              }
	      if (flagsInitValueMapOpt != "") {
		BBCloneFlagsInitInputLoader *bbInputLoader = new BBCloneFlagsInitInputLoader();
                if (0 != bbInputLoader->read(flagsInitValueMapOpt)) {
                     bbInputLoader->getFlagsMap(this->inputFlagsInitMap);
                }
	       }
	    }
	    else {
		if (NULL == dyn_cast<IntegerType>(this->flagGV->getType()->getPointerElementType())) {
		  errs() << "Global control variable type incorrect.\n";
		  exit(1);
		}
	    }
    }
    else if ("" == probabilisticSelectionOpt) {
	DEBUG(errs() << "Neither clone-flag nor probability value set.\n");
	exit(1);
    }
    for (unsigned i = 0; i < mapOpt.size(); i++)
	 DEBUG(errs() << "mapOpt : " << mapOpt[i] << "\n");
    parseAndInitRegexMap(mapOpt, regexList, regexMap);
}

void BBClonePass::getSkipFunctions()
{
    for (unsigned i=0;i<cloneExcludeCallstacksOpt.size();i++) {
        std::string FName = cloneExcludeCallstacksOpt[i];
        Function *F = M->getFunction(FName);
        if (!F) {
            errs() << "Function " << FName << " not found!\n";
            exit(1);
        }
        dsau.getCallStacksFunctions(F, skipFunctions);
    }
    DEBUG(
    for (std::set<const Function*>::iterator it=skipFunctions.begin();it!=skipFunctions.end();it++) {
        const Function *F = *it;
        errs() << " - Skipping function (exclude-callstacks-to): " << F->getName() << "\n";
    }
    );
}

bool BBClonePass::initPerFunctionSwitching()
{
  this->flagsSizeGV = M->getNamedGlobal(cloneFlagsSizeOpt);
  if (NULL == flagsSizeGV)
  {
    errs() << "Error: bbclone-flags-size variable not found.\n";
    return false;
  }
  //if (false == (dyn_cast<Value>(this->flagGV)->getType() != ArrayTy_0))
  if (NULL == (dyn_cast<ArrayType>(this->flagGV->getType()->getPointerElementType())))
  {
    errs() << "Specified per-function flag but flag found is not of the required array type (size or type mismatch).\n";
    return false;
  }
  
  Module::FunctionListType &functionList = M->getFunctionList();
  std::vector<Value*> functions;
  for (Module::iterator I = functionList.begin(), E=functionList.end(); I != E; I++)
  {
    Function *F = &(*I);
    Value *currVal = dyn_cast<Value>(F);
    if (NULL == currVal) continue;
    functions.push_back(currVal);
  }
  std::string namespaceName = metadataNamespaceOpt;

  this->lastAssignedId = PassUtil::getNextUnassignedID(this->M, namespaceName, DEBUGIFY_MAX_ID_SYM);
  errs() << "LastAssignedId found is: " << this->lastAssignedId;
  if (0 == this->lastAssignedId) {
	  this->lastAssignedId = PassUtil::assignIDs(*(this->M), &functions, namespaceName);
	  if (0 == lastAssignedId) {
	    errs() << "Error : Failed assigning IDs to functions\n";
	    return false;
	  }
	  DEBUG(errs() << "Set identifiers to " << lastAssignedId << " functions found.\n");
  }

  // set the bbclone-flag array size to lastAssignedId
  ConstantInt* const_switchboardsize = ConstantInt::get(M->getContext(), APInt(64, (uint64_t) lastAssignedId, false));
  flagsSizeGV->setInitializer(const_switchboardsize);

  assert(cloneFlagsArraySizeOpt >= lastAssignedId && "Max array size must be greater or equal to lastAssignedId");
  
  // Set (right) the size of the cloneFlagOpt array initializer.
  IntegerType *intType = IntegerType::get(this->M->getContext(), 32);
  ArrayType* ArrayTy_0 = ArrayType::get(intType, cloneFlagsArraySizeOpt);
  ConstantInt *constIntZero = CONSTANT_INT(*M, 0);;
  std::vector<Constant*> const_array_elems;
  for (uint64_t i=0; i < cloneFlagsArraySizeOpt; i++) {
    const_array_elems.push_back(constIntZero);
  }
  // Honour flagsInitMap specified if any
  for (std::map<unsigned, unsigned>::iterator I = this->inputFlagsInitMap.begin(), E = this->inputFlagsInitMap.end(); I != E; I++) {
      	unsigned f_index = I->first;
	unsigned f_value = I->second;
	assert(f_index < cloneFlagsArraySizeOpt);
	const_array_elems[f_index] = CONSTANT_INT(*M, f_value);
	DEBUG(errs() << "Switchboard init via input file: index: " << f_index 
                     <<  " value: " << f_value << "\n");
  }
  Constant *const_array = ConstantArray::get(ArrayTy_0, const_array_elems);
  DEBUG(errs() << "Setting initializer for bbclone-flag array\n");
  this->flagGV->setInitializer(const_array);
  return true;
}

void BBClonePass::cloneFunctions()
{
#if LLVM_VERSION >= 37
    InlineFunctionInfo inlineFunctionInfo = InlineFunctionInfo(NULL);
#else
    DATA_LAYOUT_TY *DL = &getAnalysis<DATA_LAYOUT_TY>();
    InlineFunctionInfo inlineFunctionInfo = InlineFunctionInfo(NULL, DL);
#endif
    Module::FunctionListType &functionList = M->getFunctionList();
    std::vector<Function *> functions;
    std::set<const Function*>::iterator skipFunctionsIt;  
    for (Module::iterator it = functionList.begin(); it != functionList.end(); ++it) {
        Function *F = &(*it);
        skipFunctionsIt = skipFunctions.find(F);
        if (skipFunctionsIt == skipFunctions.end())
            functions.push_back(F);
	else {
	    DEBUG(errs() << "Skipping function : " << F->getName() << "\n");
	}
    }
    DEBUG(errs() << "Cloning functions\n");
    for (unsigned i=0;i<functions.size();i++) {
        Function *F = functions[i];
        std::string clone1SectionName;
        std::string clone2SectionName;
        if (F->isIntrinsic() || F->isDeclaration() || !isCloneCandidate(F, clone1SectionName, clone2SectionName)) {
	   DEBUG(errs() << "Not a candidate for cloning: function: " << F->getName() << "\n");
            continue;
        }
	if (F->isVarArg() || (F->hasFnAttribute("__VARIADIC__"))) {
		// TODO: Solve the problem with variadic function cloning. Argument passing needs to be set right.
		// A function call between entering a variadic function and passing on the same arguments in a callInst to its
		// cloned variadic callee ends up in segfault.
		switch(excludeVariadicFuncsOpt)
		{
			case 1: F->setSection(clone1SectionName);
				break;
			case 2: F->setSection(clone2SectionName);
				break;
			default:
				break;
		}
		if (0 != excludeVariadicFuncsOpt) {
			DEBUG(errs() << "Not a candidate for cloning: variadic function: " << F->getName() << "\n");
			numExcludedVariadicFunctions++;
			continue;
		}
	}

   if (excludeVariadicDerivativesOpt) {
	bool hasVariadicArgDerivative = false;
	for (Function::arg_iterator IA = F->arg_begin(), EA = F->arg_end(); IA != EA; IA++) {
		Argument *A = &(*IA);
		Type *pStructType = NULL;
		if (A->getType()->isStructTy()) {
			pStructType = A->getType();
		} else if (A->getType()->isPointerTy()) {
			if (A->getType()->getPointerElementType()->isStructTy()) {
				pStructType = A->getType()->getPointerElementType();
			}
		}
		if (NULL != pStructType) {
			if (std::string::npos != pStructType->getStructName().find("struct.__va_list_tag")) {
				errs() << "Not a candidate for cloning: has __va_list_tag arg: "
				       << F->getName() << "\n" ;
				numExcludedVariadicFunctions++;
				hasVariadicArgDerivative = true;
				break;
			}
		}
        }
	if (hasVariadicArgDerivative) {
		F->setSection(clone1SectionName);
		continue;
	}
  }

	uint64_t index = 0;
	if (this->havePerFunctionFlags)
        {
        	index = PassUtil::getAssignedID(F, BBCLONE_METADATA_NAMESPACE);
		DEBUG(errs() << "The assigned id for function: " << F->getName() << " is " << index << "\n");
	}
        numClonedFunctions++;
        StringRef prefix1(prefixOpt);
        StringRef prefix2(prefixOpt);
        Function *clone1 = PassUtil::cloneFunction(F, prefix1.str().append("1.").append(F->getName().str()), clone1SectionName);
        Function *clone2 = PassUtil::cloneFunction(F, prefix2.str().append("2.").append(F->getName().str()), clone2SectionName);

	DEBUG(errs() << "curr func: " << F->getName() << "[ clones created: " << clone1->getName() << ", " << clone2->getName() << " ]\n");

        BasicBlock *entryBlock = &F->getEntryBlock();
        Instruction *I = entryBlock->begin();
        BasicBlock *nextBlock = entryBlock->splitBasicBlock(I, "");

        // Record soon-to-be-dead basic blocks
        std::vector<BasicBlock*> deadBBs;
        for (Function::iterator BI = F->getBasicBlockList().begin(), BE = F->getBasicBlockList().end(); BI != BE; ++BI) {
            BasicBlock *BB = BI;
            if (BB == entryBlock)
                continue;
            deadBBs.push_back(BB);
        }

        // Create new basic blocks
        Instruction *branchPoint = entryBlock->getTerminator();
        BasicBlock* call1Block = BasicBlock::Create(M->getContext(), "bbclone.call.1", F, 0);
        BasicBlock* call2Block = BasicBlock::Create(M->getContext(), "bbclone.call.2", F, 0);
        if (NULL != hookClone1)
        {
          if (false == placeCallInstToHook(hookClone1, call1Block->begin()))
          {
            DEBUG(errs() << "Hooks: Error while planting hookClone1\n");
          }
        }
        if (NULL != hookClone2)
        {
          if (false == placeCallInstToHook(hookClone2, call2Block->begin()))
          {
            DEBUG(errs() << "Hooks: Error while planting hookClone2\n");
          }
        }

        //Replace unconditional branch with compare and conditional branch
        ICmpInst* flagCmp = NULL;
	if ("" != probabilisticSelectionOpt)
	{
	   Function *randFuncHook = this->M->getFunction(BBCLONE_RAND_FUNC_HOOK);
	   assert(randFuncHook && "Random function hook not found - used for probabilistic selection of clones");
	   randFuncHook->setCallingConv(CallingConv::Fast);
	 
	   DEBUG(errs() << "Probabilistic selection chosen.\n");  
	   std::vector<Value*> args;
	   unsigned long probability = std::stoi(probabilisticSelectionOpt, NULL, 10);
	   DEBUG(errs() << "Probability value: " << probability << "\n");
	   ConstantInt  *probConstInt = CONSTANT_INT(*M, probability);
	   args.push_back(probConstInt);
#ifdef SEGV_DEBUG
		ConstantInt *llvmIDConstInt = CONSTANT_INT(*M, index);
		args.push_back(llvmIDConstInt);
		DEBUG(errs() << "seinding in llvmid val as well.. " << index << "\n");
#endif
	   CallInst *randCallInst = PassUtil::createCallInstruction(randFuncHook, args, "", branchPoint);
	   randCallInst->setCallingConv(CallingConv::Fast);
	   DEBUG(errs() << "RandCallInst placed.\n");	

	   //LoadInst *flagGVVal = new LoadInst(randCallInst, "", false, branchPoint);
	   flagCmp = new ICmpInst(branchPoint, ICmpInst::ICMP_NE, randCallInst,
                                                    CONSTANT_INT(*M, cloneFlagValue1Opt), "bbclone.icmp");
	}
        else if (this->havePerFunctionFlags)
        {
          std::vector<Value*> indices;
	  ConstantInt *zeroIndex = CONSTANT_INT(*M, 0);
	  indices.push_back(zeroIndex);
          assert (index <= this->lastAssignedId && "index should be less than lastAssignedId");
          IntegerType *T = IntegerType::get(this->M->getContext(), 64);
          ConstantInt *arrayIndex = ConstantInt::get(T, index);
          indices.push_back(arrayIndex);
          Instruction *GEPInst = PassUtil::createGetElementPtrInstruction(this->flagGV, indices, "", branchPoint);
          assert(GEPInst && "Failed creating GEP instruction.");
          LoadInst* flagGVIdxVal = new LoadInst(GEPInst, "", false, branchPoint);
          flagCmp = new ICmpInst(branchPoint, ICmpInst::ICMP_NE, flagGVIdxVal,
        	                                    CONSTANT_INT(*M, cloneFlagValue1Opt), "bbclone.icmp");

          // Record access to per-function flag, if specified
          if (this->logFlagsAccessed) {
		Function *logFlagsAccessFuncHook = this->M->getFunction(BBCLONE_LOG_FLAGS_ACCESS_FUNC_HOOK);
		assert(logFlagsAccessFuncHook && "logFlagsAccess function hook not found - used for logging per-function flags accesses");
		logFlagsAccessFuncHook->setCallingConv(CallingConv::Fast);

	        std::vector<Value*> args;
                ConstantInt *u32ArrayIndex = CONSTANT_INT(*M, index);
	        args.push_back(u32ArrayIndex);
	        CallInst *logFlagsAccessCallInst = PassUtil::createCallInstruction(logFlagsAccessFuncHook, args, "", branchPoint);
        	logFlagsAccessCallInst->setCallingConv(CallingConv::Fast);
	        DEBUG(errs() << "logFlagsAccessCallInst placed.\n");
		LogFlagsAccessCIPlaced++;
          }
        }
        else
        {
          LoadInst* flagGVVal = new LoadInst(flagGV, "", false, branchPoint);
          flagCmp = new ICmpInst(branchPoint, ICmpInst::ICMP_NE, flagGVVal,
        	                                    CONSTANT_INT(*M, cloneFlagValue1Opt), "bbclone.icmp");
        }
        BranchInst::Create(call1Block, call2Block, flagCmp, branchPoint);
        branchPoint->eraseFromParent();
        BranchInst::Create(nextBlock, call1Block);
        BranchInst::Create(nextBlock, call2Block);

	      // Get arguments
        std::vector<Value*> cloneParams;
        for(Function::arg_iterator it = F->arg_begin(), end = F->arg_end(); it!=end; it++) {
            Argument *arg = it;
            cloneParams.push_back(arg);
        }

        // Handle clone2
        branchPoint = call1Block->getTerminator();
        CallInst* call1Inst = PassUtil::createCallInstruction(clone1, cloneParams, "", branchPoint);
        if (!F->getReturnType()->isVoidTy())
            ReturnInst::Create(M->getContext(), call1Inst, call1Block);
        else
            ReturnInst::Create(M->getContext(), call1Block);
        branchPoint->eraseFromParent();

        // Handle clone2
        branchPoint = call2Block->getTerminator();
        CallInst* call2Inst = PassUtil::createCallInstruction(clone2, cloneParams, "", branchPoint);
        if (!F->getReturnType()->isVoidTy())
            ReturnInst::Create(M->getContext(), call2Inst, call2Block);
        else
            ReturnInst::Create(M->getContext(), call2Block);
        branchPoint->eraseFromParent();

	DEBUG(errs() << "Clone2 Handled\n");
        if (NULL != hookClone1)
        {
          if (false == placeCallInstToHook(hookClone1, clone1->getEntryBlock().getFirstInsertionPt()))
          {
            DEBUG(errs() << "Hooks: Error while planting hookClone1\n");
          }
        }
        if (NULL != hookClone2)
        {
          if (false == placeCallInstToHook(hookClone2, clone2->getEntryBlock().getFirstInsertionPt()))
          {
            DEBUG(errs() << "Hooks: Error while planting hookClone2\n");
          }
        }

        // Remove instructions from dead basic blocks
        for (unsigned i=0;i<deadBBs.size();i++) {
            BasicBlock *BB = deadBBs[i];
            while (PHINode *PN = dyn_cast<PHINode>(BB->begin())) {
                PN->replaceAllUsesWith(Constant::getNullValue(PN->getType()));
                BB->getInstList().pop_front();
            }
            for (succ_iterator SI = succ_begin(BB), E = succ_end(BB); SI != E; ++SI)
                (*SI)->removePredecessor(BB);
            BB->dropAllReferences();
        }

        // Remove dead basic blocks
        //ProfileInfo *PI = getAnalysisIfAvailable<ProfileInfo>();
        for (unsigned i=0;i<deadBBs.size();i++) {
            BasicBlock *BB = deadBBs[i];
            //if (PI) PI->removeBlock(BB);
            BB->eraseFromParent();
        }

        // Inline calls if requested
        if (cloneInline1Opt)
	{
        //    InlineFunction(call1Inst, inlineFunctionInfo);
	      clone1->addFnAttr(Attribute::AlwaysInline);
	}
        if (cloneInline2Opt)
	{
        //    InlineFunction(call2Inst, inlineFunctionInfo);
	      clone2->addFnAttr(Attribute::AlwaysInline);
	}
	// Put container function in its section, if specified
	if (0 != cloneContainerFuncSectionOpt)
	{
		// Note: If inlining the two clones doesn't go well with this option
		if (cloneInline1Opt || cloneInline2Opt)
		{
			errs() << "WARNING: Inlining is opted along with setting container function section. Are you sure?\n";
		}
		if (1 == cloneContainerFuncSectionOpt)
		{
			F->setSection(clone1SectionName);
			DEBUG(errs() << "Placed the container function in section: " << clone1SectionName);
		}
		else if (2 == cloneContainerFuncSectionOpt)
		{
			F->setSection(clone2SectionName);
			DEBUG(errs() << "Placed the container function in section: " << clone2SectionName);
		}
	}
    }
}

void BBClonePass::inlineLoops()
{
#if LLVM_VERSION >= 37
    InlineFunctionInfo inlineFunctionInfo = InlineFunctionInfo(NULL);
#else
    DATA_LAYOUT_TY *DL = &getAnalysis<DATA_LAYOUT_TY>();
    InlineFunctionInfo inlineFunctionInfo = InlineFunctionInfo(NULL, DL);
#endif
    Module::FunctionListType &functionList = M->getFunctionList();
    for (Module::iterator it = functionList.begin(); it != functionList.end(); ++it) {
        Function *F = it;
        for (Function::iterator BI = F->getBasicBlockList().begin(), BE = F->getBasicBlockList().end(); BI != BE; ++BI) {
            BasicBlock *BB = BI;
            if (BB->getName().compare("codeRepl")) //naming used by CodeExtractor::extractCodeRegion invoked by loop-extract
                continue;
            CallInst *CI = dyn_cast<CallInst>(BB->begin());
            assert(CI && "Bad codeRepl basic block format!");
            Function *IF = CI->getCalledFunction();
            assert(IF && "Bad codeRepl basic block function!");
            InlineFunction(CI, inlineFunctionInfo);
            if (IF->isDefTriviallyDead())
                IF->eraseFromParent();
        }
    }
}

bool BBClonePass::isCloneCandidate(Function *F, std::string &clone1SectionName, std::string &clone2SectionName)
{
    for (std::vector<std::pair<Regex*, Regex*> >::iterator it = regexList.begin(); it != regexList.end(); ++it) {
        std::pair<Regex*, Regex*> regexes = *it;
        regexMapIt = regexMap.find(regexes);
        assert(regexMapIt != regexMap.end());
        if (isCloneCandidateFromRegexes(F, regexes)) {
            clone1SectionName = regexMapIt->second.first;
            clone2SectionName = regexMapIt->second.second;
            return true;
        }
    }

    return false;
}

bool BBClonePass::isCloneCandidateFromRegexes(Function *F, std::pair<Regex*, Regex*> regexes)
{
    Regex* sectionRegex = regexes.first;
    Regex* functionRegex = regexes.second;
    if(!sectionRegex->match(F->getSection(), NULL)
        || !functionRegex->match(F->getName(), NULL)) {
        return false;
    }

    return true;
}

bool BBClonePass::parseStringTwoKeyMapOpt(std::map<std::pair<std::string, std::string>, std::pair<std::string, std::string> > &map, std::vector<std::pair<std::string, std::string> > &keyList, std::vector<std::string> &stringList)
{
    for (std::vector<std::string>::iterator it = stringList.begin(); it != stringList.end(); ++it) {
        StringRef token = *it;
        SmallVector< StringRef, 4 > tokenVector;
        token.split(tokenVector, "/");
        if(tokenVector.size() != 4) {
            return false;
        }
        StringRef value2 = tokenVector.pop_back_val();
        StringRef value1 = tokenVector.pop_back_val();
        StringRef key2 = tokenVector.pop_back_val();
        StringRef key1 = tokenVector.pop_back_val();
        std::pair<std::string, std::string> key = std::pair<std::string, std::string>(key1, key2);
        std::pair<std::string, std::string> value = std::pair<std::string, std::string>(value1, value2);
        map.insert( std::pair<std::pair<std::string, std::string>, std::pair<std::string, std::string> >(key, value) );
        keyList.push_back(key);
    }

    return true;
}

void BBClonePass::parseAndInitRegexMap(cl::list<std::string> &stringListOpt, std::vector<std::pair<Regex*, Regex*> > &regexList, std::map<std::pair<Regex*, Regex*>, std::pair<std::string, std::string> > &regexMap)
{
    std::map<std::pair<std::string, std::string>, std::pair<std::string, std::string> > stringMap;
    std::vector<std::pair<std::string, std::string> > stringList;
    if (!parseStringTwoKeyMapOpt(stringMap, stringList, stringListOpt) || !initRegexMap(regexMap, regexList, stringMap, stringList)) {
        stringListOpt.error("Invalid format!");
        exit(1);
    }
}

bool BBClonePass::initRegexMap(std::map<std::pair<Regex*, Regex*>, std::pair<std::string, std::string> > &regexMap, std::vector<std::pair<Regex*, Regex*> > &regexList, std::map<std::pair<std::string, std::string>, std::pair<std::string, std::string> > &stringMap, std::vector<std::pair<std::string, std::string> > &stringList)
{
    std::map<std::pair<std::string, std::string>, std::pair<std::string, std::string> >::iterator stringMapIt;
    for (std::vector<std::pair<std::string, std::string> >::iterator it = stringList.begin(); it != stringList.end(); ++it) {
        std::pair<std::string, std::string> key = *it;
        std::string sectionKey = key.first;
        std::string functionKey = key.second;
        stringMapIt = stringMap.find(key);
        assert(stringMapIt != stringMap.end());
        std::pair<std::string, std::string> value = stringMapIt->second;
        std::string clone1Section = value.first;
        std::string clone2Section = value.second;
        std::string error;
        Regex *sectionRegex = new Regex(sectionKey, 0);
        if(!sectionRegex->isValid(error)) {
            errs() << "Error: Invalid section regex.\n";
            return false;
        }
        Regex *functionRegex = new Regex(functionKey, 0);
        if(!functionRegex->isValid(error)) {
            errs() << "Error: Invalid function regex.\n";
            return false;
        }
        if (clone1Section.size()==0) {
            errs() << "Error: Invalid clone1 section.\n";
            return false;
        }
        if (clone2Section.size()==0) {
            errs() << "Error: Invalid clone2 section.\n";
            return false;
        }
        std::pair<Regex*, Regex*> regexes = std::pair<Regex*, Regex*>(sectionRegex, functionRegex);
        DEBUG(errs() << "Using regex " << sectionKey << "/" << functionKey << " with clone1 section " << clone1Section << " and clone2 section " << clone2Section << "\n");
        if (!clone1Section.compare("NULL"))
            clone1Section="";
        if (!clone2Section.compare("NULL"))
            clone2Section="";
        regexMap.insert(std::pair<std::pair<Regex*, Regex*>, std::pair<std::string, std::string> >(regexes, std::pair<std::string, std::string>(clone1Section, clone2Section)));
        regexList.push_back(regexes);
    }

    return true;
}

bool BBClonePass::getHooks()
{
    bool retVal = false;
  	DEBUG(errs() << "Getting hooks.\n");

    if ("" != hookClone1Opt)
    {
    	Constant *clone1HookFunc = M->getFunction(hookClone1Opt);
    	assert(clone1HookFunc != NULL);
      hookClone1  = cast<Function>(clone1HookFunc);
    	hookClone1->setCallingConv(CallingConv::Fast);
      retVal = (NULL != hookClone1);
    }
    else
    {
      hookClone1 = NULL;
      retVal = true;
    }

    if ("" != hookClone2Opt)
    {
    	Constant *clone2HookFunc = M->getFunction(hookClone2Opt);
    	assert(clone2HookFunc != NULL);
    	hookClone2  = cast<Function>(clone2HookFunc);
    	hookClone2->setCallingConv(CallingConv::Fast);
      retVal = retVal && (NULL != hookClone2);
    }
    else
    {
      hookClone2 = NULL;
      retVal = retVal && true;
    }

    if (false == retVal)
    {
      DEBUG(errs() << "Hooks: Error locating specified hooks: "
                   << hookClone1Opt << " and " << hookClone2Opt);
    }
    return retVal;
}

bool BBClonePass::placeCallInstToHook(Function* hook, Instruction *nextInst)
{
  if (NULL == hook || NULL == nextInst)
  {
    return false;
  }

  DEBUG(errs() << "Placing callInst to hook: " << hook->getName() << "\n");

  std::vector<Value*> args;
  CallInst *callInstToHook = PassUtil::createCallInstruction(hook, args, "", nextInst);
  callInstToHook->setCallingConv(CallingConv::Fast);

  return true;
}

} // end namespace

char BBClonePass::ID = 1;
static RegisterPass<BBClonePass> WP("bbclone", "BBClone Pass");
