/*
   Debugify class adds DWARF markers onto elements in the LLVM IR.
   This allows creating a mapping between unstripped code locations with
   its LLVM IR counterparts.

   We stick to LLVM 3.7. DebugInfo API varies across 3.4 and 3.7 versions.

   Author : Koustubha Bhat
   Date   : 31-March-2016
*/

#include <debugify/Debugify.h>

using namespace llvm;

static cl::opt<bool>
codeMarkingOpt("debugify-codemarking",
    cl::desc("Assign unique debug IDs to every basic block."),
    cl::init(true), cl::NotHidden);

static cl::opt<bool>
removeDbgInfoVersionOpt("debugify-del-debug-info-flag",
    cl::desc("Remove the 'Debug Info Version' module flag if it exists already."),
    cl::init(false), cl::NotHidden);

static cl::opt<bool>
markVariadicFuncsOpt("debugify-mark-variadic-funcs",
    cl::desc("Marks variadic functions with debug metadata: \"__VARIADIC__\"."),
    cl::init(false), cl::NotHidden);

static cl::opt<std::string>
skipSectionsOpt("debugify-skip-sections",
    cl::desc("Specify all the colon-separated section regexes to skip debugifying."),
    cl::init(""), cl::Optional, cl::NotHidden, cl::ValueRequired);

static cl::opt<std::string>
switchBoardSymOpt("debugify-switchboard-symbol",
    cl::desc("Specify global variable name of the switchboard, if it must be preserved."),
    cl::init(""), cl::Optional, cl::NotHidden, cl::ValueRequired);

static cl::opt<uint64_t>
switchBoardSizeOpt("debugify-switchboard-size",
    cl::desc("Specify size of the switchboard"),
    cl::init(32000), cl::Optional, cl::NotHidden, cl::ValueRequired);

STATISTIC(NumAssignedIDs, "Number of instructions to which IDs were assigned.");
STATISTIC(LastAssignedID, "Last assigned ID in this module.");
STATISTIC(NumGlobalSymbols, "Number of global symbols preserved.");
STATISTIC(NumVariadics,	    "Number of variadic funcs marked.");

namespace llvm
{

// Public members
Debugify::Debugify() : ModulePass(ID) {}

Debugify::~Debugify() {}

bool Debugify::runOnModule(Module &M)
{
  this->M = &M;
  if (removeDbgInfoVersionOpt)
  {
     if (false == removeDbgInfoVersion())
      return false;
  }
  PassUtil::parseRegexListOpt(skipSectionsRegexes, skipSectionsOpt);
  if (codeMarkingOpt)
  {
     if (false == addCodeMarkers(M)) {
        return false;
     }
     return true;
  }
  return false;
}

bool Debugify::addCodeMarkers(Module &M)
{
  this->M = &M;
  initLLVMMarker();
  if (false == initDwarfContext(DEBUGIFY_DWARF_CONTEXT, this->dwarfContext))
  {
    errs() << "Error initializing DWARF context.\n";
    return false;
  }

  DEBUG(errs() << "m_debugify_assigning_id is initialized to : " << m_debugify_assigning_id << "\n" );

  // Run through every basic block of every function
  // to add basic-block IDs.
  Module::FunctionListType &funcs = M.getFunctionList();

  for (Module::iterator mi = funcs.begin(), me = funcs.end(); mi!=me ; ++mi)
  {
		Function *F = &(*mi);
		if (NULL == F)
			continue;
		if (F->isIntrinsic())
			continue;
		if (markVariadicFuncsOpt && F->isVarArg()) {
			F->addFnAttr("__VARIADIC__", "F");
			NumVariadics++;
                }
		if (PassUtil::matchRegexes(F->getSection(), skipSectionsRegexes))
		{
			DEBUG(errs() << "skipping section: " << F->getSection() << "\n");
			continue;
		}
		Value *V = dyn_cast<Value>(F);
		assert(NULL != V);	
		this->funcsToMark.push_back(V);
  }

  // assign IDs first
   m_debugify_assigning_id = PassUtil::assignIDs(M, &funcsToMark, DEBUGIFY_MARKER_SYM, DEBUGIFY_MAX_ID_SYM); 
  // set these IDs in Dwarf for all instructions of respective functions
  for (unsigned i=0; i < funcsToMark.size(); i++)
  {
	uint64_t funcID = PassUtil::getAssignedID(funcsToMark[i], DEBUGIFY_MARKER_SYM);
	Function *F = dyn_cast<Function>(funcsToMark[i]);
	assert(NULL != F);
  	for (inst_iterator it = inst_begin(F), et = inst_end(F); it != et; ++it)
  	{
	   Instruction *I = &(*it);
	   setLLVMIdInDwarfContext(funcID, I, dwarfContext);   
  	}
  }

#if 0	// Per-basic block assignment of IDs
  for (Module::iterator mi = funcs.begin(), me = funcs.end(); mi!=me ; ++mi)
	{
		// std::vector<Instruction*> unsetDbgInfoCache;
		// unsetDbgInfoCache.clear();
		// unsigned maxCacheSize = 100;

		Function *F = &(*mi);

		if (F->isIntrinsic())
			continue;
		if (PassUtil::matchRegexes(F->getSection(), skipSectionsRegexes))
		{
			DEBUG(errs() << "skipping section: " << F->getSection() << "\n");
			continue;
		}
		if (NULL == F)
			continue;

		for (Function::iterator BI = F->begin(), BE = F->end(); BI != BE; BI++)
		{
			BasicBlock *BB = &(*BI);
			addLLVMLabel(BB);
			unsigned bbID = getAssignedID(BB);
			// Use col number field to add basic block id assigned
			for (BasicBlock::iterator II = BB->begin(), IE = BB->end(); II != IE; II++)
			{
				Instruction *I = &(*II);
        setLLVMIdInDwarfContext(bbID, I, dwarfContext);

				// if (false == setLLVMIdInDbgLoc(bbID, I))
				// {
        //   // Save in cache for retrying later.
				// 	if(unsetDbgInfoCache.size() < maxCacheSize)
				// 	{
				// 		unsetDbgInfoCache.push_back(I);
				// 	}
				// 	else
				// 	{
				// 		DEBUG(errs() << "WARNING: Cache full. Will not attempt to set DILocation for rest unset instructions in this function: " << I->getOpcodeName() << "( " << F->getName() << ")\n");
				// 	}
				// }

			}
		}
    // Retry for those where we failed setting the dbg field earlier.
		// if (0 != unsetDbgInfoCache.size())
		// {
		// 	for(std::vector<Instruction*>::iterator II = unsetDbgInfoCache.begin(), IE = unsetDbgInfoCache.end(); II != IE; II++)
		// 	{
		// 		Instruction *currI = *II;
		// 		unsigned bbID = getAssignedID(currI->getParent());
		// 		if (false == setLLVMIdInDbgLoc(bbID, currI))
		// 		{
		// 			DEBUG(errs() << "WARNING: Retrying to set dbg info also failed for instr: " << currI->getOpcodeName() << "( " << F->getName() << ")\n");
		// 		}	// best effort
		// 	}
		// }
	} // function iterator ends
#endif

  if ("" != switchBoardSymOpt) {
         preserveSwitchBoardSymbol(switchBoardSymOpt, switchBoardSizeOpt);
  }
  this->dwarfContext.diBuilder->finalize();
  this->M->addModuleFlag(llvm::Module::Warning, DEBUGIFY_STD_DEBUG_INFO_VERSION, llvm::DEBUG_METADATA_VERSION);
	saveMaxIDAssigned();
  LastAssignedID = m_debugify_assigning_id;
	return true;
}

unsigned Debugify::getAssignedID(BasicBlock *bb)
{
	assert(bb != NULL);
	MDNode *N = bb->getFirstNonPHI()->getMetadata(DEBUGIFY_MARKER_SYM);
	if ( N != NULL && N->getNumOperands() >= 1 )
	{
#if LLVM_VERSION >= 37
    ConstantInt *I = dyn_cast_or_null<ConstantInt>(((ConstantAsMetadata *)((Metadata *)(N->getOperand(0))))->getValue()) ;
#else
    ConstantInt *I = dyn_cast_or_null<ConstantInt>(N->getOperand(0));
#endif
    return (unsigned)(I->getZExtValue());
	}
	return 0;
}

bool Debugify::removeDbgInfoVersion()
{
  SmallVector<Module::ModuleFlagEntry, 8> moduleFlags;
  this->M->getModuleFlagsMetadata(moduleFlags);
  NamedMDNode *moduleFlagNode = this->M->getModuleFlagsMetadata();
  if(NULL == moduleFlagNode)
  {
    // If nothing is there, we are more than happy!
    return true;
  }
  moduleFlagNode->dropAllReferences();
  moduleFlagNode->eraseFromParent();
  DEBUG(errs() << "Removed all moduleFlags. Going to add them back, except that which we don't want.\n");
  for(SmallVector<Module::ModuleFlagEntry, 8>::iterator IM = moduleFlags.begin(), EM = moduleFlags.end(); IM != EM; IM++)
  {
    Module::ModuleFlagEntry E = *IM;
    if (std::string::npos != E.Key->getString().find(DEBUGIFY_STD_DEBUG_INFO_VERSION))
    {
      DEBUG(errs() << "Not going to add back: " << E.Key->getString() << "\n");
      continue;
    }
    DEBUG(errs() << "Adding back: " << E.Key->getString() << "\n");
    this->M->addModuleFlag(E.Behavior, E.Key->getString(), E.Val);
  }
  return true;
}

// Private members

bool Debugify::initDwarfContext(std::string contextName, DwarfContext &dwarfContext)
{
  if (NULL != this->M->getModuleFlag(DEBUGIFY_STD_DEBUG_INFO_VERSION))
  {
    errs() << "Conflicting dbg info exists. Retry by using bitcode file without debug symbols.\n";
    return false;
  }
  Function *mainFunction = this->M->getFunction("main");
  if(NULL == mainFunction)
  {
    DEBUG(errs() << "Error : Couldn't fetch main() function.\n");
    return false;
  }

  dwarfContext.name = contextName;
  dwarfContext.diBuilder = new DIBuilder(*M);
  dwarfContext.diBuilder->createCompileUnit(dwarf::DW_LANG_C99,
                              M->getModuleIdentifier(),             // File
                              contextName,   // Directory
                              "",                       // Producer
                              false,                    // optimized
                              contextName,   // Flags   --> this is important for us
                              1,                        // no RV
                              "");                      // no split name
  // create a DIFile
  dwarfContext.diFile = dwarfContext.diBuilder->createFile(M->getModuleIdentifier(), contextName);

#if LLVM_VERSION >= 37
  // create a subprogram for using it as our default scope
  DITypeRefArray *diArray = new DITypeRefArray(NULL);
  this->diDefaultSubroutineType = dwarfContext.diBuilder->createSubroutineType(dwarfContext.diFile, *diArray);
  dwarfContext.diDefaultSubprogram = dwarfContext.diBuilder->createFunction(dwarfContext.diFile,
                                                                            mainFunction->getName(),  // subroutine name
                                                                            "",                       // linkage name
                                                                            dwarfContext.diFile,      // DIFile
                                                                            0,                        // LineNo
                                                                            this->diDefaultSubroutineType,
                                                                            true,                     // isLocalToUnit
                                                                            true,                     // isDefinition
                                                                            0                        // scope Line
                                                                          );
#else
  SmallVector<llvm::Value*, 16> Elts;
  DIArray EltTypeArray = dwarfContext.diBuilder->getOrCreateArray(Elts);
  DICompositeType diDefaultSubroutineType = dwarfContext.diBuilder->createSubroutineType(dwarfContext.diFile, EltTypeArray);
  dwarfContext.diDefaultSubprogram = dwarfContext.diBuilder->createFunction(DIDescriptor(dwarfContext.diFile),     // Scope
                                                                            mainFunction->getName(),    // Name
                                                                            "",              // LinkageName
                                                                            dwarfContext.diFile,       // File
                                                                            0,               // LineNo
                                                                            diDefaultSubroutineType,       // FunctionType
                                                                            mainFunction->hasInternalLinkage(),  // function is not externally visible
                                                                            true,                     // Is definition
                                                                            0,               // ScopeLine
                                                                            DIDescriptor::FlagPrototyped,     // Flags
                                                                            true,  // Is Optimized
                                                                            mainFunction,     // Function
                                                                            0,
                                                                            0
                                                                          );
#endif
  this->m_dwarfContextInitialized = true;
  return true;
}

bool Debugify::setLLVMIdInDbgLoc(unsigned bbID, Instruction *I)
{
	const DebugLoc &dbgLoc = I->getDebugLoc();
  DebugLoc newDbgLoc;

	static const DIScope *defaultScope = NULL;		// scope cache for those instrs where DILocation couldn't be set earlier.
	static Function *scopeFunction = NULL;

	// reset the cache when it is not valid anymore.
	if (scopeFunction != I->getParent()->getParent())
	{
		scopeFunction = NULL;
		defaultScope = NULL;
	}

	DEBUG(errs() << "instr: " << I->getOpcodeName() << " bbID: " << (unsigned) bbID << "\n");

#if LLVM_VERSION >= 37
	DILocation *DIL = NULL;

	if (NULL != dbgLoc)
  {
      DIL = DILocation::get(this->M->getContext(), dbgLoc->getLine(), (unsigned) bbID, dbgLoc->getScope(), dbgLoc->getInlinedAt());
      if (NULL == defaultScope)
  		{
  			defaultScope = dbgLoc->getScope();	// We don't really care about the scope. All that we require is the column number.
  			scopeFunction = I->getParent()->getParent();
  		}
  }
  else
	{
  		DEBUG(errs() << "WARNING: dbg loc not found for instr: " << I->getOpcodeName() << "\n");
  		if (NULL == defaultScope)
  		{
  			// ask the caller to retry later
  			return false;
  		}
  		DIL = DILocation::get(this->M->getContext(), 0, (unsigned) bbID, (DIScope *) defaultScope, 0);
	}
  if (NULL != DIL)
  {
    DebugLoc debugLoc(DIL);
    newDbgLoc = debugLoc;
  }
#else
  if (!dbgLoc.isUnknown())
	{
      newDbgLoc = DebugLoc::get(dbgLoc.getLine(), bbID, dbgLoc.getScope(M->getContext()), dbgLoc.getInlinedAt(M->getContext()));
  		if (NULL == defaultScope)
  		{
  			defaultScope = (DIScope*) dbgLoc.getScope(M->getContext());	// We don't really care about the scope. All that we require is the column number.
  			scopeFunction = I->getParent()->getParent();
  		}
	}
  else
  {
      DEBUG(errs() << "WARNING: dbg loc not found for instr: " << I->getOpcodeName() << "\n");
      if (NULL == defaultScope)
      {
        // ask the caller to retry later
        return false;
      }
      newDbgLoc = DebugLoc::get(0, bbID, (MDNode *) defaultScope );
  }
#endif

// set the Loc for the instruction.
	if (newDbgLoc.getCol() != 0)
	{
  		I->setDebugLoc(newDbgLoc);
	}
	return true;
}

void Debugify::setLLVMIdInDwarfContext(unsigned bbID, Instruction *I, DwarfContext &dwarfContext)
{
  // prepare the DILocation to be set

#if LLVM_VERSION >= 37
  DILocation *DIL = DILocation::get(this->M->getContext(), 0, (unsigned) bbID, dwarfContext.diDefaultSubprogram);
  DEBUG(errs() << "instr: " << I->getName() << "\tbbid: " << DIL->getColumn() << "\n");
  NumAssignedIDs++;
  I->setMetadata(dwarfContext.name, DIL);  // used by rdef diagnoser

  // Also create separate function-wise Dwarf symbols with func-id in their line-num info.
  StringRef funcName(I->getParent()->getParent()->getName());
  DISubprogram *diFunc = this->dwarfContext.diBuilder->createFunction(this->dwarfContext.diFile, // File
								      funcName, // Symbol name
								      funcName,	// Linkage name
								      this->dwarfContext.diFile, // File
								      bbID, // Line No reused for storing func-id
								      this->diDefaultSubroutineType,	// Type
								      false, // isLocalToUnit
								      true, // isDefinition
								      0);    // ScopeLine
#else
  // DIScopeRef scopeRef = dwarfContext.diDefaultSubprogram.getContext();
  // ArrayRef<Value *> scopeVals(scopeRef);
  MDNode *scopeMDNode = DIDescriptor((DIScope)dwarfContext.diDefaultSubprogram);
  // WARNING: This just doesn't work with LLVM 3.4. Column number remains 0 no matter what!
  DebugLoc dbgLoc = DebugLoc::get(0, bbID, scopeMDNode, NULL);
  DEBUG(errs() << "instr: " << I->getName() << "\tbbid: " << dbgLoc.getCol() << "\n");
  NumAssignedIDs++;
  I->setMetadata(dwarfContext.name, dbgLoc.getAsMDNode(this->M->getContext()));
  // I->setDebugLoc(dbgLoc);
#endif
  return;
}
// Initialization helpers
void Debugify::initLLVMMarker()
{
  NamedMDNode *nmdn = M->getOrInsertNamedMetadata(DEBUGIFY_MAX_ID_SYM);
  m_debugify_assigning_id = 0xAAA0;
  if ( nmdn == NULL || nmdn->getNumOperands() < 1 )
	{
          return;
  }
  MDNode *N = nmdn->getOperand(0);
  if ( N != NULL && N->getNumOperands() >= 1 )
	{
#if LLVM_VERSION >= 37
        ConstantInt *I = dyn_cast_or_null<ConstantInt>(((ConstantAsMetadata *)((Metadata *)(N->getOperand(0))))->getValue()) ;
#else
    ConstantInt *I = dyn_cast_or_null<ConstantInt>(N->getOperand(0));
#endif
    m_debugify_assigning_id = (unsigned) (I->getZExtValue());
  }
	return;
}

void Debugify::preserveSwitchBoardSymbol(std::string globalSymbolName, uint64_t arraySize)
{
    // Assuming that dwarf context is already initialized.
    GlobalVariable *gv = NULL;

    DEBUG(errs() << "Adding symbol for global variable: " << globalSymbolName << "\n");
    gv = this->M->getNamedGlobal(globalSymbolName);
    assert(NULL != gv);
    
    DIBasicType *diInt64Type = this->dwarfContext.diBuilder->createBasicType("uint64_t", 64, gv->getAlignment(), dwarf::DW_ATE_unsigned);
    ArrayRef<Metadata *> *emptyArrayRef = new ArrayRef<Metadata*>();
    DICompositeType *diGArrayType = this->dwarfContext.diBuilder->createArrayType(arraySize, gv->getAlignment(), diInt64Type,
                                                                                 this->dwarfContext.diBuilder->getOrCreateArray(*emptyArrayRef));
    DIGlobalVariable *diGVar = this->dwarfContext.diBuilder->createGlobalVariable(this->dwarfContext.diFile, // File
										  (StringRef) globalSymbolName,
										  (StringRef) globalSymbolName,
										  this->dwarfContext.diFile, // File
                                                         			  0, // Line
										  diGArrayType,	// Type
                                                         			  false, // isLocalToUnit
                         			                                  gv);   // Variable
/*										  
    DIGlobalVariable *diGVar = DIGlobalVariable::get(this->M->getContext(), this->dwarfContext.diDefaultSubprogram, 
                                                         globalSymbolName, // Name
                                                         globalSymbolName, // Linkage name
                                                         this->dwarfContext.diFile, // File
                                                         0, // Line
                                                         diGArrayType, // Type
                                                         true, // isLocalToUnit
                                                         true, // isDefinition
                                                         gv,   // Variable
                                                         NULL);
    //                                                     DIGlobalVariable::getStaticDataMemberDeclaration());
*/
        NumGlobalSymbols++;
    DEBUG(errs() << "Added symbol for global var: " << diGVar->getDisplayName() << " (" << diGVar->getLinkageName() << ")\n");
    return;
}

// Other helper functions

MDNode* Debugify::createMDNodeForConstant(unsigned constantValue)
{
  IntegerType *T = IntegerType::get(this->M->getContext(), 32);
  ConstantInt *I = ConstantInt::get(T, constantValue);
#if LLVM_VERSION >= 37
  ArrayRef<Metadata *> arrayRefMetadata(ConstantAsMetadata::get(I));
  MDNode *N = MDNode::get(this->M->getContext(), arrayRefMetadata);
#else
  ArrayRef<Value*> arrayRefValue(I);
  MDNode *N = MDNode::get(this->M->getContext(), arrayRefValue);
#endif
	return N;
}

void Debugify::saveMaxIDAssigned()
{
  NamedMDNode *nmdn = M->getOrInsertNamedMetadata(DEBUGIFY_MAX_ID_SYM);
	MDNode *N = createMDNodeForConstant(m_debugify_assigning_id);
  nmdn->dropAllReferences();
  nmdn->addOperand(N);
	return;
}

unsigned Debugify::getNextUnassignedID()
{
	// Note that we will never return 0 as a valid ID.
	return ++m_debugify_assigning_id;
}

void Debugify::addLLVMLabel(BasicBlock *bb)
{
	MDNode *N;
	N = bb->getFirstNonPHI()->getMetadata(DEBUGIFY_MARKER_SYM);
	if (N != NULL && N->getNumOperands() != 0)
	{
		// already present.
		return;
	}

	N = createMDNodeForConstant(getNextUnassignedID());
	bb->getFirstNonPHI()->setMetadata(DEBUGIFY_MARKER_SYM, N);
	return;
}

char Debugify::ID = 1;
static RegisterPass<Debugify> WP("debugify", "Debugify Pass");

}
