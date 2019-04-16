/*
   Dwarfer class adds DWARF markers onto elements in the LLVM IR.
   This allows creating a mapping between unstripped code locations with
   its LLVM IR counterparts.

   Author : Koustubha Bhat
   Date   : 31-March-2016
*/

#include <dwarfer/dwarfer.h>

using namespace llvm;

namespace llvm
{

// Public members
Dwarfer::Dwarfer() : ModulePass(ID) {}

Dwarfer::~Dwarfer() {}

unsigned Dwarfer::getAssignedID(BasicBlock *bb)
{
	assert(bb != NULL);
	MDNode *N = bb->getFirstNonPHI()->getMetadata(DWARFER_MARKER_SYM);
	if ( N != NULL && N->getNumOperands() >= 1 )
	{
		// TODO: DIE is not necessary here as the dwarf reader is not required to read this info
		// and we dont connect this to any dwarf CU tree.
		DIExpression *dieElement = dyn_cast<DIExpression>(N->getOperand(0));
		if (NULL == dieElement)
			return 0;
		return (unsigned)(dieElement->getElement(0));
	}
	return 0;
}

bool Dwarfer::runOnModule(Module &M)
{
	this->M = &M;
	initLLVMMarker();

	DEBUG(errs() << "m_dwarfer_assigning_id is initialized to : " << m_dwarfer_assigning_id << "\n" );

	// Run through every basic block of every function
	// to add basic-block IDs.
  Module::FunctionListType &funcs = M.getFunctionList();

  for (Module::iterator mi = funcs.begin(), me = funcs.end(); mi!=me ; ++mi)
	{
		std::vector<Instruction*> unsetDbgInfoCache;
		unsetDbgInfoCache.clear();
		unsigned maxCacheSize = 100;

		Function *F = &(*mi);

		if (F->isIntrinsic())
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
				// const DebugLoc &dbgLoc = I->getDebugLoc();
				// DILocation *DIL = NULL;
				// if (NULL != dbgLoc)
				// {
				// 	DIL = DILocation::get(this->M->getContext(), dbgLoc->getLine(), (unsigned) bbID, dbgLoc->getScope(), dbgLoc->getInlinedAt());
				// 	if (NULL != DIL)
				// 	{
				// 		DebugLoc debugLoc(DIL);
				// 		I->setDebugLoc(debugLoc);
				// 	}
				// 	DEBUG(errs() << "instr: " << I->getOpcodeName() << " bbID: " << (unsigned) bbID << "\n");
				// }
				// else
				// {
				// 	DEBUG(errs() << "WARNING: dbg loc not found for instr: " << I->getOpcodeName() << "\n");
				// 	DIL = DILocation::get(this->M->getContext(), 0, (unsigned) bbID, (DIScope *) NULL, 0);
				// }
					if (false == setBBIdInColNumField(bbID, I))
					{
						if(unsetDbgInfoCache.size() < maxCacheSize)
						{
							unsetDbgInfoCache.push_back(I);
						}
						else
						{
							DEBUG(errs() << "WARNING: Cache full. Will not attempt to set DILocation for rest unset instructions in this function: " << I->getOpcodeName() << "( " << F->getName() << ")\n");
						}
					}
			}
		}

		if (0 != unsetDbgInfoCache.size())
		{
			for(std::vector<Instruction*>::iterator II = unsetDbgInfoCache.begin(), IE = unsetDbgInfoCache.end(); II != IE; II++)
			{
				Instruction *currI = *II;
				unsigned bbID = getAssignedID(currI->getParent());
				if (false == setBBIdInColNumField(bbID, currI))
				{
					DEBUG(errs() << "WARNING: Retrying to set dbg info also failed for instr: " << currI->getOpcodeName() << "( " << F->getName() << ")\n");
				}	// best effort
			}
		}
	} // function iterator ends

	saveMaxIDAssigned();
	return true;
}

// Private members

bool Dwarfer::setBBIdInColNumField(unsigned bbID, Instruction *I)
{
	const DebugLoc &dbgLoc = I->getDebugLoc();
	DILocation *DIL = NULL;

	static const DIScope *defaultScope = NULL;		// scope cache for those instrs where DILocation couldn't be set earlier.
	static Function *scopeFunction = NULL;

	// reset the cache when it is not valid anymore.
	if (scopeFunction != I->getParent()->getParent())
	{
		scopeFunction = NULL;
		defaultScope = NULL;
	}

	DEBUG(errs() << "instr: " << I->getOpcodeName() << " bbID: " << (unsigned) bbID << "\n");
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
		I->setDebugLoc(debugLoc);
	}
	return true;
}

// Initialization helpers
void Dwarfer::initLLVMMarker()
{
  NamedMDNode *nmdn = M->getOrInsertNamedMetadata(DWARFER_MAX_ID_SYM);
  m_dwarfer_assigning_id = 0xAAA0;
  if ( nmdn == NULL || nmdn->getNumOperands() < 1 )
	{
          return;
  }
  MDNode *N = nmdn->getOperand(0);
  if ( N != NULL && N->getNumOperands() >= 1 )
	{
	  DIExpression *dieElement = dyn_cast<DIExpression>(N->getOperand(0));
          if (NULL == dieElement)
              return;
          m_dwarfer_assigning_id = dieElement->getElement(0);
  }
	return;
}

// Other helper functions

MDNode* Dwarfer::createMDNodeForConstant(unsigned constantValue)
{
	// TODO: DIE is not necessary here as the dwarf reader is not required to read this info
	// and we dont connect this to any dwarf CU tree.

	ArrayRef<uint64_t> arrayRefValue((uint64_t)constantValue);
	DIExpression *DIE = DIExpression::get(this->M->getContext(), arrayRefValue);
	ArrayRef<Metadata *> arrayRefMetadata(DIE);
	MDNode *N = MDNode::get(this->M->getContext(), arrayRefMetadata);
	return N;
}

void Dwarfer::saveMaxIDAssigned()
{
	// TODO: Fix this and use this.
        NamedMDNode *nmdn = M->getOrInsertNamedMetadata(DWARFER_MAX_ID_SYM);
       /*
	ConstantInt *CI = ConstantInt::get(M->getContext(), APInt(64, m_dwarfer_assigning_id));
        SmallVector<Value*, 1> V;
        V.push_back(CI);
        MDNode *N = MDNode::get(M->getContext(), V);
	*/
	MDNode *N = createMDNodeForConstant(m_dwarfer_assigning_id);
        // nmdn->dropAllReferences();
        // nmdn->addOperand(N);
	return;
}

unsigned Dwarfer::getNextUnassignedID()
{
	// Note that we will never return 0 as a valid ID.
	return ++m_dwarfer_assigning_id;
}

void Dwarfer::addLLVMLabel(BasicBlock *bb)
{
	MDNode *N;
	N = bb->getFirstNonPHI()->getMetadata(DWARFER_MARKER_SYM);
	if (N != NULL && N->getNumOperands() != 0)
	{
		// already present.
		return;
	}

	N = createMDNodeForConstant(getNextUnassignedID());
	bb->getFirstNonPHI()->setMetadata(DWARFER_MARKER_SYM, N);
	return;
}

char Dwarfer::ID = 1;
static RegisterPass<Dwarfer> WP("dwarfer", "Dwarfer Pass");

}
