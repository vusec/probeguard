#ifndef DWARFER_H
#define DWARFER_H

#define DEBUG_TYPE "dwarfer"

#include <pass.h>
#include <llvm/IR/DIBuilder.h>
#include <llvm/IR/DebugInfo.h>

#define DWARFER_MARKER_SYM		  "RD_MARKER"
#define DWARFER_MAX_ID_SYM		  "RD_MAX_ID"

using namespace llvm;

namespace llvm
{

class Dwarfer : public ModulePass
{
public:
	static char ID;

	Dwarfer();
	virtual bool runOnModule(Module &M);
  unsigned getAssignedID(BasicBlock *bb);

private:
	unsigned m_dwarfer_assigning_id;
	Module *M;

  // Initialization helpers
  void initLLVMMarker();
	void saveMaxIDAssigned();

  // Other helper functions
  MDNode* createMDNodeForConstant(unsigned constantValue);
	DILocation* createDILocationWithBBID(unsigned bbID, const DebugLoc *dbgLoc);
	unsigned getNextUnassignedID();
  void addLLVMLabel(BasicBlock *bb);
	bool setBBIdInColNumField(unsigned bbID, Instruction *I);

protected:
  ~Dwarfer();
};

}
#endif
