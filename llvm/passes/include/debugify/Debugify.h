#ifndef DEBUGIFY_H
#define DEBUGIFY_H

#define DEBUG_TYPE "debugify"

#include <pass.h>
#if LLVM_VERSION >= 37
	#include <llvm/IR/DIBuilder.h>
	#include <llvm/IR/DebugInfo.h>
	#include <llvm/IR/DebugInfo.h>
	#include <llvm/IR/Verifier.h>
        #include <llvm/IR/InstIterator.h>
#else
	#include "llvm/DIBuilder.h"
	#include "llvm/DebugInfo.h"
	#include <llvm/Analysis/Verifier.h>
        #include <llvm/Support/InstIterator.h>
#endif

#define DEBUGIFY_MARKER_SYM		  					"RD_MARKER"
#define DEBUGIFY_MAX_ID_SYM		  					"RD_MAX_ID"
#define DEBUGIFY_STD_DEBUG_INFO_VERSION 	"Debug Info Version"
// #define DEBUGIFY_DWARF_CONTEXT					"RDF"
#define DEBUGIFY_DWARF_CONTEXT						"dbg"			// this needs to be dbg so that LLVM backend picks this up.

using namespace llvm;

namespace llvm
{

typedef struct
{
	std::string name;
	DIBuilder *diBuilder;
#if LLVM_VERSION >= 37
	DIFile 		*diFile;
	DISubprogram *diDefaultSubprogram;
#else
  DIFile diFile;
	DISubprogram diDefaultSubprogram;
#endif
} DwarfContext ;

class Debugify : public ModulePass
{
public:
	static char ID;

	Debugify();
	virtual bool runOnModule(Module &M);
	bool addCodeMarkers(Module &M);
  unsigned getAssignedID(BasicBlock *bb);
	bool removeDbgInfoVersion();

private:
	unsigned m_debugify_assigning_id;
	Module *M;
	DwarfContext dwarfContext;
	std::vector<Regex*> skipSectionsRegexes;
	std::vector<Value*> funcsToMark;
        bool m_dwarfContextInitialized;
        DISubroutineType *diDefaultSubroutineType;
        // Initialization helpers
        void initLLVMMarker();
	void saveMaxIDAssigned();
	bool initDwarfContext(std::string contextName, DwarfContext &dwarfContext);
        void preserveSwitchBoardSymbol(std::string globalSymbolName, uint64_t arraySize);

  // Other helper functions
  MDNode* createMDNodeForConstant(unsigned constantValue);
	unsigned getNextUnassignedID();
  void addLLVMLabel(BasicBlock *bb);
	bool setLLVMIdInDbgLoc(unsigned bbID, Instruction *I);
	void setLLVMIdInDwarfContext(unsigned bbID, Instruction *I, DwarfContext &dwarfContext);

protected:
  ~Debugify();
};

}
#endif
