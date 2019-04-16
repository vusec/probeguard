#ifndef BBCLONE_PASS_H

#define BBCLONE_PASS_H

#define DEBUG_TYPE "bbclone"
#include <pass.h>

#include <common/dsa_common.h>
#include <common/input_common.h>

#define BBCLONE_CLONE1_HOOK      "inc_counter_inwindow"
#define BBCLONE_CLONE2_HOOK      "inc_counter_outsidewindow"
//#define BBCLONE_METADATA_NAMESPACE   "bbclone"
#define BBCLONE_METADATA_NAMESPACE   "RD_MARKER"   // Used in reactive defense
#define BBCLONE_RAND_FUNC_HOOK	 "prand"
#define BBCLONE_LOG_FLAGS_ACCESS_FUNC_HOOK	"log_flags_access"
#define BBCLONE_INPUT_FLAGS_INIT_REGEX	 	"[0-9]+=[0-9]+"
using namespace llvm;

namespace llvm {

class BBClonePass : public ModulePass {

  public:
      static char ID;

      BBClonePass();

      virtual void getAnalysisUsage(AnalysisUsage &AU) const;
      virtual bool runOnModule(Module &M);

  private:
      Module *M;
      GlobalVariable *flagGV;
      GlobalVariable *flagsSizeGV;
      DSAUtil dsau;
      std::set<const Function*> skipFunctions;
      bool cloned;
      static unsigned PassRunCount;
      bool havePerFunctionFlags;
      bool logFlagsAccessed;
      uint64_t lastAssignedId;
      std::map<unsigned, unsigned> inputFlagsInitMap;
      std::map<std::pair<Regex*, Regex*>, std::pair<std::string, std::string> > regexMap;
      std::map<std::pair<Regex*, Regex*>, std::pair<std::string, std::string> >::iterator regexMapIt;
      std::vector<std::pair<Regex*, Regex*> > regexList;
      std::map<Function*, unsigned> functionIdMap;

      Function *hookClone1, *hookClone2;

      void moduleInit(Module &M);
      void getSkipFunctions();
      void cloneFunctions();
      void inlineLoops();
      bool isCloneCandidate(Function *F, std::string &clone1SectionName, std::string &clone2SectionName);
      bool isCloneCandidateFromRegexes(Function *F, std::pair<Regex*, Regex*> regexes);
      bool parseStringTwoKeyMapOpt(std::map<std::pair<std::string, std::string>, std::pair<std::string, std::string> > &map, std::vector<std::pair<std::string, std::string> > &keyList, std::vector<std::string> &stringList);
      void parseAndInitRegexMap(cl::list<std::string> &stringListOpt, std::vector<std::pair<Regex*, Regex*> > &regexList, std::map<std::pair<Regex*, Regex*>, std::pair<std::string, std::string> > &regexMap);
      bool initRegexMap(std::map<std::pair<Regex*, Regex*>, std::pair<std::string, std::string> > &regexMap, std::vector<std::pair<Regex*, Regex*> > &regexList, std::map<std::pair<std::string, std::string>, std::pair<std::string, std::string> > &stringMap, std::vector<std::pair<std::string, std::string> > &stringList);
      bool getHooks();
      bool initPerFunctionSwitching();
      bool placeCallInstToHook(Function* hook, Instruction *nextInst);
};

class BBCloneFlagsInitInputLoader : public InputLoader
{
  public:
      BBCloneFlagsInitInputLoader();
      void getFlagsMap(std::map<unsigned, unsigned> &flagsMap);
};

BBCloneFlagsInitInputLoader::BBCloneFlagsInitInputLoader() : InputLoader(new Regex(BBCLONE_INPUT_FLAGS_INIT_REGEX))
{
}

void BBCloneFlagsInitInputLoader::getFlagsMap(std::map<unsigned, unsigned> &flagsMap)
{
    unsigned flagsCount = 0;
    if (0 != this->acceptedLines.size()) {
	for(unsigned i=0; i < acceptedLines.size(); i++) {
	   StringRef currLine = acceptedLines[i];
           SmallVector<StringRef, 3> tokenVector;
           currLine.split(tokenVector, "=");
           if (tokenVector.size() != 2) {
               return;
           }
           unsigned flagNum = std::strtoul(tokenVector.pop_back_val().str().c_str(), NULL, 0);
           unsigned value   = std::strtoul((const char *)tokenVector.pop_back_val().str().c_str(), NULL, 0);
           flagsMap.insert(std::pair<unsigned, unsigned>(flagNum, value));
           flagsCount++;
	}
    }
    DEBUG(errs() << "Num per-function flags initialized by mapfile : " << flagsCount << "\n");
}

unsigned BBClonePass::PassRunCount = 0;

}
#endif
