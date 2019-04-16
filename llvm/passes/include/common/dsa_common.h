#ifndef _DSA_COMMON_H_
#define _DSA_COMMON_H_

#include <pass.h>
#ifdef  USE_SLICER
#include <slicer/SlicerPass.h>
#endif

#ifndef LLVM_HAS_DSA
#define LLVM_HAS_DSA 0
#endif

#ifndef LLVM_HAS_DSAA
#define LLVM_HAS_DSAA 0
#endif

#if LLVM_HAS_DSA
#include <dsa/DataStructure.h>
#if LLVM_HAS_DSAA
#include <dsa/DataStructureAA.h>
#endif
#include <dsa/DSGraph.h>
#include <dsa/CallTargets.h>
#include <dsa/DSNode.h>

#define DSA_ADD_REQUIRED(U, DSA) U.addRequired<DSA>()
#define DSA_OR_RETURN(R, B) B
#define DSA_CALLGRAPH(P) (&((P)->getAnalysis<DSA_CALLGRAPH_ANALYSIS>().getCallGraph()))
#define DSA_DATASTRUCTUREGRAPH(P, D, F) (((P)->getAnalysis<D>().getOrCreateGraph(F)))
#define DSA_DSNodeValue(P, V) (P)->addValueList(V)
#if LLVM_HAS_DSAA
#define DSA_DSAAESCAPEVALUE(P, V) (((P)->getAnalysis<DSA_DSAA_ANALYSIS>().mightValueEscapeThread(V)))
#else
#define DSA_DSAAESCAPEVALUE(P, V) (false)
#endif
#define DSA_DSNodeIncompleteCheck(P) (P)->isIncompleteNode()
#define DSA_CALLTARGETS(P) (&((P)->getAnalysis< dsa::CallTargetFinder<TDDataStructures> >()))
#define DSA_ALLOC_WRAPPERS(P) (&((P)->getAnalysis<DSA_ALLOC_WRAPPER_ANALYSIS>()))
#define DSA_FILLNODEDETAILS(P, V) (P.fillNodeMetaData(V))
#define DSA_NODE DSNode 
#define DSCALLSITE DSCallSite
#define DSGRAPH DSGraph
#else
#define DSA_ADD_REQUIRED(U, DSA)
#define DSA_OR_RETURN(R, B) ({ if(1) return R;})
#define DSA_CALLGRAPH(P) (NULL)
#define DSA_CALLTARGETS(P) (NULL)
#define DSA_DATASTRUCTUREGRAPH(P, D, F) (NULL)
#define DSA_DSAAESCAPEVALUE(P, V) (false)
#define DSA_ALLOC_WRAPPERS(P) (NULL)
#define DSA_DSNodeValue(P, V) (NULL)
#define DSA_DSNodeIncompleteCheck(P) (NULL)
#define DSA_FILLNODEDETAILS(P, V) (P.fillNodeMetaData())
#define DSA_NODE   void
#define DSCALLSITE void
#define DSGRAPH    void
#endif
#define DSA_CALLGRAPH_ANALYSIS TDDataStructures
#define DSA_LOCALDATA_ANALYSIS LocalDataStructures
#define DSA_LOCALDATA_STRUCTURE LocalDataStructures
#define DSA_STD_LIB_DATA_STRUCTURE StdLibDataStructures
#define DSA_BU_DATA_STRUCTURE BUDataStructures
#define DSA_COMP_BU_DATA_STRUCTURE CompleteBUDataStructures
#define DSA_EQUIV_BU_DATA_STRUCTURE EquivBUDataStructures
#define DSA_TD_DATA_STRUCTURE TDDataStructures
#define DSA_EQUIV_TD_DATA_STRUCTURE EQTDDataStructures
#define DSA_DSAA_ANALYSIS DSAA
#define DSA_CALLTARGETS_ANALYSIS dsa::CallTargetFinder<TDDataStructures>
#define DSA_ALLOC_WRAPPER_ANALYSIS AllocIdentify

#define DSA_UTIL_INIT_ONCE() \
    DSAUtil::CalleeMapperTy DSAUtil::calleeMapper = CM_DIRECTCALL_ANALYSIS; \
    DSAUtil::AllocIdentifierTy DSAUtil::allocIdentifier = AI_NONE; \
    DSAUtil::LocalAnalysisTy DSAUtil::localAnalysis = LOCAL_NONE; \
    DSAUtil::IdempotifyAnalysisTy DSAUtil::idempotifyAnalysis = IDEMPOTIFY_NONE;

#ifndef DSA_UTIL_TYPE_HASH_MAX_LEVEL
#define DSA_UTIL_TYPE_HASH_MAX_LEVEL 1
#endif

using namespace llvm;

namespace llvm {

class VariableNodeState;

class CallEdge {
  public:
      CallEdge(CallSite &CS_, std::set<const Function*> &funcs_) : CS(CS_), funcs(funcs_) {}
      CallSite getCS() { return CS; }
      std::set<const Function*> getTargets() { return funcs; }
  private:
      CallSite CS;
      std::set<const Function*> funcs;
};

class DSAUtil {
  private:
  public:
      typedef enum {
          CM_DIRECTCALL_ANALYSIS,   /* Direct calls only. */
          CM_CALLTARGETS_ANALYSIS,  /* Direct+indirect calls. */
          CM_TYPETARGETS_ANALYSIS,  /* Type-based direct+indirect calls. */
          CM_PARAMTARGETS_ANALYSIS, /* Parameter-based direct+indirect calls. */
          CM_ATTARGETS_ANALYSIS,    /* Address taken-based direct+indirect calls. */
          CM_ALLTARGETS_ANALYSIS,   /* All targets-based direct+indirect calls. */
          CM_SPTTARGETS_ANALYSIS,   /* Slicer's points-to-based direct+indirect calls. */
          CM_CALLGRAPH_ANALYSIS,    /* Not working properly. */
      } CalleeMapperTy;
      typedef enum {
          AI_NONE,                  /* None. */
          AI_ALLOC_WRAPPER_ANALYSIS, /* DSA's wrapper analysis. */
      } AllocIdentifierTy;
      typedef enum {
	    LOCAL_NONE,
	    LOCAL_ESCAPEANALYSIS_DSA,
	    LOCAL_ESCAPEANALYSIS_INSTRUCTION,
      }LocalAnalysisTy;

      typedef enum {
	    IDEMPOTIFY_NONE,
	    IDEMPOTIFY_LOCAL,
	    IDEMPOTIFY_INTER,
      }IdempotifyAnalysisTy;

      typedef enum {
	    LOCAL_GRAPH,
	    STD_LIB_GRAPH,
	    BOTTOM_UP_GRAPH,
	    COMPLETE_BOTTOM_UP_GRAPH,
	    EQUI_BOTTOM_UP_GRAPH,
	    TOP_DOWN_GRAPH,
	    EQ_TOP_DOWN_GRAPH, 
      }GraphTypeTy;

      typedef std::vector<CallEdge> CallEdgeVecTy;
      typedef std::vector<const Function*> FuncVecTy;
      typedef std::vector<const Value*> ValueVecTy;
      typedef std::vector<VariableNodeState> VariableVecTy;
      typedef std::set<CallEdge> CallEdgeSetTy;
      typedef std::set<const Function*> FuncSetTy;
      typedef std::vector<const CallSite> CallSiteVecTy;
      typedef std::map<const Function*, std::vector<CallSite> > ActualCallersTy;
      typedef std::map<const Function*, FuncSetTy > ActualCallersFuncSetTy;

      void init(Pass *P, Module *M);
      bool haveDSA();
      bool getCallees(const Function *F, FuncSetTy &callees);
      bool getICallees(const Function *F, FuncSetTy &icallees);
      bool getDCallees(const Function *F, FuncSetTy &dcallees);
      bool isGlobalValue(const Function *F, const Value *V);
      bool getCalleeEdges(const Function *F, CallEdgeVecTy &callEdges);
      bool getEscapedVar(const Function *F, VariableVecTy &escapedVar, VariableVecTy &incompleteVal, int &totalVar, int &incompleteCount);
      bool getCallees(CallSite &CS, FuncSetTy &callees);
      bool getCalleesCTA(CallSite &CS, FuncSetTy &callees);
      bool getCalleesGEN(CallSite &CS, FuncSetTy &callees, CalleeMapperTy calleeMapper);
      void checkEscapeVar(ValueVecTy nodeValueList, ValueVecTy &escapedVariable);
      bool checkEscapeVar(const Value *V);
      bool getCalleesCGA(CallSite &CS, FuncSetTy &callees);
      bool getCalleesSPT(CallSite &CS, FuncSetTy &callees);
      bool getCalleesDCA(CallSite &CS, FuncSetTy &callees);
      unsigned long getCalleeTypeHash(TYPECONST Type* type, CalleeMapperTy calleeMapper);
      bool getCallSites(const Function *F, std::vector<CallSite> &callSites);
      bool getCallers(const Function *F, FuncSetTy &callers);
      bool getCallStacks(const Function *F, std::vector<FuncVecTy> &callStacks, unsigned limit=0);
      bool getCallStacks(const CallSite &CS, std::vector<FuncVecTy> &callStacks, unsigned limit=0);
      bool getCallStacksFunctions(const Function *F, FuncSetTy &functions, unsigned limit=0);
      DSA_NODE *getDSNodeFromLocalDataStructure(const Function *F, const Value *V);
      void dumpCallGraph();
      void dumpInverseCallGraph();
      void appendValueVec(ValueVecTy inputVec, ValueVecTy &finalVec);
      DSGRAPH *getDSGraph(const Function *F, GraphTypeTy type);
      bool isDeclarationKnownLibraryFunction(Function *F);

      #if LLVM_HAS_DSA
	inline std::string classifyNode(DSNode *node);
      #endif
      std::set<std::string>::iterator getAllocatorIterator(bool alloc, bool begin);
      std::set<std::string>::iterator getAllocatorIteratorAWA(bool alloc, bool begin);

      DSCALLSITE getDSCallSiteFromCallSite(const Function *F, CallSite CS, GraphTypeTy type);


      DSA_NODE* getDSNode(const Function *F, const Value *V, GraphTypeTy type);
      static void getAnalysisUsage(AnalysisUsage &usage);
      static CalleeMapperTy calleeMapper;
      static AllocIdentifierTy allocIdentifier;
      static LocalAnalysisTy localAnalysis;
    
      std::vector<FuncSetTy> callsite_icallees;

      static IdempotifyAnalysisTy idempotifyAnalysis;
  private:
      void fetchActualCallers();
      void addActualCaller(ActualCallersTy &ActualCallers, const Function *F, const CallSite &callSite);
      ActualCallersTy ActualCallers;
      ActualCallersFuncSetTy ActualCallersFuncSet;
      std::set<std::string> emptyStringSet;
      Pass *P;
      Module *M;
      
};


inline bool DSAUtil::isDeclarationKnownLibraryFunction(Function *F)
{
    #if LLVM_HAS_DSAA
	StdLibDataStructures &stdLibDS = P->getAnalysis<DSA_STD_LIB_DATA_STRUCTURE>();
	StdLibInfo &stdLibInfo = stdLibDS.getStdLibInfo();
	if(stdLibInfo.getLibActionForFunction(F) == NULL)
	    return false;
	else	
	    return true;
    #else
	return false;
    #endif
}

inline void DSAUtil::init(Pass *P, Module *M)
{
    this->P = P;
    this->M = M;
}

inline bool DSAUtil::haveDSA()
{
    return LLVM_HAS_DSA;
}


inline DSGRAPH *DSAUtil::getDSGraph(const Function *F, GraphTypeTy type)
{
   #if LLVM_HAS_DSA
	DSGraph *ds = NULL;
	switch(type)
	{
	    case LOCAL_GRAPH:
		ds = DSA_DATASTRUCTUREGRAPH(P,DSA_LOCALDATA_ANALYSIS ,F);
	    break;
	    case STD_LIB_GRAPH:
		ds = DSA_DATASTRUCTUREGRAPH(P,DSA_STD_LIB_DATA_STRUCTURE,F);
	    break;
	    case BOTTOM_UP_GRAPH:
		ds = DSA_DATASTRUCTUREGRAPH(P,DSA_BU_DATA_STRUCTURE ,F);
	    break;
	    case COMPLETE_BOTTOM_UP_GRAPH:
		ds = DSA_DATASTRUCTUREGRAPH(P, DSA_COMP_BU_DATA_STRUCTURE, F);
	    break;
	    case EQUI_BOTTOM_UP_GRAPH:
		ds = DSA_DATASTRUCTUREGRAPH(P, DSA_EQUIV_BU_DATA_STRUCTURE, F);
	    break;
	    case TOP_DOWN_GRAPH:
		ds = DSA_DATASTRUCTUREGRAPH(P, DSA_TD_DATA_STRUCTURE, F);
	    break;
	    case EQ_TOP_DOWN_GRAPH: 
		ds = DSA_DATASTRUCTUREGRAPH(P, DSA_EQUIV_TD_DATA_STRUCTURE, F);
	    break;
	}
	return ds;
   #else
	return NULL; 
    #endif
}

inline void DSAUtil::getAnalysisUsage(AnalysisUsage &usage)
{
    switch(DSAUtil::calleeMapper) {
    case DSAUtil::CM_CALLTARGETS_ANALYSIS:
        DSA_ADD_REQUIRED(usage, DSA_CALLTARGETS_ANALYSIS);
    break;
    case DSAUtil::CM_CALLGRAPH_ANALYSIS:
        DSA_ADD_REQUIRED(usage, DSA_CALLGRAPH_ANALYSIS);
    break;
    default:
    break;
    }

#if LLVM_HAS_DSAA
    if(DSAUtil::localAnalysis == DSAUtil::LOCAL_ESCAPEANALYSIS_DSA)
    {
	DSA_ADD_REQUIRED(usage, DSA_LOCALDATA_ANALYSIS);
        DSA_ADD_REQUIRED(usage, DSA_DSAA_ANALYSIS);
    }
    else if(DSAUtil::localAnalysis == DSAUtil::LOCAL_ESCAPEANALYSIS_INSTRUCTION)
    {
        DSA_ADD_REQUIRED(usage, DSA_DSAA_ANALYSIS);
    }


    if(DSAUtil::idempotifyAnalysis == DSAUtil::IDEMPOTIFY_LOCAL)
    {
	DSA_ADD_REQUIRED(usage, DSA_LOCALDATA_ANALYSIS);
	DSA_ADD_REQUIRED(usage, DSA_STD_LIB_DATA_STRUCTURE);
        DSA_ADD_REQUIRED(usage, DSA_DSAA_ANALYSIS);
    }
    else if(DSAUtil::idempotifyAnalysis == DSAUtil::IDEMPOTIFY_INTER)
    {
	DSA_ADD_REQUIRED(usage, DSA_LOCALDATA_ANALYSIS);
	DSA_ADD_REQUIRED(usage, DSA_STD_LIB_DATA_STRUCTURE);
	DSA_ADD_REQUIRED(usage, DSA_STD_LIB_DATA_STRUCTURE);
	DSA_ADD_REQUIRED(usage, DSA_BU_DATA_STRUCTURE); 
	DSA_ADD_REQUIRED(usage, DSA_TD_DATA_STRUCTURE); 
    }
#endif

    switch(DSAUtil::allocIdentifier) {
    case DSAUtil::AI_ALLOC_WRAPPER_ANALYSIS:
        DSA_ADD_REQUIRED(usage, DSA_ALLOC_WRAPPER_ANALYSIS);
    break;
    default:
    break;
    }
}

inline bool DSAUtil::getCallees(const Function *F, FuncSetTy &callees)
{
    FOREACH_FUNC_CS(F, CS,
        bool ret = getCallees(CS, callees);
        if (!ret)
            return false;
    );

    return true;
}

inline bool DSAUtil::getICallees(const Function *F, FuncSetTy &icallees)
{
    FOREACH_FUNC_CS(F, CS,
        /* Same as above, but only for indirect calls */
        if (CS.getCalledFunction() == NULL) {
            icallees.clear();
            bool ret = getCallees(CS, icallees);
            if (!ret)
                return false;
            
            for (DSAUtil::FuncSetTy::iterator it  = icallees.begin(); 
                                              it != icallees.end(); 
                                            ++it) {
                const Function *callee = *it;
                if (!PassUtil::hasAddressTaken((Function*)callee)) {
                    /* this can not be a callee */
                    icallees.erase(callee);
                }
            }
            callsite_icallees.push_back(icallees);
        }
    );

    return true;
}

inline bool DSAUtil::getDCallees(const Function *F, FuncSetTy &dcallees)
{
    FOREACH_FUNC_CS(F, CS,
        if (CS.getCalledFunction() != NULL) {
            bool ret = getCallees(CS, dcallees);
            if (!ret)
                return false;
        }
    );

    return true;
}

inline bool DSAUtil::getCalleeEdges(const Function *F, CallEdgeVecTy &callEdges)
{
    FuncSetTy callees;
    FOREACH_FUNC_CS(F, CS,
        bool ret = getCallees(CS, callees);
        if (!ret)
            return false;
        CallEdge callEdge(CS, callees);
        callEdges.push_back(callEdge);
        callees.clear();
    );

    return true;
}


inline DSA_NODE* DSAUtil::getDSNode(const Function *F, const Value *V, GraphTypeTy type)
{
    #if LLVM_HAS_DSA
    DSGraph *graph = getDSGraph(F, type);
    if(graph->hasNodeForValue(V))
    {
	return graph->getNodeForValue(V).getNode(); 
    }
    else    
	return NULL;
    #else
	return NULL;
    #endif
}

inline DSA_NODE* DSAUtil::getDSNodeFromLocalDataStructure(const Function *F, const Value *V)
{
    #if LLVM_HAS_DSA
    DSGraph *graph = getDSGraph(F, LOCAL_GRAPH);
    DSNodeHandle *dsnh = NULL;
    if(graph->hasNodeForValue(V))
	dsnh = &(graph->getNodeForValue(V));
    else if(isa<Constant>(V))
	return NULL;
    else
	assert("No DSNode Value" && false);

    DSNode *dsn = dsnh->getNode();
    assert(dsn != NULL);

    return dsn;

    #else
	return NULL;
    #endif
}


inline DSCALLSITE DSAUtil::getDSCallSiteFromCallSite(const Function *F, CallSite CS, GraphTypeTy type)
{
    #if LLVM_HAS_DSA
    DSGraph *graph = getDSGraph(F, type);
    return graph->getDSCallSiteForCallSite(CS);
    #endif
}

inline bool DSAUtil::isGlobalValue(const Function *F, const Value *V)
{
    #if LLVM_HAS_DSA
    DSGraph *graph = getDSGraph(F, LOCAL_GRAPH);
    DSNodeHandle *dsnh = NULL;
    if(graph->hasNodeForValue(V))
	dsnh = &(graph->getNodeForValue(V));
    else if(isa<Constant>(V))
	return false;
    else
	assert("No DSNode Value" && false);

    DSNode *dsn = dsnh->getNode();
    assert(dsn != NULL);

    if(dsn->isGlobalNode())
    {
	return true;
    }
    else
    {
	return false;
    }
    #else
	return false;
    #endif
}

inline bool DSAUtil::getCalleesCTA(CallSite &CS, FuncSetTy &callees)
{
DSA_OR_RETURN(false,
    DSA_CALLTARGETS_ANALYSIS *cta = DSA_CALLTARGETS(P);

    for (std::vector<const Function*>::iterator it = cta->begin(CS), end = cta->end(CS); it != end; ++it) {
        if ((*it)->isIntrinsic())
            continue;
        callees.insert(*it);
    }

    return true;
);
}

inline bool DSAUtil::getCalleesGEN(CallSite &CS, FuncSetTy &callees, CalleeMapperTy calleeMapper)
{
    static std::map<unsigned long, FuncSetTy> typeMap;
    static std::map<unsigned long, FuncSetTy>::iterator typeMapIt;
    static FuncSetTy varArgFuncSet;
    unsigned long typeHash;

    if (CS.getCalledFunction())
        return getCalleesDCA(CS, callees);

    if (typeMap.size() == 0) {
        FOREACH_FUNC(*M, F,
            if (!PassUtil::hasAddressTaken((Function*)F)) {
            	if (calleeMapper != DSAUtil::CM_ALLTARGETS_ANALYSIS)
                    continue;
                if (F->hasInternalLinkage() || F->hasPrivateLinkage())
                    continue;
            }

            TYPECONST FunctionType *fType = F->getFunctionType();
            if (fType->isVarArg()) {
                varArgFuncSet.insert(F);
                continue;
            }
            typeHash = getCalleeTypeHash(fType, calleeMapper);
            typeMapIt = typeMap.find(typeHash);
            if (typeMapIt == typeMap.end()) {
                FuncSetTy fSet;
                fSet.insert(F);
                typeMap.insert(std::pair<unsigned long, FuncSetTy>(typeHash, fSet));
            }
            else {
                typeMapIt->second.insert(F);
            }
        );
    }
    callees.insert(varArgFuncSet.begin(), varArgFuncSet.end());
    TYPECONST FunctionType *fType = dyn_cast<FunctionType>(CS.getCalledValue()->getType()->getContainedType(0));
    assert(fType);
    if (fType->isVarArg())
        return true;
    typeHash = getCalleeTypeHash(fType, calleeMapper);
    typeMapIt = typeMap.find(typeHash);
    if (typeMapIt == typeMap.end()) {
        /* No suitable target found, classify it as dead code (e.g., a function pointer set to NULL and never used). */
        return true;
    }
    FuncSetTy fSet = typeMapIt->second;
    callees.insert(fSet.begin(), fSet.end());

    return true;
}

inline bool DSAUtil::getCalleesSPT(CallSite &CS, FuncSetTy &callees)
{
#ifdef USE_SLICER
    SlicerPass * slicer = P->getAnalysisIfAvailable<SlicerPass>();
    if (!slicer)
        return false;
    std::map<Instruction*, std::set<Function*> > *calleesMap = &slicer->calleesMap;
    std::map<Instruction*, std::set<Function*> >::iterator it;
    it = calleesMap->find(CS.getInstruction());
    if (it == calleesMap->end())
        return true;
    std::set<Function*> set = it->second;
    for (std::set<Function*>::iterator it2=set.begin();it2 != set.end(); it2++) {
        const Function *F = *it2;
        callees.insert(F);
    }
    return true;
#else
    return false;
#endif
}

inline bool DSAUtil::getCalleesCGA(CallSite &CS, FuncSetTy &callees)
{
DSA_OR_RETURN(false,
    const DSCallGraph *callGraph = DSA_CALLGRAPH(P);

    DSCallGraph::callee_iterator csi = callGraph->callee_begin(CS);
    DSCallGraph::callee_iterator cse = callGraph->callee_end(CS);
    while(csi != cse) {
        callees.insert(*csi);
        csi++;
    }

    return true;
);
}

inline bool DSAUtil::checkEscapeVar(const Value *V)
{
    return DSA_DSAAESCAPEVALUE(P, V);
}

inline void DSAUtil::checkEscapeVar(ValueVecTy nodeValueList, ValueVecTy &escapedVariable)
{
    ValueVecTy::iterator it;	

    it = nodeValueList.begin();
    while( it != nodeValueList.end())
    {
	if(DSA_DSAAESCAPEVALUE(P, *it))
	{
	    escapedVariable.push_back(*it);
	}
	it++;
    }
}



inline bool DSAUtil::getCalleesDCA(CallSite &CS, FuncSetTy &callees)
{
    if (CS.getCalledFunction()) {
        callees.insert(CS.getCalledFunction());
    }
    return true;
}

inline unsigned long DSAUtil::getCalleeTypeHash(TYPECONST Type* type, CalleeMapperTy calleeMapper)
{
    unsigned long hash = 0;
    TYPECONST FunctionType *fType;

    switch(calleeMapper) {
    case DSAUtil::CM_TYPETARGETS_ANALYSIS:
        /* All targets with the same type in the same bucket.
         * Note: higher DSA_UTIL_TYPE_HASH_MAX_LEVEL values improve accuracy, but
         * reduce conservativeness due to type transformations possibly operated
         * by LLVM. DSA_UTIL_TYPE_HASH_MAX_LEVEL=0 is the most conservative value,
         * but converges to CM_PARAMTARGETS_ANALYSIS.
         */
        hash = PassUtil::getTypeHash(type, DSA_UTIL_TYPE_HASH_MAX_LEVEL);
    break;
    case DSAUtil::CM_PARAMTARGETS_ANALYSIS:
        /* All targets with the same number parameters in the same bucket. */
        hash = type->getNumContainedTypes();
        fType = dyn_cast<FunctionType>(type);
        assert(fType);
        if (!fType->getReturnType()->isVoidTy()) {
            hash += 1000;
        }
    break;
    case DSAUtil::CM_ALLTARGETS_ANALYSIS:
    case DSAUtil::CM_ATTARGETS_ANALYSIS:
        /* All targets in the same bucket. */
        hash = 1;
    break;
    default:
        assert(0);
    break;
    }
    return hash;
}

inline bool DSAUtil::getCallees(CallSite &CS, FuncSetTy &callees)
{
    bool ret;

    switch(calleeMapper) {
    case DSAUtil::CM_CALLTARGETS_ANALYSIS:
        ret = getCalleesCTA(CS, callees);
    break;
    case DSAUtil::CM_TYPETARGETS_ANALYSIS:
    case DSAUtil::CM_PARAMTARGETS_ANALYSIS:
    case DSAUtil::CM_ALLTARGETS_ANALYSIS:
    case DSAUtil::CM_ATTARGETS_ANALYSIS:
        ret = getCalleesGEN(CS, callees, calleeMapper);
    break;
    case DSAUtil::CM_SPTTARGETS_ANALYSIS:
        ret = getCalleesSPT(CS, callees);
    break;
    case DSAUtil::CM_CALLGRAPH_ANALYSIS:
        ret = getCalleesCGA(CS, callees);
    break;
    default:
        ret = getCalleesDCA(CS, callees);
    break;
    }
    return ret;
}

inline bool DSAUtil::getCallSites(const Function *F, std::vector<CallSite> &callSites)
{
    fetchActualCallers();
    ActualCallersTy::iterator it = ActualCallers.find(F);
    if (it == ActualCallers.end()) {
        return false;
    }
    callSites = it->second;
    return true;
}

inline bool DSAUtil::getCallers(const Function *F, FuncSetTy &callers)
{
    fetchActualCallers();
    ActualCallersFuncSetTy::iterator it = ActualCallersFuncSet.find(F);
    if (it == ActualCallersFuncSet.end()) {
        return false;
    }
    callers = it->second;
    return true;
}

inline bool DSAUtil::getCallStacks(const Function *F,
    std::vector<FuncVecTy> &callStacks, unsigned limit)
{
    static unsigned level = 0;
    static std::set<const Function *> visited;
    FuncSetTy callers;
    if (level == 0) {
        visited.clear();
    }
    getCallers(F, callers);
    if (callers.size() == 0 || visited.find(F) != visited.end() || (limit && limit == visited.size()+1)) {
        FuncVecTy cstack;
        cstack.push_back(F);
        callStacks.push_back(cstack);
        return true;
    }
    level++;
    visited.insert(F);
    for (FuncSetTy::iterator it = callers.begin(); it != callers.end(); ++it) {
        const Function *caller = *it;
        std::vector<FuncVecTy> nestedCallStacks;
        getCallStacks(caller, nestedCallStacks, limit);
        callStacks.insert(callStacks.end(), nestedCallStacks.begin(), nestedCallStacks.end());
        nestedCallStacks.clear();
    }
    level--;
    visited.erase(F);
    for (unsigned i=0;i<callStacks.size();i++) {
        callStacks[i].push_back(F);
    }
    return true;
}

inline bool DSAUtil::getCallStacks(const CallSite &CS,
    std::vector<FuncVecTy> &callStacks, unsigned limit)
{
    if (!CS.getCalledFunction())
        return false;
    getCallStacks(CS.getInstruction()->getParent()->getParent(),
        callStacks, limit);
    for (unsigned i=0;i<callStacks.size();i++) {
        callStacks[i].push_back(CS.getCalledFunction());
    }
    return true;
}

inline bool DSAUtil::getCallStacksFunctions(const Function *F, FuncSetTy &functions, unsigned limit)
{
    std::vector<FuncVecTy> callStacks;
    getCallStacks(F, callStacks, limit);
    for (unsigned i=0;i<callStacks.size();i++) {
        FuncVecTy &callStack = callStacks[i];
        for (unsigned j=0;j<callStack.size();j++) {
            functions.insert(callStack[j]);
        }
    }
    return true;
}

inline void DSAUtil::dumpCallGraph()
{
    FuncSetTy funcs;
    for (Module::iterator I = M->begin(), E = M->end(); I != E; ++I) {
        Function *F = I;
        if (F->isIntrinsic())
            continue;
        getCallees(F, funcs);
        errs() << "CallGraph[" << F->getName() << "]";
        for (FuncSetTy::iterator i = funcs.begin(),
             e = funcs.end(); i != e; ++i) {
          errs() << " ";
          errs() << (*i)->getName();
        }
        errs() << "\n";
        funcs.clear();
    }
}

inline void DSAUtil::dumpInverseCallGraph()
{
    fetchActualCallers();
    for (ActualCallersFuncSetTy::iterator ii = ActualCallersFuncSet.begin(),
           ee = ActualCallersFuncSet.end(); ii != ee; ++ii) {
        errs() << "InverseCallGraph[" << ii->first->getName() << "]";
        for (FuncSetTy::iterator i = ii->second.begin(),
             e = ii->second.end(); i != e; ++i) {
          errs() << " ";
          errs() << (*i)->getName();
        }
        errs() << "\n";
    }
}

inline std::set<std::string>::iterator DSAUtil::getAllocatorIterator(bool alloc, bool begin)
{
    std::set<std::string>::iterator ret;

    switch(DSAUtil::allocIdentifier) {
    case DSAUtil::AI_ALLOC_WRAPPER_ANALYSIS:
        ret = getAllocatorIteratorAWA(alloc, begin);
    break;
    default:
        ret = emptyStringSet.begin();
    break;
    }

    return ret;
}

inline std::set<std::string>::iterator DSAUtil::getAllocatorIteratorAWA(bool alloc, bool begin)
{
DSA_OR_RETURN(emptyStringSet.begin(),
    DSA_ALLOC_WRAPPER_ANALYSIS *awa = DSA_ALLOC_WRAPPERS(P);
    if (alloc) {
        return begin ? awa->alloc_begin() : awa->alloc_end();
    }
    return begin ? awa->dealloc_begin() : awa->dealloc_end();
);
}

inline void DSAUtil::fetchActualCallers()
{
    if (ActualCallers.size() > 0) {
        return;
    }

    FuncSetTy funcs;

    for (Module::iterator I = M->begin(), E = M->end(); I != E; ++I) {
        Function *F = I;
        if (F->isIntrinsic())
            continue;
        FOREACH_FUNC_CS(F, CS,
            getCallees(CS, funcs);
            for (FuncSetTy::iterator it = funcs.begin(),
                e = funcs.end(); it != e; ++it) {
                addActualCaller(ActualCallers, *it, CS);
            }
            funcs.clear();
        );
    }
}

inline void DSAUtil::addActualCaller(ActualCallersTy &ActualCallers, const Function *F, const CallSite &callSite)
{
    ActualCallersTy::iterator it = ActualCallers.find(F);
    if (it == ActualCallers.end()) {
        std::vector<CallSite> callSites;
        FuncSetTy callers;
        callSites.push_back(callSite);
        callers.insert(callSite.getInstruction()->getParent()->getParent());
        ActualCallers.insert(std::pair<const Function*, std::vector<CallSite> >(F, callSites));
        ActualCallersFuncSet.insert(std::pair<const Function*, FuncSetTy>(F, callers));
        return;
    }
    ActualCallersFuncSetTy::iterator it2 = ActualCallersFuncSet.find(F);
    assert(it2 != ActualCallersFuncSet.end());
    it->second.push_back(callSite);
    it2->second.insert(callSite.getInstruction()->getParent()->getParent());
}

class VariableNodeState
{
private:
    bool globalNode;
    bool heapNode;
    bool stackNode;
    bool arrayNode;
    bool ptrToIntNode;
    bool intToPtrNode;
    llvm::DSAUtil::ValueVecTy valueList;
public:
    ~VariableNodeState()
    {
	if(valueList.size() > 0)
	{
	    valueList.clear();
	}	
    }
#if LLVM_HAS_DSA
    void fillNodeMetaData(DSNode *node)
    {
	globalNode = node->isGlobalNode();
	heapNode = node->isHeapNode();
	stackNode = node->isAllocaNode();
	arrayNode = node->isArrayNode();
	ptrToIntNode = node->isPtrToIntNode();
	intToPtrNode = node->isIntToPtrNode();
    }	
#else
    void fillNodeMetaData()
    {
	globalNode = false;
	heapNode = false;
	stackNode = false;
	arrayNode = false;
	ptrToIntNode = false;
	intToPtrNode = false;
    }
#endif

    bool isGlobalNode()
    {
	return globalNode;
    }

    bool isHeapNode()
    {
	return heapNode;
    }

    bool isStackNode()
    {
	return stackNode;
    }

    bool isArrayNode()
    {
	return arrayNode;
    }

    bool isPtrToIntNode()
    {
	return ptrToIntNode;
    }

    bool isIntToPtrNode()
    {
	return intToPtrNode;
    }

    void setValueVecTy(DSAUtil::ValueVecTy valueList)
    {
	if(this->valueList.size() > 0)
	{
	    this->valueList.clear();
	}
	this->valueList = DSAUtil::ValueVecTy(valueList);
    }

    DSAUtil::ValueVecTy getValueVecTy()
    {
	return valueList;
    }

    void reinitialiseVector()
    {
	if(valueList.size() > 0)
	{
	    valueList.clear();
	}
    }
};

inline bool DSAUtil::getEscapedVar(const Function *F, VariableVecTy 
    &escapedVariables, VariableVecTy &incompleteVal, int &totalVar, 
    int &incompleteCount)
{
#if LLVM_HAS_DSA
    DSGraph* localGraph = getDSGraph(F, LOCAL_GRAPH);	
    DSGraph::node_iterator n_start = localGraph->node_begin();
    DSGraph::node_iterator n_end = localGraph->node_end();
    ValueVecTy nodeValueList, escapeList;

    totalVar = 0;
    incompleteCount = 0;

    while(n_start != n_end)
    {
	DSA_DSNodeValue(n_start, nodeValueList);
	totalVar += nodeValueList.size();

	if(nodeValueList.size() > 0)
	{
	    VariableNodeState vns;
	    DSA_FILLNODEDETAILS(vns, n_start);

	    if(DSA_DSNodeIncompleteCheck(n_start))
	    {
		vns.setValueVecTy(nodeValueList);	
		incompleteVal.push_back(vns);
		incompleteCount += nodeValueList.size(); 
		nodeValueList.clear();
	    }
	    else
	    {
		checkEscapeVar(nodeValueList, escapeList);
		vns.setValueVecTy(escapeList);	
		escapedVariables.push_back(vns);
		nodeValueList.clear();
		escapeList.clear();
	    }
	}
	n_start++;
    }
    return true;	
#else
    return false;
#endif
}
}

#endif /* _DSA_COMMON_H_ */

