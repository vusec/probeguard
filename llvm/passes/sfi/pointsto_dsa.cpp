#include "pointsto.h"

using namespace llvm;

#undef DEBUG_TYPE
#define DEBUG_TYPE "sfi"
#define log(M) DEBUG(dbgs() << "SFIPass: DSA: " << M << "\n")

void PointsToDSA::init(Pass *P, Module *M, std::string SFIFuncSection)
{
    StaticPointsTo::init(P, M, SFIFuncSection);

#ifdef STEENSGAARD
    // Get the global DSGraph. Steensgaard merges together all
    // function-local DSGraphs so we can track our DSNode across functions.
    dsg = P->getAnalysis<SteensgaardDataStructures>().getResultGraph();
#else
    dsau = new DSAUtil();
    dsau->init(P, M);
#endif

    /*
#ifndef STEENSGAARD
    DSGraph *dsg = dsau->getDSGraph(M->getFunction("main"), DSAUtil::TOP_DOWN_GRAPH)->getGlobalsGraph();
#endif
    for (Module::global_iterator it = M->global_begin(); it != M->global_end(); ++it)
    {
        GlobalVariable *G = it;
        if (G->getName().find("globby") != StringRef::npos)
        {
            DSNodeHandle dsnh = dsg->getNodeForValue(G);
            DSNode *dsn = dsnh.getNode();
            dummyPassLog("GLOB " << G->getName() << " " << dsn << "   " << *G);
            //dsn_tracked = dsn;
        }
    }
    */

}

void PointsToDSA::addRequired(AnalysisUsage &U)
{
#ifdef STEENSGAARD
    log("Adding req steensgaard");
    U.addRequired<SteensgaardDataStructures>();
#else
    log("Adding req TDDataStructures");
    U.addRequired<TDDataStructures>();
    U.addRequired<dsa::CallTargetFinder<TDDataStructures> >();
#endif
}

void PointsToDSA::findTrackingNodes()
{
    std::set<DSNode *> myset;
    myset.clear();
    dsn_tracking.clear();
    std::map<Function *, unsigned long> func_done;
    std::map<Function *, DSAUtil::FuncSetTy> cg_funcs;

    // Find the creation points of all secure nodes (which, for steensgaard, are
    // immidiately the global (ie context-insensitve) nodes.
    Module::FunctionListType &functionList = M->getFunctionList();
    for (Module::iterator it = functionList.begin(); it != functionList.end(); ++it) {
        Function *F = it;
        if (!std::string(F->getSection()).compare(SFIFuncSection))
            continue;
        if (F->isIntrinsic() || F->empty() || F->getName() == "secure_alloc" || F->getName() == "secure_free")
            continue;
        func_done[F] = 0;
        for (inst_iterator it2 = inst_begin(F), E = inst_end(F); it2 != E; ++it2) {
            Instruction *I = &(*it2);

            CallInst *CI = dyn_cast<CallInst>(I);
            if (!CI)
                continue;
            Function *FC = CI->getCalledFunction();
            if (!FC)
                continue;
            if (FC->getName() == "secure_alloc")
            {
#ifdef STEENSGAARD
                DSNode *dsn = dsg->getNodeForValue(I).getNode();
#else
                DSNode *dsn = dsau->getDSNode(F, I, DSAUtil::TOP_DOWN_GRAPH);
#endif
                if (!dsn)
                    continue;
                dsn_tracking.insert(dsn);
                log("Now tracking " << dsn);
                Function *secalloc = M->getFunction("vmfunc_secure_malloc");
                assert(secalloc && "Cannot find vmfunc_secure_malloc!!");
                CI->setCalledFunction(secalloc);
                //func_done[F]++;
            }
            else if (FC->getName() == "secure_free")
            {
                log("Rewriting free " << *CI);
                Function *secfree = M->getFunction("vmfunc_secure_free");
                assert(secfree && "Cannot find vmfunc_secure_free!!");
                CI->setCalledFunction(secfree);
            }
        }
    }



#ifndef STEENSGAARD
    // Construct a callgraph we can work with.
    for (auto it = func_done.begin(), e = func_done.end(); it != e; it++)
    {
        Function *F = it->first;
        DSAUtil::FuncSetTy funcs;
        cg_funcs[F] = funcs;
        FOREACH_FUNC_CS(F, CS,
            DSAUtil::FuncSetTy csfuncs;
            dsau->getCalleesCTA(CS, csfuncs);
            for (DSAUtil::FuncSetTy::iterator it2 = csfuncs.begin(), e2 = csfuncs.end(); it2 != e2; it2++)
            {
                Function *CF = (Function*)*it2;
                if (func_done.find(CF) == func_done.end())
                    continue;
                log("CALL " << F->getName() << " -> " << CF->getName());
                cg_funcs[F].insert(CF);
            }
        );
    }

    // Find the matching nodes accross functions (without merging the actual
    // nodes, as steensgaard does.
    for (auto it = func_done.begin(), e = func_done.end(); it != e; it++)
    {
        Function *F = it->first;
        unsigned long count = it->second;
        if (count == dsn_tracking.size())
            continue;
        DSGraph *dsg = dsau->getDSGraph(F, DSAUtil::TOP_DOWN_GRAPH);
        //DSCallGraph *dscg = dsau->getCallDSGraph(F, DSAUtil::TOP_DOWN_GRAPH);
        log("F " << F->getName() << " " << F->getSection() << " " << count);

        /*
        for (auto it2 = func_done.begin(), e2 = func_done.end(); it2 != e2; it2++)
        {
            Function *F2 = it2->first;
            DSGraph *dsg2 = dsau->getDSGraph(F2, DSAUtil::TOP_DOWN_GRAPH);
            F->computeCalleeCallerMapping(


        }
        */
    }

#endif
}

bool PointsToDSA::instrPointsToTracked(Instruction *I)
{
    Value *v = NULL;

    LoadInst *LI = dyn_cast<LoadInst>(I);
    StoreInst *SI = dyn_cast<StoreInst>(I);
    CallInst *CI = dyn_cast<CallInst>(I);
    if (LI)
        v = LI->getPointerOperand();
    else if (SI)
        v = SI->getPointerOperand();
    else if (CI)
    {
        // We include functions as well as we need to switch for the
        // allocation. XXX do this in findDSNodes when scanning for these
        // secure allocations?
        Function *f = CI->getCalledFunction();
        if (!f)
            return false;
        //log("FUNCCALL " << CI->getCalledFunction()->isIntrinsic() << " " << *CI);

        if (f->getName() == "vmfunc_secure_malloc")
            v = CI;
        else if (f->getName() == "vmfunc_secure_free")
            v = CI->getOperand(0);
        else if (f->isIntrinsic())
            v = CI->getOperand(0); // XXX per func?
        else
            return false;
    }
    else
    {
        //log("Instr not load nor store: " << *I);
        return false;
    }

#ifdef STEENSGAARD
    DSNodeHandle dsnh = dsg->getNodeForValue(v);
    DSNode *dsn = dsnh.getNode();
#else
    DSNode *dsn = dsau->getDSNode(I->getParent()->getParent(), v, DSAUtil::TOP_DOWN_GRAPH);
#endif
    if (!dsn)
        return false;
    //if (!dsn->isHeapNode())
    //if (!dsn->isGlobalNode())
        //return false;

    //assert(dsn->isCompleteNode());

#if 0
    std::string s;
    if (dsn->isAllocaNode())     s += "a";
    if (dsn->isHeapNode())       s += "h";
    if (dsn->isGlobalNode())     s += "g";
    if (dsn->isExternFuncNode()) s += "E";
    if (dsn->isUnknownNode())    s += "u";
    if (dsn->isModifiedNode())   s += "m";
    if (dsn->isReadNode())       s += "r";
    if (dsn->isArrayNode())      s += "A";
    if (dsn->isCollapsedNode())  s += "c";
    if (dsn->isIncompleteNode()) s += "I";
    if (dsn->isCompleteNode())   s += "C";
    if (dsn->isExternalNode())   s += "e";
    if (dsn->isIntToPtrNode())   s += "i";
    if (dsn->isPtrToIntNode())   s += "p";
    if (dsn->isVAStartNode())    s += "V";

    DSGraph::NodeMapTy nm;
#ifndef STEENSGAARD
    DSGraph *dsg = dsau->getDSGraph(I->getParent()->getParent(), DSAUtil::TOP_DOWN_GRAPH);
#endif
    dsg->computeGToGGMapping(nm);
    log("## NEW INS " << *I << " @ " << I->getParent()->getParent()->getName());
    log("blabla " << dsn << " " << s << " " << dsn->getSize() << " " << dsn->getNumReferrers() << " " << dsn->getForwardNode() << " " << nm[dsn].getNode());

    /*
    for (DSNode::edge_iterator i = dsn->edge_begin(); i != dsn->edge_end(); i++)
    {
        unsigned key = i->first;
        DSNodeHandle val = i->second;
        log("edge " << key << " " << val.getNode());
    }
    */
    //return false;
    /*
    if (dsn->isIncompleteNode())
        log("Incomplete node " << dsn << " " << " " << dsn->getSize() << " " << dsn->getNumReferrers());
    else
        log("hcomplete node " << dsn << " " << " " << dsn->getSize() << " " << dsn->getNumReferrers());
    */
#endif
    return dsn_tracking.find(dsn) != dsn_tracking.end();
    //return dsn_tracked == dsn;
    //return dsn_tracked == dsn || dsn->isIncompleteNode();

}
