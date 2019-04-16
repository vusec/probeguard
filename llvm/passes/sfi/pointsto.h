#ifndef POINTSTO_H
#define POINTSTO_H

#include <pass.h>
#include <common/dsa_common.h>

// Toggles between TD (with own merge) and complete context-insensitive merge
// XXX: expose both at runtime?
// XXX currently broken
#define STEENSGAARD

class StaticPointsTo {

    protected:
        llvm::Module *M;
        std::string SFIFuncSection;
    public:
        StaticPointsTo() {}

        virtual void init(llvm::Pass *P, llvm::Module *M, std::string SFIFuncSection)
        {
            this->M = M;
            this->SFIFuncSection = SFIFuncSection;
        }

        virtual void addRequired(AnalysisUsage &U) = 0;
        virtual void findTrackingNodes() = 0;
        virtual bool instrPointsToTracked(llvm::Instruction *I) = 0;
};

class PointsToDSA : public StaticPointsTo {
    private:
        std::set<llvm::DSNode *> dsn_tracking;
#ifdef STEENSGAARD
        DSGraph *dsg;
#else
        DSAUtil *dsau;
#endif
    public:
        PointsToDSA() : StaticPointsTo(), dsn_tracking() {}
        void init(llvm::Pass *P, llvm::Module *M, std::string SFIFuncSection);
        void addRequired(AnalysisUsage &U);
        void findTrackingNodes();
        bool instrPointsToTracked(llvm::Instruction *I);
};

#endif
