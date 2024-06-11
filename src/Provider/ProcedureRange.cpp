#include <MHTR/Provider/ProcedureRange.h>
#include <stdexcept>

using namespace MHTR;

ProcedureRangeProvider::ProcedureRangeProvider(ICapstoneProvider* cstoneProvider, IProcedureEntryProvider* procEntryProvider, size_t defProcSize)
    : mCStoneProvider(cstoneProvider)
    , mProcEntryProvider(procEntryProvider)
    , mDefProcSize(defProcSize)
{}

Range ProcedureRangeProvider::GetRange() {
    
    uint64_t procEntry = mProcEntryProvider->GetEntry();

    if (mDefProcSize != 0)
        // Procedure size seems already known
        return Range((void*)mProcEntryProvider->GetEntry(), mDefProcSize);

    uint64_t procEnd = 0;
    ICapstone* cstone = mCStoneProvider->GetInstance();
    ICapstoneHeuristic* heuristic = cstone->getHeuristic();

    cstone->InsnForEach((void*)procEntry, [&](const CsInsn& curr) {
        auto currDisp = curr->address;
        uint64_t currAddr = procEntry + currDisp;

        if (heuristic->InsnIsProcedureEntry(&curr.mInsn) && currDisp)
        {
            // At this point, seems current instruciton 
            // is a procedure entry from anoter procedure
            // probably we missed the epilog of the 
            // mProcEntry or, it didnt have any, 
            // just like the case of non-return functions

            return false;
        }

        procEnd = currAddr + curr->size;

        return heuristic->InsnIsProcedureExit(&curr.mInsn) == false;
        }, 0);

    if (!procEnd)
        throw std::runtime_error("procedure end lookup failed");

    return Range((void*)procEntry, procEnd - procEntry);
}