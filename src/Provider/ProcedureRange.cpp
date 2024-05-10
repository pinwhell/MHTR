#include <Provider/ProcedureRange.h>

#include <stdexcept>

ProcedureRangeProvider::ProcedureRangeProvider(ICapstone* capstone, IProcedureEntryProvider* procEntryProvider)
    : mCapstone(capstone)
    , mProcEntryProvider(procEntryProvider)
{}

BufferView ProcedureRangeProvider::GetRange() {
    uint64_t procEntry = mProcEntryProvider->GetEntry();
    uint64_t procEnd = 0;
    ICapstoneHeuristic* heuristic = mCapstone->getHeuristic();

    mCapstone->InsnForEach((void*)procEntry, [&](const CsInsn& curr) {
        auto currDisp = curr->address;
        uint64_t currAddr = procEntry + currDisp;

        procEnd = currAddr + curr->size;

        if (heuristic->InsnIsProcedureEntry(&curr.mInsn) && currDisp)
        {
            // At this point, seems current instruciton 
            // is a procedure entry from anoter procedure
            // probably we missed the epilog of the 
            // mProcEntry or, it didnt have any, 
            // just like the case of non-return functions

            return false;
        }

        return heuristic->InsnIsProcedureExit(&curr.mInsn) == false;
        }, 0);

    if (!procEnd)
        throw std::runtime_error("procedure end lookup failed");

    return BufferView((void*)procEntry, procEnd - procEntry);
}