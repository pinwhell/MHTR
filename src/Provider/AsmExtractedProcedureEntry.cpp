#include <Provider/AsmExtractedProcedureEntry.h>

#include <unordered_set>
#include <string>

#include <MultiException.h>

AsmExtractedProcedureEntryProvider::AsmExtractedProcedureEntryProvider(ICapstoneProvider* cstoneProvider, IAddressesProvider* adressesProvider)
    : mCStoneProvider(cstoneProvider)
    , mAddressesProvider(adressesProvider)
{}

uint64_t AsmExtractedProcedureEntryProvider::GetEntry()
{
    std::vector<uint64_t> addresses = mAddressesProvider->GetAllAddresses();
    std::unordered_set<uint64_t> procAddresses;
    ICapstone* cstone = mCStoneProvider->GetInstance();
    ICapstoneUtility* utility = cstone->getUtility();

    std::vector<std::string> allErrs;

    for (const auto addr : addresses)
    {
        try {
            auto insn = cstone->DisassembleOne((void*)addr, 0);

            if (utility->InsnIsBranch(&insn.mInsn) == false)
            {
                // Treating the address as 
                // a normal procedure entry

                procAddresses.insert(addr);
                continue;
            }

            // Seems to be a type of branch. 
            // lets extract the disp

            int64_t callDisp = utility->InsnGetImmByIndex(&insn.mInsn, 0);
            uint64_t callDst = addr + callDisp;

            // Successfully solved, saving

            procAddresses.insert(callDst);

        }
        catch (std::exception& e)
        {
            allErrs.push_back(e.what());
        }
    }

    if (procAddresses.size() > 1)
        throw "multiple procedure entry found";

    if (procAddresses.size() < 1)
        throw MultiException(allErrs);

    return *procAddresses.begin();
}