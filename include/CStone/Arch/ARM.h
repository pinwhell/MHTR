#pragma once

#include <CStone/CStone.h>
#include <CStone/Utility.h>

class ARM32CapstoneUtility : public ICapstoneUtility {
public:
    bool InsnHasRegister(const cs_insn* pIns, uint16_t reg) const override;
    uint64_t InsnGetImmByIndex(const cs_insn* pIns, size_t index) const override;
    uint16_t InsnGetPseudoDestReg(const cs_insn* pIns) const override;

    CapstoneUtility mBaseUtility;
};

class ARM32Capstone : public ICapstone {
public:
    ARM32Capstone(bool mbThumb = false, bool bDetailedInsn = true);

    ICapstoneUtility* getUtility() override;
    CapstoneDismHandle Disassemble(const void* start, size_t nBytes, uint64_t pcAddr = 0) override;
    CsInsn DisassembleOne(const void* start, uint64_t pcAddr = 0) override;
    void InsnForEach(const void* start, std::function<bool(const CsInsn& insn)> callback, size_t buffSize = SIZE_MAX, uint64_t pcAddr = 0) override;

    Capstone mCapstone;
    ARM32CapstoneUtility mUtility;
};