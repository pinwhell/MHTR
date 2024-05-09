#pragma once

#include <capstone/capstone.h>

class ICapstoneUtility {
public:
    virtual bool InsnHasRegister(const cs_insn* pIns, uint16_t reg) const = 0;
    virtual uint64_t InsnGetImmByIndex(const cs_insn* pIns, size_t index) const = 0;
    virtual uint16_t InsnGetPseudoDestReg(const cs_insn* pIns) const = 0;
    virtual bool InsnIsBranch(const cs_insn* pInsn) const = 0;
    virtual bool InsnHasCondition(const cs_insn* pInsn) const = 0;
};
