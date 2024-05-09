#pragma once

#include <capstone/capstone.h>

class ICapstoneHeuristic {
public:
    virtual bool InsnIsProcedureEntry(const cs_insn* pInsn) const = 0;
    virtual bool InsnIsProcedureExit(const cs_insn* pInsn) const = 0;
};