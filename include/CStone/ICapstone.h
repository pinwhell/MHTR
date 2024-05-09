#pragma once

#include <cstdint>
#include <functional>
#include <CStone/IUtility.h>
#include <CStone/DismHandle.h>
#include <CStone/Insn.h>
#include <CStone/IHeuristic.h>

class ICapstone {
public:
    virtual ICapstoneUtility* getUtility() = 0;
    virtual ICapstoneHeuristic* getHeuristic() = 0;
    virtual CapstoneDismHandle Disassemble(const void* start, size_t nBytes, uint64_t pcAddr = 0) = 0;
    virtual CsInsn DisassembleOne(const void* start, uint64_t pcAddr = 0) = 0;
    virtual void InsnForEach(const void* start, std::function<bool(const CsInsn& insn)> callback, uint64_t pcAddr = 0, size_t buffSize = SIZE_MAX) = 0;
};
