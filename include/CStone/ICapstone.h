#pragma once

#include <cstdint>
#include <functional>
#include <CStone/IUtility.h>
#include <CStone/DismHandle.h>
#include <CStone/Insn.h>

class ICapstone {
public:
    virtual ICapstoneUtility* getUtility() = 0;
    virtual CapstoneDismHandle Disassemble(const void* start, size_t nBytes, uint64_t pcAddr = 0) = 0;
    virtual CsInsn DisassembleOne(const void* start, uint64_t pcAddr = 0) = 0;
    virtual void InsnForEach(const void* start, std::function<bool(const CsInsn& insn)> callback, size_t buffSize = SIZE_MAX, uint64_t pcAddr = 0) = 0;
};
