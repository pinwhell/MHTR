#pragma once

#include <stdexcept>
#include <CStone/ICapstone.h>
#include <CStone/Factory.h>
#include <CStone/Utility.h>

class DismFailedException : public std::runtime_error {
public:
    DismFailedException(const std::string& what);
};

class Capstone : public ICapstone {
public:
    Capstone(cs_arch arch, cs_mode mode, bool bDetailedDisasm = true);
    ~Capstone();

    CapstoneDismHandle Disassemble(const void* _start, size_t nBytes, uint64_t pcAddr = 0) override;
    CsInsn DisassembleOne(const void* start, uint64_t pcAddr = 0) override;
    void InsnForEach(const void* start, std::function<bool(const CsInsn& insn)> callback, size_t buffSize = SIZE_MAX, uint64_t pcAddr = 0) override;
    ICapstoneUtility* getUtility() override;

    csh mhCapstone;
};