#pragma once

#include <capstone/capstone.h>

class CapstoneDismHandle {
public:
    CapstoneDismHandle(cs_insn* pFirst, size_t count);
    ~CapstoneDismHandle();

    CapstoneDismHandle(const CapstoneDismHandle&) = delete;
    CapstoneDismHandle(CapstoneDismHandle&&) noexcept = default;
    CapstoneDismHandle& operator=(const CapstoneDismHandle&) = delete;
    CapstoneDismHandle& operator=(CapstoneDismHandle&&) noexcept = default;

    operator bool();

    cs_insn* mpFirst;
    cs_insn* mpEnd;
    size_t mCount;
};
