#pragma once

#include <capstone/capstone.h>

struct CsInsn {
    CsInsn();

    const cs_insn* operator->() const;

    cs_insn mInsn;
private:
    cs_detail mDetail;
};