#pragma once

#include <vector>
#include <cstdint>
#include <functional>
#include <capstone/capstone.h>

class CapstoneUtility {
public:
    template<typename CSInsDetailT, typename CSInsDetailOpT>
    static void InsnForEachOperand(CSInsDetailT& pInstDetail, std::function<bool(CSInsDetailOpT& op)> callback)
    {
        for (int i = 0; i < pInstDetail.op_count && callback(pInstDetail.operands[i]); i++)
            ;
    }

    template<typename CSInsDetailT>
    static void InsnForEachRegister(CSInsDetailT& pInstDetail, std::function<bool(uint16_t reg)> callback)
    {
        InsnForEachOperand<CSInsDetailT, decltype(pInstDetail.operands[0])>(pInstDetail, [&](const auto& op) -> bool {
            if (op.type == CS_OP_MEM)
                return callback(op.mem.base) && callback(op.mem.index);

            return callback(op.reg);
            });
    }

    template<typename CSInsDetailT>
    static bool InsnHasRegister(CSInsDetailT& pInstDetail, uint16_t reg)
    {
        bool bHasReg = false;

        InsnForEachRegister<CSInsDetailT>(pInstDetail, [&](uint16_t _reg) -> bool {
            return !(bHasReg = (_reg == reg));
            });

        return bHasReg;
    }

    template<typename CSInsDetailT>
    static std::vector<uint16_t> InsnGetAllRegisters(CSInsDetailT& pInstDetail)
    {
        std::vector<uint16_t> regs;

        InsnForEachRegister<CSInsDetailT>(pInstDetail, [&](uint16_t _reg) -> bool {
            regs.push_back(_reg);
            return true;
            });

        return regs;
    }

    template<size_t T_REG_INVALID, typename CSInsDetailT>
    static std::vector<uint64_t> InsnGetAllImms(CSInsDetailT& pInstDetail)
    {
        std::vector<uint64_t> result;

        InsnForEachOperand<CSInsDetailT, decltype(pInstDetail.operands[0])>(pInstDetail, [&](const auto& op) -> bool {
            switch (op.type)
            {
            case CS_OP_IMM:
                result.push_back(op.imm);
                break;

            case CS_OP_MEM:
                if (op.mem.index == T_REG_INVALID)
                    result.push_back(op.mem.disp);
                break;
            }

            return true;
            });

        return result;
    }
};