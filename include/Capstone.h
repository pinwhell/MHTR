#pragma once

#include <stdexcept>
#include <capstone/capstone.h>
#include <string>
#include <memory>
#include <functional>

enum class ECapstoneArchMode {
    UNDEFINED,
    X86_16,
    X86_32,
    X86_64,
    ARM32_ARM,
    ARM32_THUMB,
    AARCH64_ARM,
};

struct CsInsn {
    CsInsn();

    const cs_insn* operator->() const;

    cs_insn mInsn;
private:
    cs_detail mDetail;
};

class CapstoneCreationFailedException : public std::runtime_error {
public:
    CapstoneCreationFailedException(const std::string& what);
};

class DismFailedException : public std::runtime_error {
public:
    DismFailedException(const std::string& what);
};

class ICapstoneUtility {
public:
    virtual bool InsnHasRegister(const cs_insn* pIns, uint16_t reg) const = 0;
    virtual uint64_t InsnGetImmByIndex(const cs_insn* pIns, size_t index) const = 0;
    virtual uint16_t InsnGetPseudoDestReg(const cs_insn* pIns) const = 0;
};

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
                if(op.mem.index == T_REG_INVALID)
                    result.push_back(op.mem.disp);
                break;
            }

            return true;
            });

        return result;
    }
};

class ARM32CapstoneUtility : public ICapstoneUtility {
public:
    bool InsnHasRegister(const cs_insn* pIns, uint16_t reg) const override;
    uint64_t InsnGetImmByIndex(const cs_insn* pIns, size_t index) const override;
    uint16_t InsnGetPseudoDestReg(const cs_insn* pIns) const override;

    CapstoneUtility mBaseUtility;
};

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

class ICapstone {
public:
    virtual ICapstoneUtility* getUtility() = 0;
    virtual CapstoneDismHandle Disassemble(const void* start, size_t nBytes, uint64_t pcAddr = 0) = 0;
    virtual CsInsn DisassembleOne(const void* start, uint64_t pcAddr = 0) = 0;
    virtual void InsnForEach(const void* start, std::function<bool(const CsInsn& insn)> callback, size_t buffSize = SIZE_MAX, uint64_t pcAddr = 0) = 0;
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

class ICapstoneFactory {
public:
    virtual std::unique_ptr<ICapstone> CreateCapstoneInstance(bool bDetailedInst = true) = 0;
};


class CapstoneFactory : public ICapstoneFactory
{
public:
    CapstoneFactory(ECapstoneArchMode archMode);

    std::unique_ptr<ICapstone> CreateCapstoneInstance(bool bDetailedInst = true) override;

    ECapstoneArchMode mArchMode;
};