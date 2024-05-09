#include <CStone/CStone.h>
#include <CStone/Factory.h>
#include <CStone/Provider.h>
#include <CStone/Arch/ARM.h>

#include <fmt/core.h>

static bool InsnIsBranch(const cs_insn* pInsn)
{
    bool bIsBranch = pInsn->id == ARM_INS_B || pInsn->id == ARM_INS_BX;
    bool bIsBranchLink = pInsn->id == ARM_INS_BL || pInsn->id == ARM_INS_BLX;
    bool bIsBranchAny = bIsBranch || bIsBranchLink;

    return bIsBranchAny;
}

static bool InsnHasCondition(const cs_insn* pInsn)
{
    return pInsn->detail->arm.cc != ARMCC_AL;
}

Capstone::Capstone(cs_arch arch, cs_mode mode, bool bDetailedDisasm)
    : mhCapstone(0)
{
    if (cs_err err = cs_open(arch, mode, &mhCapstone)) // != CS_ERR_OK(0)
        throw std::runtime_error(fmt::format("Capstone Arch:{},Mode:{} {}", (int)arch, (int)mode, cs_strerror(err)));

    if (bDetailedDisasm)
        cs_option(mhCapstone, CS_OPT_DETAIL, CS_OPT_ON);
}

Capstone::~Capstone()
{
    if (mhCapstone)
        cs_close(&mhCapstone);
}

CapstoneDismHandle Capstone::Disassemble(const void* _start, size_t nBytes, uint64_t pcAddr)
{
    const uint8_t* start = (const uint8_t*)_start;
    cs_insn* startIns = nullptr;

    size_t nInstCount = cs_disasm(mhCapstone, start, nBytes, pcAddr, 0, &startIns);

    if (nInstCount < 1)
        throw DismFailedException(fmt::format("Addr:{},nBytes:{} disassembly failed", fmt::ptr(start), nBytes));

    return CapstoneDismHandle(startIns, nInstCount);
}

CsInsn Capstone::DisassembleOne(const void* start, uint64_t pcAddr)
{
    CsInsn r{};

    InsnForEach(start, [&r](const CsInsn& insn) {
        r = insn;
        return false;
        }, pcAddr);

    if (r->address != pcAddr)
        throw DismFailedException(fmt::format("Addr:{} disassembly failed", fmt::ptr(start)));

    return r;
}

void Capstone::InsnForEach(const void* _start, std::function<bool(const CsInsn& insn)> callback, uint64_t pcAddr, size_t buffSize)
{
    const uint8_t* start = (const uint8_t*)_start;
    const uint8_t* curr = start;
    size_t currSize = buffSize;
    uint64_t currPcAddr = pcAddr;
    CsInsn currInsn{};

    while (cs_disasm_iter(mhCapstone, &curr, &currSize, &currPcAddr, &currInsn.mInsn) && callback(currInsn))
        ;
}

ICapstoneUtility* Capstone::getUtility() {
    return nullptr;
}

ICapstoneHeuristic* Capstone::getHeuristic()
{
    return nullptr;
}

CapstoneDismHandle::CapstoneDismHandle(cs_insn* pFirst, size_t count)
    : mpFirst(pFirst)
    , mpEnd(pFirst + count)
    , mCount(count)
{}

CapstoneDismHandle::~CapstoneDismHandle()
{
    if (!*this)
        return;

    cs_free(mpFirst, mCount);
}

CapstoneDismHandle::operator bool()
{
    return mpFirst != nullptr && mCount > 0;
}

ARM32Capstone::ARM32Capstone(bool mbThumb, bool bDetailedInsn)
    : mCapstone(CS_ARCH_ARM, mbThumb ? CS_MODE_THUMB : CS_MODE_ARM, bDetailedInsn)
{}

ICapstoneUtility* ARM32Capstone::getUtility() {
    return &mUtility;
}

ICapstoneHeuristic* ARM32Capstone::getHeuristic()
{
    return &mHeuristic;
}

CapstoneDismHandle ARM32Capstone::Disassemble(const void* start, size_t nBytes, uint64_t pcAddr) {
    return mCapstone.Disassemble(start, nBytes, pcAddr);
}

CsInsn ARM32Capstone::DisassembleOne(const void* start, uint64_t pcAddr)
{
    return mCapstone.DisassembleOne(start, pcAddr);
}

void ARM32Capstone::InsnForEach(const void* _start, std::function<bool(const CsInsn& insn)> callback, uint64_t pcAddr, size_t buffSize)
{
    mCapstone.InsnForEach(_start, callback, pcAddr, buffSize);
}

bool ARM32CapstoneUtility::InsnHasRegister(const cs_insn* pIns, uint16_t reg) const
{
    return mBaseUtility.InsnHasRegister(pIns->detail->arm, reg);
}

uint64_t ARM32CapstoneUtility::InsnGetImmByIndex(const cs_insn* pIns, size_t index) const
{
    std::vector<uint64_t> allImms = mBaseUtility.InsnGetAllImms<ARM_REG_INVALID>(pIns->detail->arm);

    if (index < allImms.size())
        return allImms[index];

    throw std::runtime_error(fmt::format("'{} {}' no imm at index '{}' ", pIns->mnemonic, pIns->op_str, index));

    return 0;
}

uint16_t ARM32CapstoneUtility::InsnGetPseudoDestReg(const cs_insn* pIns) const
{
    std::vector<uint16_t> allRegs = mBaseUtility.InsnGetAllRegisters(pIns->detail->arm);

    if (!allRegs.empty())
        return allRegs[0];  // Fair Assumption, 
                            // usual ARM the syntax 
                            // often follows a pattern XXX Rd, Rn, Operand2 ...
                            // where Rd (first register operand) is the destination

    throw std::runtime_error(fmt::format("'{} {}' no register operands found", pIns->mnemonic, pIns->op_str));

    return 0;
}

bool ARM32CapstoneUtility::InsnHasCondition(const cs_insn* pInsn) const
{
    return ::InsnHasCondition(pInsn);
}

bool ARM32CapstoneUtility::InsnIsBranch(const cs_insn* pInsn) const
{
    return ::InsnIsBranch(pInsn);
}

CapstoneFactory::CapstoneFactory(ECapstoneArchMode archMode)
    : mArchMode(archMode)
{}

std::unique_ptr<ICapstone> CapstoneFactory::CreateCapstoneInstance(bool bDetailedInst) {
    switch (mArchMode) {
    case ECapstoneArchMode::ARM32_ARM:
    case ECapstoneArchMode::ARM32_THUMB:
        return std::move(std::make_unique<ARM32Capstone>(ECapstoneArchMode::ARM32_THUMB == mArchMode, bDetailedInst));

    default:
        throw CapstoneCreationFailedException(fmt::format("ArchMode:{} not implemented."));
    }

    return 0;
}


DismFailedException::DismFailedException(const std::string& what)
    : std::runtime_error(what)
{}

CapstoneCreationFailedException::CapstoneCreationFailedException(const std::string& what)
    : std::runtime_error(what)
{}

CsInsn::CsInsn()
{
    memset(&mInsn, 0x0, sizeof(mInsn));
    memset(&mDetail, 0x0, sizeof(mDetail));
    mInsn.detail = &mDetail;
}

const cs_insn* CsInsn::operator->() const
{
    return &mInsn;
}

bool ARM32CapstoneHeuristic::InsnIsProcedureEntry(const cs_insn* pInsn) const {
    return
        pInsn->detail->arm.cc == ARMCC_AL &&
        pInsn->id == ARM_INS_PUSH &&
        CapstoneUtility::InsnHasRegister(pInsn->detail->arm, ARM_REG_LR);
}

bool ARM32CapstoneHeuristic::InsnIsProcedureExit(const cs_insn* pInsn) const {
    bool foundUnconditionalPopPc =
        pInsn->detail->arm.cc == ARMCC_AL &&
        pInsn->id == ARM_INS_POP &&
        CapstoneUtility::InsnHasRegister(pInsn->detail->arm, ARM_REG_PC);

    bool foundBranchLinkReg =
        pInsn->id == ARM_INS_BX &&
        CapstoneUtility::InsnHasRegister(pInsn->detail->arm, ARM_REG_LR);

    return foundUnconditionalPopPc || foundBranchLinkReg;
}

CapstoneConcurrentInstanceProvider::CapstoneConcurrentInstanceProvider(ICapstoneFactory* defFactory)
    : mDefaultFactory(defFactory)
{}

ICapstone* CapstoneConcurrentInstanceProvider::GetInstance(bool bDetailedInstuction, ICapstoneFactory* _factory)
{
    std::thread::id this_id = std::this_thread::get_id();

    std::unique_lock<std::mutex> lock(mMutex);
    while (mInstances.find(this_id) == mInstances.end()) {
        ICapstoneFactory* factory = _factory ? _factory : mDefaultFactory;

        if (factory == nullptr)
            return nullptr;

        // This thread doesn't have a Capstone object yet, so create one.
        mInstances[this_id] = factory->CreateCapstoneInstance(bDetailedInstuction);
    }

    return mInstances[this_id].get();
}
