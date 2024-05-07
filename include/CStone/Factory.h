#pragma once

#include <CStone/ICapstone.h>
#include <CStone/IFactory.h>

enum class ECapstoneArchMode {
    UNDEFINED,
    X86_16,
    X86_32,
    X86_64,
    ARM32_ARM,
    ARM32_THUMB,
    AARCH64_ARM,
};

class CapstoneCreationFailedException : public std::runtime_error {
public:
    CapstoneCreationFailedException(const std::string& what);
};

class CapstoneFactory : public ICapstoneFactory
{
public:
    CapstoneFactory(ECapstoneArchMode archMode);

    std::unique_ptr<ICapstone> CreateCapstoneInstance(bool bDetailedInst = true) override;

    ECapstoneArchMode mArchMode;
};