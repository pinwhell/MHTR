#pragma once

#include <memory>
#include <ELFPP.hpp>
#include <BufferView.h>
#include <CStone/ICapstone.h>
#include <CStone/IFactory.h>

class ELFBuffer : public ICapstoneFactory {
    using EELFMachine = ELFPP::EMachine;

public:

    ELFBuffer(const BufferView& view);

    std::unique_ptr<ICapstone> CreateInstance(bool bDetailedInst = true);

    BufferView mView;
    std::unique_ptr<ELFPP::IELF> mELF;
};