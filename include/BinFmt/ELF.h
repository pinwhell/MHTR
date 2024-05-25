#pragma once

#include <memory>
#include <ELFPP.hpp>
#include <BufferView.h>
#include <CStone/ICapstone.h>
#include <CStone/IFactory.h>
#include <CStone/IProvider.h>
#include <Provider/IFarAddress.h>

class ELFBuffer : public ICapstoneFactory, public IFarAddressResolverProvider {
    using EELFMachine = ELFPP::EMachine;
public:
    ELFBuffer(const BufferView& view);

    std::unique_ptr<ICapstone> CreateInstance(bool bDetailedInst = true) override;
    IFarAddressResolver* GetFarAddressResolver(ICapstoneProvider* cstoneProvider) override;

    BufferView mView;
    std::unique_ptr<ELFPP::IELF> mELF;
    std::unordered_map<std::string, std::unique_ptr<IFarAddressResolver>> mFarAddressResolvers;
};