#pragma once

#include <MHTR/Synther/ICxxHeader.h>
#include <MHTR/Synther/Cxx/Builder/HeaderIncludeBlock.h>

class CxxHeaderHead : public ICxxHeaderHead {
public:
    CxxHeaderHead(bool bUsePragmaOnce = true);

    ICxxHeaderIncludeBlockBuilder* GetIncBlockBuilder() override;

    MultiLine Synth() const override;

    bool mbUsePragmaOnce;
    CxxHeaderIncludeBlockBuilder mIncludeBlockBuilder;
};