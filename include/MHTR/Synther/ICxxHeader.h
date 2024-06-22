#pragma once

#include <MHTR/Synther/IMultiLine.h>
#include <MHTR/Synther/Cxx/Builder/IHeaderIncludeBlock.h>

class ICxxHeaderHead : public IMultiLineSynthesizer {
public:
    virtual ICxxHeaderIncludeBlockBuilder* GetIncBlockBuilder() = 0;
};