#pragma once

#include <string>
#include <MHTR/Synther/IMultiLine.h>

class ICxxHeaderIncludeBlockBuilder : public IMultiLineSynthesizer {
public:
    virtual ~ICxxHeaderIncludeBlockBuilder() = default;
    virtual ICxxHeaderIncludeBlockBuilder* Add(const std::string& header, bool bGlobalInclude = true) = 0;
};