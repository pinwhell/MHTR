#pragma once

#include <unordered_set>
#include <MHTR/Synther/Cxx/HeaderInclude.h>
#include <MHTR/Synther/Cxx/Builder/IHeaderIncludeBlock.h>

class CxxHeaderIncludeBlockBuilder : public ICxxHeaderIncludeBlockBuilder {
public:
    using Set = std::unordered_set<CxxHeaderInclude>;

    CxxHeaderIncludeBlockBuilder() = default;

    ICxxHeaderIncludeBlockBuilder* Add(const std::string& header, bool bGlobalInclude = true) override;
    MultiLine Synth() const override;

    Set mCollection;
};