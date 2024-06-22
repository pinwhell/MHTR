#include <algorithm>
#include <iterator>

#include <MHTR/Synther/Cxx/Builder/HeaderIncludeBlock.h>
#include <MHTR/Synther/Line.h>
#include <MHTR/Synther/LineGroup.h>

ICxxHeaderIncludeBlockBuilder* CxxHeaderIncludeBlockBuilder::Add(const std::string& header, bool bGlobalInclude)
{
    mCollection.insert({ header, bGlobalInclude });
    return this;
}

MultiLine CxxHeaderIncludeBlockBuilder::Synth() const
{
    std::vector<const CxxHeaderInclude*> includeDescs;
    std::transform(mCollection.begin(), mCollection.end(), std::back_inserter(includeDescs), [](const CxxHeaderInclude& header) {
        return &header;
        });

    std::sort(includeDescs.begin(), includeDescs.end(), [](const CxxHeaderInclude* lhs, const CxxHeaderInclude* rhs) {
        return lhs->mbGlobal > rhs->mbGlobal;
        });

    std::vector<Line> includes;
    std::transform(includeDescs.begin(), includeDescs.end(), std::back_inserter(includes), [](const CxxHeaderInclude* header) {

        const std::string openBrack = header->mbGlobal ? "<" : "\"";
        const std::string closeBrack = header->mbGlobal ? ">" : "\"";

        return Line("#include " + openBrack + header->mInclude + closeBrack);
        });

    std::vector<ILineSynthesizer*> includesPtrs;
    std::transform(includes.begin(), includes.end(), std::back_inserter(includesPtrs), [](Line& headerInclude) {
        return &headerInclude;
        });

    return LineSynthesizerGroup(includesPtrs).Synth();
}