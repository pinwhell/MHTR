#include <MHTR/Synther/Cxx/Header.h>
#include <MHTR/Synther/MultiLineSingleLine.h>
#include <MHTR/Synther/MultiLineGroup.h>

CxxHeaderHead::CxxHeaderHead(bool bUsePragmaOnce)
    : mbUsePragmaOnce(bUsePragmaOnce)
{}

ICxxHeaderIncludeBlockBuilder* CxxHeaderHead::GetIncBlockBuilder()
{
    return &mIncludeBlockBuilder;
}

MultiLine CxxHeaderHead::Synth() const
{
    MultiLineSingleLine pragmaOnce(Line("#pragma once"));

    return MultiLineSynthesizerGroup({
        &pragmaOnce,
        &MultiLineSingleLine::mEmptyLine,
        (IMultiLineSynthesizer*)
        &mIncludeBlockBuilder
        }).Synth();
}