#pragma once

#include <Metadata.h>

#include <Synther/ILine.h>
#include <Synther/IMultiLine.h>

class MetadataStaticLineSynther : public ILineSynthesizer {
public:
    MetadataStaticLineSynther(const MetadataTarget& target);

    std::string Synth() const override;

    const MetadataTarget& mTarget;
};

class MultiMetadataStaticSynther : public IMultiLineSynthesizer
{
public:
    MultiMetadataStaticSynther(std::vector<MetadataTarget*> targets, const std::string& ns = METADATA_NULL_NS);

    std::vector<std::string> Synth() const override;

    std::string mNamespace;
    std::vector<MetadataTarget*> mTargets;
};

class MultiNsMultiMetadataStaticSynther : public IMultiLineSynthesizer {
public:

    MultiNsMultiMetadataStaticSynther(const std::vector<MetadataTarget*>& targets);

    std::vector<std::string> Synth() const override;

    std::vector<MetadataTarget*> mTargets;
};