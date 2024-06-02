#include <iostream>
#include <cxxopts.hpp>
#include <Provider/FromFileJson.h>
#include <Provider/Json.h>
#include <Metadata.h>
#include <Provider/FromJsonPathJsonFile.h>
#include <Provider/FromJsonSingleNamespace.h>
#include <IR/From/Json.h>
#include <Binary/IBinary.h>
#include <Factory/FromTargetBinJsonBinary.h>
#include <IR/ToMetadata.h>
#include <Factory/MetadataTarget.h>
#include <CStone/Provider.h>

class MHunterCLI {
public:
    MHunterCLI(int argc, char** argv)
        : mCLIOptions("Metadata Hunter CLI", "Robust Binary Analizis Framework.")
    {
        mCLIOptions.add_options()
            ("t,targets", "JSON targets path", cxxopts::value<std::string>())
            ("h,help", "Print help");

        mCLIParseRes = mCLIOptions.parse(argc, argv);
    }

    int Run()
    {
        if (mCLIParseRes.count("help") ||
            !mCLIParseRes.count("targets")) {
            std::cout << mCLIOptions.help() << std::endl;
            return 0;
        }

        FromFileJsonProvider targetsJsonProvider(mCLIParseRes["targets"].as<std::string>());
        const auto& targets = (*targetsJsonProvider.GetJson());
        std::vector<std::vector<std::unique_ptr<ILookableMetadata>>> allVecLookables;

        std::transform(targets.begin(), targets.end(), std::back_inserter(allVecLookables), [&](const auto& target) {
            JsonProvider binTargetJsonProvider(target);
            FromJsonPathJsonFileProvider metadataIrJsonProvider(&binTargetJsonProvider, "metadataPath");
            FromJsonSingleNamespaceProvider nsProvider(&binTargetJsonProvider);
            FromJsonMultiMetadataIRFactory irFactory(&metadataIrJsonProvider);
            IBinary* bin = mBinariesStorage.Store(FromTargetBinJsonBinaryFactory(&binTargetJsonProvider).CreateBinary()).get();
            IOffsetCalculator* offsetCalculator = bin->GetOffsetCalculator();
            ICapstoneProvider* capstoneProvider = mCStoneProvidersStorage.Store(std::make_unique<CapstoneConcurrentProvider>(bin)).get();

            return FromIRMultiMetadataFactory(
                mScanRangesStorage,
                &mMetadataTargetProvider,
                &irFactory,
                bin,
                offsetCalculator,
                capstoneProvider,
                bin,
                &nsProvider
            ).ProduceAll();
            });

        std::vector<std::unique_ptr<ILookableMetadata>> allLookables;

        for (auto& lookableVec : allVecLookables)
        {
            allLookables.reserve(allLookables.size() + lookableVec.size());
            std::move(std::make_move_iterator(lookableVec.begin()), std::make_move_iterator(lookableVec.end()), std::back_inserter(allLookables));
            lookableVec.clear();
        }

        std::unordered_set<ILookableMetadata*> found;

        for (auto& lookable : allLookables)
        {
            try {
                lookable->Lookup();
                found.insert(lookable.get());
            }
            catch (const std::exception& e)
            {
                std::cerr << e.what() << std::endl;
            }
        }

        return 0;
    }

    cxxopts::Options mCLIOptions;
    cxxopts::ParseResult mCLIParseRes;
    MetadataTargetFactory mMetadataTargetProvider;
    Storage<std::unique_ptr<IProvider>> mScanRangesStorage;
    Storage<std::unique_ptr<ICapstoneProvider>> mCStoneProvidersStorage;
    Storage<std::unique_ptr<IBinary>> mBinariesStorage;
};

int MHunterMain(int argc, char** argv)
{
    try {
        MHunterCLI cli(argc, argv);
        return cli.Run();
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        return -1;
    }

    return 0; // we should not get here
}

int main(int argc, char* argv[]) {
    return MHunterMain(argc, argv);
}