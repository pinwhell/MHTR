#include <CLI/MH.h>
#include <iostream>
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
#include <fmt/core.h>
#include <MetadataSynthers.h>
#include <SyntherFileOp.h>
#include <BS_thread_pool.hpp>

static auto DEFAULT_NTHREADS = 1;

MHCLI::MHCLI(int argc, const char** argv)
    : mCLIOptions("Metadata Hunter CLI", "Robust Binary Analizis Framework.")
{
    mCLIOptions.add_options()
        ("r,report", "Output result report", cxxopts::value<std::string>(), "[output path]")
        ("t,targets", "JSON targets path", cxxopts::value<std::string>())
        ("j,threads", "Number of threads", cxxopts::value<int>(DEFAULT_NTHREADS)->default_value("1"))
        ("h,help", "Print help");

    mCLIOptions.allow_unrecognised_options();

    mCLIParseRes = mCLIOptions.parse(argc, argv);
}

int MHCLI::Run()
{
    if (mCLIParseRes.count("help") ||
        !mCLIParseRes.count("targets")) {
        std::cout << mCLIOptions.help() << std::endl;
        return 0;
    }

    const auto nThreads = mCLIParseRes.count("threads")
        ? DEFAULT_NTHREADS
        : mCLIParseRes["threads"].as<int>();

    FromFileJsonProvider targetsJsonProvider(mCLIParseRes["targets"].as<std::string>());
    const auto& targets = (*targetsJsonProvider.GetJson());
    std::vector<std::vector<std::unique_ptr<ILookableMetadata>>> allVecLookables;

    std::transform(targets.begin(), targets.end(), std::back_inserter(allVecLookables), [&](const auto& target) {
        JsonProvider binTargetJsonProvider(target);
        FromJsonPathJsonFileProvider metadataIrJsonProvider(&binTargetJsonProvider, "metadataPath");
        FromJsonSingleNamespaceProvider* nsProvider = (FromJsonSingleNamespaceProvider*)mProvidersStorage.Store(
            std::make_unique<FromJsonSingleNamespaceProvider>(
                &binTargetJsonProvider
            )
        ).get();
        FromJsonMultiMetadataIRFactory irFactory(&metadataIrJsonProvider);
        IBinary* bin = mBinariesStorage.Store(FromTargetBinJsonBinaryFactory(&binTargetJsonProvider).CreateBinary()).get();
        IOffsetCalculator* offsetCalculator = bin->GetOffsetCalculator();
        ICapstoneProvider* capstoneProvider = mCStoneProvidersStorage.Store(std::make_unique<CapstoneConcurrentProvider>(bin)).get();

        return FromIRMultiMetadataFactory(
            mProvidersStorage,
            &mMetadataTargetProvider,
            &irFactory,
            bin,
            offsetCalculator,
            capstoneProvider,
            bin,
            nsProvider
        ).ProduceAll();
        });

    std::vector<std::unique_ptr<ILookableMetadata>> allLookables;

    for (auto& lookableVec : allVecLookables)
    {
        allLookables.reserve(allLookables.size() + lookableVec.size());
        std::move(std::make_move_iterator(lookableVec.begin()), std::make_move_iterator(lookableVec.end()), std::back_inserter(allLookables));
        lookableVec.clear();
    }

    std::vector<ILookableMetadata*> allLookablesPtr;
    std::vector<ILookableMetadata*> foundLookablesPtr;
    std::mutex mtx;

    std::transform(allLookables.begin(), allLookables.end(), std::back_inserter(allLookablesPtr), [](const auto& ptr) {
        return ptr.get();
        });

    {
        BS::thread_pool pool(nThreads);

        auto _ = pool.submit_loop((size_t)(0), allLookablesPtr.size(), [&mtx, &foundLookablesPtr, &allLookablesPtr](size_t idx) {

            ILookableMetadata* lookable = allLookablesPtr[idx];

            try {
                lookable->Lookup();
                {
                    std::lock_guard<std::mutex> lck(mtx);
                    foundLookablesPtr.emplace_back(lookable);
                }
            }
            catch (const std::exception& e)
            {
                std::cerr << fmt::format("warning: '{}':{}\n", lookable->GetTarget()->GetFullName(), e.what());
            }
            });
    }

    std::unordered_set<MetadataTarget*> foundTargets;

    std::transform(foundLookablesPtr.begin(), foundLookablesPtr.end(), std::inserter(foundTargets, foundTargets.end()), [](ILookableMetadata* metadata) {
        return metadata->GetTarget();
        });

    std::vector<MetadataTarget*> foundTargetVec(foundTargets.begin(), foundTargets.end());

    if (mCLIParseRes.count("report"))
    {
        MultiNsMultiMetadataReportSynther reportSynther(foundTargetVec);
        FileWrite(mCLIParseRes["report"].as<std::string>(), &reportSynther);
    }

    return 0;
}
