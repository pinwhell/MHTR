#include <MHTR/CLI/MH.h>
#include <iostream>
#include <algorithm>
#include <fmt/core.h>
#include <MHTR/Provider/FromFileJson.h>
#include <MHTR/Provider/Json.h>
#include <MHTR/Provider/FromJsonPathJsonFile.h>
#include <MHTR/Provider/FromJsonSingleNamespace.h>
#include <MHTR/Metadata/Metadata.h>
#include <MHTR/Metadata/Synthers.h>
#include <MHTR/Synther/FileOperations.h>
#include <MHTR/IR/ToMetadata.h>
#include <MHTR/Factory/MetadataTarget.h>
#include <MHTR/IR/From/Json.h>
#include <MHTR/Binary/IBinary.h>
#include <MHTR/Factory/FromTargetBinJsonBinary.h>
#include <MHTR/Factory/FromPluginFolderMultiPlugin.h>
#include <MHTR/Pltform.h>
#include <CStone/Provider.h>
#include <BS_thread_pool.hpp>

using namespace MHTR;

static auto DEFAULT_NTHREADS = 1;

#ifdef WINDOWS
#include <Windows.h>
#else
#include <unistd.h>
#include <limits.h>
#endif

std::string GetExecutablePath() {
#ifdef WINDOWS
    char buffer[MAX_PATH];
    DWORD length = GetModuleFileNameA(NULL, buffer, MAX_PATH);
    if (length == 0) {
        // Handle error
        throw std::runtime_error("Failed getting MHCLI executable path");
    }
    return std::string(buffer);
#elif defined (LINUX)
    char buffer[PATH_MAX];
    ssize_t length = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
    if (length == -1) {
        // Handle error
        throw std::runtime_error("Failed getting MHCLI executable path");
    }
    buffer[length] = '\0';
    return std::string(buffer);
#else
    static_assert(false, "Getting Current Executable Path Not Supported For This Platform");
#endif
}

std::filesystem::path MHTRFromExePathPluginDirGet(const std::string& exePath)
{
    return std::filesystem::path(exePath).parent_path() / "plugins";
}

std::filesystem::path MHTRFromCurrentExePathPluginDirGet()
{
    return MHTRFromExePathPluginDirGet(GetExecutablePath());
}

MHCLI::MHCLI(int argc, const char* argv[], IMultiPluginFactory* pluginsFactory)
    : mAllPluginsFactory(pluginsFactory)
    , mCLIOptions("Metadata Hunter CLI", "Robust Binary Analizis Framework.")
{
    mCLIOptions.allow_unrecognised_options();

    mCLIOptions.add_options()
        ("h,help", "Print help")
        ("t,targets", "JSON targets path", cxxopts::value<std::string>())
        ("j,threads", "Number of threads", cxxopts::value<int>(DEFAULT_NTHREADS)->default_value("1"))
        ("plugin-dir", "Directory path containing Plugins", cxxopts::value<std::string>())
        ("r,report", "Output result report", cxxopts::value<std::string>(), "[output path]")
        ("rhpp,report-hpp", "Output result report to hpp file", cxxopts::value<std::string>(), "[output path]");


    mAllPlugins = mAllPluginsFactory ?
        mAllPluginsFactory->CreatePlugins() :
        FromPluginFolderMultiPluginFactory(
            mCLIParseRes.count("plugin-dir") ?
            std::filesystem::path(
                mCLIParseRes["plugin-dir"].as<std::string>()
            ) :
            MHTRFromCurrentExePathPluginDirGet()
            , argc, argv).CreatePlugins();

    std::for_each(mAllPlugins.begin(), mAllPlugins.end(), 
        [&](const PluginInstance& pluginInstance) {
            pluginInstance->OnCLIRegister(mCLIOptions);
        });

    mCLIParseRes = mCLIOptions.parse(argc, argv);

    std::for_each(mAllPlugins.begin(), mAllPlugins.end(),
        [&](const PluginInstance& pluginInstance) {
            pluginInstance->OnCLIParsed(mCLIParseRes);
            std::cout << fmt::format("Loaded:'{}'\n", pluginInstance->GetName());
        });  
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

    std::unordered_set<MetadataTarget*> allTargets;

    std::transform(allLookablesPtr.begin(), allLookablesPtr.end(), std::inserter(allTargets, allTargets.end()), [](ILookableMetadata* metadata) {
        return metadata->GetTarget();
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
                std::cerr << fmt::format("'{}':{}\n", lookable->GetTarget()->GetFullName(), e.what());
            }
            });
    }

    std::unordered_set<MetadataTarget*> foundTargets;

    std::transform(foundLookablesPtr.begin(), foundLookablesPtr.end(), std::inserter(foundTargets, foundTargets.end()), [](ILookableMetadata* metadata) {
        return metadata->GetTarget();
        });

    MetadataTargetSet foundTargetVec(foundTargets.begin(), foundTargets.end());

    {
        BS::thread_pool pool(nThreads);

        if (mCLIParseRes.count("report")) pool.detach_task([this, &foundTargetVec] {
            MultiNsMultiMetadataSynther reportSynther(foundTargetVec, TextReportSynther::Synth);
            FileWrite(mCLIParseRes["report"].as<std::string>(), &reportSynther);
            });

        if (mCLIParseRes.count("report-hpp")) pool.detach_task([this, &foundTargetVec] {
            MultiNsMultiMetadataSynther bodySynther(foundTargetVec, ConstAssignSynther::Synth);
            Line pragmaOnce("#pragma once");
            Line cstdintInclude("#include <cstdint>");
            LineSynthesizerGroup headGroup({
                &pragmaOnce,
                &Line::mEmpty,
                &cstdintInclude,
                &Line::mEmpty
                });
            MultiLineSynthesizerGroup fullHpp({
                &headGroup,
                &bodySynther
                });
            //HppSynther report(&bodySynther);
            FileWrite(mCLIParseRes["report-hpp"].as<std::string>(), &fullHpp);
            });

        pool.detach_loop((size_t)0, mAllPlugins.size(), [this, &foundTargetVec](size_t idx) {
            mAllPlugins[idx]->OnResult(foundTargetVec);
            });
    }

    std::cout << fmt::format("{}/{} targets successful.", foundTargets.size(), allTargets.size()) << std::endl;

    return 0;
}
