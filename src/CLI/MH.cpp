#include <CLI/MH.h>
#include <iostream>
#include <Provider/FromFileJson.h>
#include <Provider/Json.h>
#include <Provider/FromJsonPathJsonFile.h>
#include <Provider/FromJsonSingleNamespace.h>
#include <CStone/Provider.h>
#include <Metadata/Metadata.h>
#include <Metadata/Synthers.h>
#include <Synther/FileOperations.h>
#include <IR/ToMetadata.h>
#include <Factory/MetadataTarget.h>
#include <IR/From/Json.h>
#include <Binary/IBinary.h>
#include <Factory/FromTargetBinJsonBinary.h>
#include <fmt/core.h>
#include <BS_thread_pool.hpp>
#include <Factory/FromPluginFolderMultiPlugin.h>
#include <Pltform.h>

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
    mCLIOptions.add_options()
        ("r,report", "Output result report", cxxopts::value<std::string>(), "[output path]")
        ("rhpp,report-hpp", "Output result report to hpp file", cxxopts::value<std::string>(), "[output path]")
        ("t,targets", "JSON targets path", cxxopts::value<std::string>())
        ("j,threads", "Number of threads", cxxopts::value<int>(DEFAULT_NTHREADS)->default_value("1"))
        ("plugin-dir", "Directory path containing Plugins", cxxopts::value<std::string>());
        ("h,help", "Print help");

    mCLIOptions.allow_unrecognised_options();

    mCLIParseRes = mCLIOptions.parse(argc, argv);

    mAllPlugins = mAllPluginsFactory ?
        mAllPluginsFactory->CreatePlugins() :
        FromPluginFolderMultiPluginFactory(
            mCLIParseRes.count("plugin-dir") ?
            std::filesystem::path(
                mCLIParseRes["plugin-dir"].as<std::string>()
            ) :
            MHTRFromCurrentExePathPluginDirGet()
            , argc, argv).CreatePlugins();

    for (auto& plugin : mAllPlugins)
        std::cout << fmt::format("Loaded:'{}'\n", plugin->GetName());
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

    std::vector<MetadataTarget*> foundTargetVec(foundTargets.begin(), foundTargets.end());

    {
        BS::thread_pool pool(nThreads);

        if (mCLIParseRes.count("report")) pool.detach_task([this, &foundTargetVec] {
            MultiNsMultiMetadataReportSynther reportSynther(foundTargetVec);
            FileWrite(mCLIParseRes["report"].as<std::string>(), &reportSynther);
            });

        if (mCLIParseRes.count("report-hpp")) pool.detach_task([this, &foundTargetVec] {
            HppStaticReport report(foundTargetVec);
            FileWrite(mCLIParseRes["report-hpp"].as<std::string>(), &report);
            });

        pool.detach_loop((size_t)0, mAllPlugins.size(), [this, &foundTargetVec](size_t idx) {
            mAllPlugins[idx]->OnResult(foundTargetVec);
            });
    }

    std::cout << fmt::format("{}/{} targets successful.", foundTargets.size(), allTargets.size()) << std::endl;

    return 0;
}
