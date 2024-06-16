#include <MHTR/Binary/Factory.h>
#include <MHTR/Binary/ELF.h>
#include <MHTR/Binary/Unknown.h>
#include <MHTR/Binary/File.h>
#include <ELFPP.hpp>

using namespace MHTR;

FromMemoryBinaryFactory::FromMemoryBinaryFactory(const void* entry, IBinaryArchModeProvider* archModeProvider)
    : mEntry(entry)
    , mArchModeProvider(archModeProvider)
{}

std::unique_ptr<IBinary> FromMemoryBinaryFactory::CreateBinary()
{
    if (ELFPP::IsELF(mEntry))
        return std::make_unique<ELFBinary>(mEntry, mArchModeProvider);

    return std::make_unique<UnknownBinary>();
}

FromPathBinaryFactory::FromPathBinaryFactory(const std::string& path, IBinaryArchModeProvider* archModeProvider)
    : mPath(path)
    , mArchModeProvider(archModeProvider)
{}

std::unique_ptr<IBinary> FromPathBinaryFactory::CreateBinary()
{
    return std::make_unique<BinaryFile>(mPath.c_str(), mArchModeProvider);
}
