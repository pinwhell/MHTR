#include <MHTR/Binary/Factory.h>
#include <MHTR/Binary/ELF.h>
#include <MHTR/Binary/Unknown.h>
#include <MHTR/Binary/File.h>
#include <ELFPP.hpp>

using namespace MHTR;

FromMemoryBinaryFactory::FromMemoryBinaryFactory(const void* entry)
    : mEntry(entry)
{}

std::unique_ptr<IBinary> FromMemoryBinaryFactory::CreateBinary()
{
    if (ELFPP::IsELF(mEntry))
        return std::make_unique<ELFBinary>(mEntry);

    return std::make_unique<UnknownBinary>();
}

FromPathBinaryFactory::FromPathBinaryFactory(const std::string& path)
    : mPath(path)
{}

std::unique_ptr<IBinary> FromPathBinaryFactory::CreateBinary()
{
    return std::make_unique<BinaryFile>(mPath.c_str());
}
