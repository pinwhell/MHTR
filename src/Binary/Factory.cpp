#include <Binary/Factory.h>
#include <Binary/ELF.h>
#include <Binary/Unknown.h>
#include <Binary/File.h>
#include <ELFPP.hpp>

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
