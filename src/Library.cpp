#include <Library.h>
#include <Pltform.h>
#include <stdexcept>
#include <fmt/format.h>

#include WIN_LINUX(<Windows.h>, <dlfcn.h>)

Library::Library(void* handle)
    : mHandle(handle)
{}

Library Library::Load(const char* fullPath)
{
    void* handle = WIN_LINUX((void*)LoadLibraryA(fullPath), dlopen(fullPath, RTLD_NOW));

    if (handle == nullptr)
        throw std::runtime_error(fmt::format("Failed to load '{}'", fullPath));

    return Library(handle);
}

void* Library::GetSymbol(const char* symName) const
{
    void* pfn = (void*)WIN_LINUX(GetProcAddress((HMODULE)mHandle, symName), dlsym(mHandle, symName));

    if (pfn == nullptr)
        throw std::runtime_error(fmt::format("Failed to get '{}'", symName));

    return pfn;
}
