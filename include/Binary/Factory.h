#pragma once

#include <Binary/IFactory.h>
#include <Provider/IBinaryArchMode.h>

#include <string>

class FromMemoryBinaryFactory : public IBinaryFactory {
public:
    FromMemoryBinaryFactory(const void* entry, IBinaryArchModeProvider* archModeProvider = 0);

    std::unique_ptr<IBinary> CreateBinary() override;

    const void* mEntry;
    IBinaryArchModeProvider* mArchModeProvider;
};

class FromPathBinaryFactory : public IBinaryFactory {
    FromPathBinaryFactory(const std::string& path, IBinaryArchModeProvider* archModeProvider = 0);

    std::unique_ptr<IBinary> CreateBinary() override;

    std::string mPath;
    IBinaryArchModeProvider* mArchModeProvider;
};
