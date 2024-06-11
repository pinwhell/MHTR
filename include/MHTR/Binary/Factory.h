#pragma once

#include <MHTR/Binary/IFactory.h>

#include <string>

namespace MHTR {
    class FromMemoryBinaryFactory : public IBinaryFactory {
    public:
        FromMemoryBinaryFactory(const void* entry);

        std::unique_ptr<IBinary> CreateBinary() override;

        const void* mEntry;
    };

    class FromPathBinaryFactory : public IBinaryFactory {
        FromPathBinaryFactory(const std::string& path);

        std::unique_ptr<IBinary> CreateBinary() override;

        std::string mPath;
    };
}
