#pragma once

#include <cstdint>
#include <unordered_map>
#include <variant>
#include <string>
#include <iterator>

namespace MHTR {
    using Metadata = std::variant<std::string, uint64_t>;
    using MetadataMap = std::unordered_map<std::string, Metadata>;

    class MetadataProvider {
    public:
        inline MetadataProvider()
        {}

        inline MetadataProvider(MetadataMap&& metadatas)
            : mMetadatas(std::move(metadatas))
        {}

        inline MetadataProvider(MetadataProvider&& other) noexcept {
            mMetadatas = std::move(other.mMetadatas);
        }

        inline uint64_t GetOffset(const std::string& key)
        {
            return std::get<uint64_t>(mMetadatas[key]);
        }

        inline std::string GetPattern(const std::string& key)
        {
            return std::get<std::string>(mMetadatas[key]);
        }

        inline MetadataProvider& operator+(MetadataProvider&& other)
        {
            *this += std::move(other);
            return *this;
        }

        inline void operator+=(MetadataProvider&& other)
        {
            for (auto& [key, value] : other.mMetadatas) {
                mMetadatas[key] = std::move(value);
            }
            other.mMetadatas.clear();
        }

        MetadataMap mMetadatas;
    };
}