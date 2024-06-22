#pragma once

#include <cstdint>
#include <string>
#include <functional>

struct CxxHeaderInclude {
    std::string mInclude;
    bool mbGlobal;

    inline bool operator==(const CxxHeaderInclude& other) const {
        return mInclude == other.mInclude && mbGlobal == other.mbGlobal;
    }
};

namespace std {
    template <>
    struct hash<CxxHeaderInclude> {
        inline std::size_t operator()(const CxxHeaderInclude& hi) const {
            return std::hash<std::string>()(hi.mInclude + std::to_string(hi.mbGlobal));
        }
    };
}