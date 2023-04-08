#pragma once

#include <cstdint>
#include <functional>

constexpr uint32_t fnv1a_32(char const* s, size_t count)
{
    return ((count ? fnv1a_32(s, count - 1) : 2166136261u) ^ s[count]) * 16777619u;
}

constexpr uint32_t operator"" _hash(char const* s, size_t count)
{
    return fnv1a_32(s, count);
}

#define FNV1A_32(txt) \
[](){ \
   constexpr auto hashedTxt = txt##_hash;  \
   return hashedTxt; \
}()

