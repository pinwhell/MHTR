#pragma once
#if defined(_WIN32) || defined(_WIN64)
#if defined(__GNUC__)
#define MHTR_EXPORT extern "C" __attribute__((dllexport)) 
#else
#define MHTR_EXPORT extern "C" __declspec(dllexport) 
#endif
#else
#if defined(__GNUC__) && __GNUC__ >= 4
#define MHTR_EXPORT extern "C" __attribute__((visibility("default")))
#else
#define MHTR_EXPORT extern "C"
#endif
#endif