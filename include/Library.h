#pragma once

class Library {
public:
    Library(void* handle);

    template<typename FuncType>
    FuncType GetSymbol(const char* symName) const;

    static Library Load(const char* fullPath);

    void* mHandle;

private:
    void* GetSymbol(const char* symName) const;
};

template<typename FuncType>
inline FuncType Library::GetSymbol(const char* symName) const
{
    return (FuncType)GetSymbol(symName);
}