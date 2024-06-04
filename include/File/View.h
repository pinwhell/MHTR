#pragma once

#include <filesystem>

#ifdef _WIN32
#include <Windows.h>
#endif

class FileView {
public:
    inline FileView(const char* filePath)
        : fileHandle(nullptr)
        , fileMapping(nullptr)
        , mapView(nullptr)
    {
        Init(filePath);
    }

    inline ~FileView() {

        Release();
    }

    operator const void* () const
    {
        return mapView;
    }

    size_t size() const
    {
        return fileSize;
    }

private:
    size_t fileSize;
    union {
        void* fileHandle;
        int fileHandleI;
    };
    void* fileMapping;
    union {
        void* mapView;
        int mapViewI;
    };

#ifdef __linux__
    inline void Init(const char* filePath)
    {
        fileSize = std::filesystem::file_size(filePath);

        if ((fileSize > 0) == false)
            throw std::runtime_error("Invalid File Size");

        fileHandleI = open(filePath, O_RDONLY);

        if (fileHandleI < 0)
            throw std::runtime_error("File Open Failed");

        mapView = mmap(nullptr, fileSize, PROT_READ, MAP_SHARED, fileHandleI, 0);

        if (mapViewI == -1)
        {
            close(fileHandleI);
            throw std::runtime_error("File Mapping Failed");
        }
    }

    inline void Release()
    {
        if (mapViewI != -1 && mapView != nullptr)
        {
            munmap(mapView, fileSize);
        }

        if (fileHandleI > 0)
            close(fileHandleI);
    }
#endif


#ifdef _WIN32
    inline void Init(const char* filePath)
    {
        fileHandle = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (fileHandle == INVALID_HANDLE_VALUE)
            throw std::runtime_error("Error opening file");

        fileSize = std::filesystem::file_size(filePath);

        fileMapping = CreateFileMappingA(fileHandle, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (fileMapping == nullptr)
        {
            CloseHandle(fileHandle);
            throw std::runtime_error("Error creating file mapping");
        }

        mapView = MapViewOfFile(fileMapping, FILE_MAP_READ, 0, 0, 0);

        if (mapView == nullptr) {
            CloseHandle(fileMapping);
            CloseHandle(fileHandle);
            throw std::runtime_error("Error mapping view of file");
        }
    }

    inline void Release()
    {
        if (mapView != nullptr) {
            UnmapViewOfFile(mapView);
        }

        if (fileMapping != nullptr) {
            CloseHandle(fileMapping);
        }

        if (fileHandle != nullptr && fileHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(fileHandle);
        }
    }
#endif
};