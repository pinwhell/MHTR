#pragma once

template <typename T>
class Storage {
public:
    Storage() = default;

    // Delete the copy constructor and copy assignment operator
    Storage(const Storage&) = delete;
    Storage& operator=(const Storage&) = delete;

    // Operator += to move elements from another Storage
    Storage& operator+=(Storage& other) {
        // Move all elements from the other Storage to this Storage
        for (auto&& elem : other.mStorage) {
            mStorage.emplace_back(std::move(elem));
        }
        // Clear the other Storage
        other.mStorage.clear();
        return *this;
    }

    template <typename U>
    Storage& operator+=(U&& thing) {
        Store<U>(std::move(thing));
        return *this;
    }

    // Store an element and return a reference to the stored element
    template <typename U>
    T& Store(U&& value) {
        mStorage.emplace_back(std::move(value));
        return mStorage.back();
    }

private:
    std::vector<T> mStorage;
};