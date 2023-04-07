#pragma once

template<typename T>

bool isBetween(T value, T lowerBound, T upperBound) {
    return (value >= lowerBound && value <= upperBound);
}
