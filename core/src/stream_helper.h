#pragma once

#include <fstream>

// Helper function to read data from a binary stream
template <typename T>
T read(std::ifstream& stream) {
    T value;
    stream.read(reinterpret_cast<char*>(&value), sizeof(T));
    return value;
}
