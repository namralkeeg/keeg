/*
 * Copyright (C) 2017 Larry Lopez
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#ifndef BINARYREADERS_HPP
#define BINARYREADERS_HPP

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <type_traits>
#include <vector>
#include <keeg/endian/conversion.hpp>

namespace keeg { namespace io {

/// Template helper for reading simple integer types. Is endian aware for integer types.
template<typename T>
std::size_t readIntType(std::istream &instream, T &data, const endian::Order &endian = endian::Order::native)
{
    static_assert(std::is_integral<T>::value
                  && !std::is_same<T, bool>::value, "T must be an integer type!");
    try
    {
        if (instream)
        {
            if (instream.read(reinterpret_cast<char*>(&data), sizeof(T)))
            {
                endian::convertToEndianInplace<T>(data, endian);
                return static_cast<std::size_t>(instream.gcount());
            }
        }
    }
    catch(const std::exception &ex)
    {
        std::cerr << ex.what() << std::endl;
        return 0;
    }

    return 0;
}

/// Template helper for reading simple POD types. Usually used for simple structs.
template<typename T>
std::size_t readPODType(std::istream &instream, T &data)
{
    static_assert(std::is_pod<T>::value && std::is_trivially_copyable<T>::value, "T must be a POD!");
    try
    {
        if (instream)
        {
            instream.read(reinterpret_cast<char*>(&data), sizeof(T));
            return static_cast<std::size_t>(instream.gcount());
        }
    }
    catch(const std::exception &ex)
    {
        std::cerr << ex.what() << std::endl;
        return 0;
    }

    return 0;
}

template<typename T>
std::size_t readPrefixString(std::istream &instream, std::string &data,
                             const endian::Order &endian = endian::Order::native,
                             const bool &isNullTerminated = false)
{
    static_assert(std::is_integral<T>::value &&
                  !std::is_same<T, bool>::value, "T must be any integer type!");
    try
    {
        if (instream)
        {
            T size;
            if(readIntType<T>(instream, size, endian) > 0)
            {
                data.resize(size);
                instream.read(reinterpret_cast<char*>(&data[0]), size);

                if(isNullTerminated)
                {
                    /// Removes all nulls from a string by shifting all non-null characters to the left
                    /// and then erasing the extra.
                    data.erase(std::remove(std::begin(data), std::end(data), '\0'), std::end(data));
                }

                return static_cast<std::size_t>(instream.gcount() + sizeof(T));
            }
        }
    }
    catch(const std::exception &ex)
    {
        std::cerr << ex.what() << std::endl;
        return 0;
    }

    return 0;
}

/// For bool types. bool isn't standardized between platforms at this time.
inline std::size_t readBoolean(std::istream &instream, bool &data, const endian::Order &endian = endian::Order::native)
{
    try
    {
        if (instream)
        {
            std::size_t status = 0;

            switch (sizeof(bool)) {
            case sizeof(uint64_t):
                uint64_t buffer64;
                status = readIntType<uint64_t>(instream, buffer64, endian);
                if(status)
                    data = static_cast<bool>(buffer64);
                break;
            case sizeof(uint32_t):
                uint32_t buffer32;
                status = readIntType<uint32_t>(instream, buffer32, endian);
                if(status)
                    data = static_cast<bool>(buffer32);
                break;
            case sizeof(uint16_t):
                uint16_t buffer16;
                status = readIntType<uint16_t>(instream, buffer16, endian);
                if(status)
                    data = static_cast<bool>(buffer16);
                break;
            case sizeof(uint8_t):
                uint8_t buffer;
                status = readIntType<uint8_t>(instream, buffer, endian);
                if(status)
                    data = static_cast<bool>(buffer);
                break;
            default:
                break;
            }

            return status;
        }
    }
    catch(const std::exception &ex)
    {
        std::cerr << ex.what() << std::endl;
        return 0;
    }
}

/// Reads length bytes into data starting from index from the input stream.
/// Data is resized if it's smaller than length.
inline std::size_t readBytes(std::istream &instream, std::vector<uint8_t> &data, const std::size_t &length,
                             const std::size_t &index)
{
    try
    {
        if (instream)
        {
            if (length + index > data.size())
                data.resize(length + index);

            if (instream.read(reinterpret_cast<char*>(&data[index]), length))
                return instream.gcount();
        }
    }
    catch(const std::exception &ex)
    {
        std::cerr << ex.what() << std::endl;
        return 0;
    }

    return 0;
}

/// Reads length bytes into data from the input stream. Data is resized if it's smaller than length.
inline std::size_t readBytes(std::istream &instream, std::vector<uint8_t> &data, const std::size_t &length)
{
    return readBytes(instream, data, length, 0);
}

/// Read a string prefixed with a uint8_t length. NOT zero terminated.
inline std::size_t readBString(std::istream &instream, std::string &data,
                               const endian::Order &endian = endian::Order::native)
{
    return readPrefixString<uint8_t>(instream, data, endian, false);
}

/// Read a string prefixed with a uint8_t length. zero terminated.
inline std::size_t readBZString(std::istream &instream, std::string &data,
                                const endian::Order &endian = endian::Order::native)
{
    return readPrefixString<uint8_t>(instream, data, endian, true);
}

/// Read a string prefixed with a uint16 length. NOT zero terminated.
inline std::size_t readWString(std::istream &instream, std::string &data,
                               const endian::Order &endian = endian::Order::native)
{
    return readPrefixString<uint16_t>(instream, data, endian, false);
}

/// Read a string prefixed with a uint16 length. zero terminated.
inline std::size_t readWZString(std::istream &instream, std::string &data,
                                const endian::Order &endian = endian::Order::native)
{
    return readPrefixString<uint16_t>(instream, data, endian, true);
}

/// Zero terminated string.
/// Size is size of string text + 1 for string terminator.
inline std::size_t readZString(std::istream &instream, std::string &data)
{
    try
    {
        if (instream)
        {
            std::stringstream ss;
            char c;

            while (instream.read(&c, sizeof(char)))
            {
                if (c != '\0')
                    ss << c;
                else
                    break;
            }

            data = ss.str();
            return data.length() + 1;
        }
    }
    catch(const std::exception &ex)
    {
        std::cerr << ex.what() << std::endl;
        return 0;
    }

    return 0;
}

} // io namespace
} // keeg namespace

#endif // BINARYREADERS_HPP
