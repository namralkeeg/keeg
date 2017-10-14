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
#ifndef BINARYWRITERS_HPP
#define BINARYWRITERS_HPP

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <type_traits>
#include <vector>
#include <keeg/endian/conversion.hpp>

namespace keeg { namespace io {

/// Template helper for writing simple integer types. Is endian aware for integer types.
template<typename T>
std::size_t writeIntType(std::ostream &outstream, const T &data, const endian::Order &endian = endian::Order::native)
{
    static_assert(std::is_integral<T>::value
                  && !std::is_same<T, bool>::value, "T must be an integer type!");
    try
    {
        if (outstream)
        {
            T buffer;
            buffer = endian::convertToEndian<T>(data, endian);
            outstream.write(reinterpret_cast<char*>(&buffer), sizeof(T));
            return sizeof(T);
        }
    }
    catch(const std::exception &ex)
    {
        std::cerr << ex.what() << std::endl;
        return 0;
    }

    return 0;
}

/// Template helper for writing simple POD types. Usually used for simple structs.
template<typename T>
std::size_t writePODType(std::ostream &outstream, const T &data)
{
    static_assert(std::is_pod<T>::value && std::is_trivially_copyable<T>::value, "T must be a POD!");
    try
    {
        if (outstream)
        {
            outstream.write(reinterpret_cast<const char*>(&data), sizeof(T));
            return sizeof(T);
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
std::size_t writePrefixString(std::ostream &outstream, const std::string &data,
                             const endian::Order &endian = endian::Order::native,
                             const bool &isNullTerminated = false)
{
    static_assert(std::is_integral<T>::value &&
                  !std::is_same<T, bool>::value, "T must be any integer type!");

    try
    {
        if (outstream)
        {
            std::stringstream ss{data};
            if (isNullTerminated)
                ss << '\0';

            T size = static_cast<T>(ss.str().size());
            if(writeIntType<T>(outstream, size, endian) > 0)
            {
                outstream.write(ss.str().c_str(), size);
                return size + sizeof(T);
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
inline std::size_t writeBoolean(std::ostream &outstream, const bool &data,
                                const endian::Order &endian = endian::Order::native)
{
    try
    {
        if (outstream)
        {
            std::size_t status = 0;

            switch (sizeof(bool)) {
            case sizeof(uint64_t):
                status = writeIntType<uint64_t>(outstream, static_cast<uint64_t>(data), endian);
                break;
            case sizeof(uint32_t):
                status = writeIntType<uint32_t>(outstream, static_cast<uint32_t>(data), endian);
                break;
            case sizeof(uint16_t):
                status = writeIntType<uint16_t>(outstream, static_cast<uint16_t>(data), endian);
                break;
            case sizeof(uint8_t):
                status = writeIntType<uint8_t>(outstream, static_cast<uint8_t>(data), endian);
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

    return 0;
}

/// Writes length bytes from data into the output stream starting at index.
inline std::size_t writeBytes(std::ostream &outstream, const std::vector<uint8_t> &data, const std::size_t &length,
                              const std::size_t &index)
{
    try
    {
        if (outstream && ((length + index) <= data.size()))
        {
            if (outstream.write(reinterpret_cast<const char*>(&data[index]), length))
                return length;
        }
    }
    catch(const std::exception &ex)
    {
        std::cerr << ex.what() << std::endl;
        return 0;
    }

    return 0;
}

/// Writes length bytes from data into the output stream from index 0.
inline std::size_t writeBytes(std::ostream &outstream, const std::vector<uint8_t> &data, const std::size_t &length)
{
    return writeBytes(outstream, data, length, 0);
}

/// Write a string prefixed with a uint8 length. NOT null terminated.
inline std::size_t writeBString(std::ostream &outstream, const std::string &data,
                                const endian::Order &endian = endian::Order::native)
{
    return writePrefixString<uint8_t>(outstream, data, endian, false);
}

/// Write a string prefixed with a uint8 length. Null terminated.
inline std::size_t writeBZString(std::ostream &outstream, const std::string &data,
                                 const endian::Order &endian = endian::Order::native)
{
    return writePrefixString<uint8_t>(outstream, data, endian, true);
}

/// Write a string prefixed with a uint16 length. NOT null terminated.
inline std::size_t writeWString(std::ostream &outstream, const std::string &data,
                                const endian::Order &endian = endian::Order::native)
{
    return writePrefixString<uint16_t>(outstream, data, endian, false);
}

/// Write a string prefixed with a uint16 length. Null terminated.
inline std::size_t writeWZString(std::ostream &outstream, const std::string &data,
                                 const endian::Order &endian = endian::Order::native)
{
    return writePrefixString<uint16_t>(outstream, data, endian, true);
}

/// Zero terminated string.
/// Size is size of string text + 1 for string terminator.
inline std::size_t writeZString(std::ostream &outstream, const std::string &data)
{
    try
    {
        if (outstream)
        {
            std::stringstream ss{data};
            ss << '\0';
            outstream.write(ss.str().c_str(), ss.str().size());
            return ss.str().size();
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

#endif // BINARYWRITERS_HPP
