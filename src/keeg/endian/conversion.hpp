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
#ifndef CONVERSION_HPP
#define CONVERSION_HPP

#include <assert.h>
#include <cstdint>
#include <iterator>
#include <limits>
#include <type_traits>
#include <vector>
#include <keeg/common/macrohelpers.hpp>
#include <boost/endian/conversion.hpp>

namespace keeg { namespace endian {

enum class Order
{
    big, little,
#if __BYTE_ORDER == __BIG_ENDIAN
    native = big
#else
    native = little
#endif
};

static inline uint16_t swap(uint16_t x)
{
#if defined(_MSC_VER)
    return _byteswap_ushort(x);
#elif defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap16(x);
#else
    return (x >> 8) | (x << 8);
#endif
}

static inline uint32_t swap(uint32_t x)
{
#if defined(_MSC_VER)
    return _byteswap_ulong(x);
#elif defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap32(x);
#else

    return (x >> 24) |
            ((x >>  8) & 0x0000FF00) |
            ((x <<  8) & 0x00FF0000) |
            (x << 24);
#endif
}

static inline uint64_t swap(uint64_t x)
{
#if defined(_MSC_VER)
    return _byteswap_uint64(x);
#elif defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap64(x);
#else
    return ((x & 0x00000000FFFFFFFF) << 32 | (x & 0xFFFFFFFF00000000) >> 32) |
            ((x & 0x0000FFFF0000FFFF) << 16 | (x & 0xFFFF0000FFFF0000) >> 16) |
            ((x & 0x00FF00FF00FF00FF) << 8  | (x & 0xFF00FF00FF00FF00) >> 8);
#endif
}

/// rotate left and wrap around to the right
inline uint64_t rotateLeft(uint64_t x, uint8_t numBits)
{
#if (defined(__x86_64__) || defined(__i386) || defined(_M_IX86) || defined(_M_X64)) \
    && !defined(__clang__) && !defined(__MINGW32__)

    return _rotl64(x, numBits);
#else
    const uint64_t mask = (CHAR_BIT * sizeof(x) - 1);
    //assert(numBits <= mask);
    numBits &= mask;
    return (x << numBits) | (x >> ( (-numBits)&mask ));
#endif
}

/// rotate left and wrap around to the right
inline uint32_t rotateLeft(uint32_t x, uint8_t numBits)
{
#if (defined(__x86_64__) || defined(__i386) || defined(_M_IX86) || defined(_M_X64)) && !defined(__clang__)
    return _rotl(x, numBits);
#else
    const uint32_t mask = (CHAR_BIT * sizeof(x) - 1);
    //assert(numBits <= mask);
    numBits &= mask;
    return (x << numBits) | (x >> ( (-numBits)&mask ));
#endif
}

/// rotate left and wrap around to the right
inline uint16_t rotateLeft(uint16_t x, uint8_t numBits)
{
#if (defined(__x86_64__) || defined(__i386) || defined(_M_IX86) || defined(_M_X64)) && !defined(__clang__)
    #ifdef _MSC_VER
        return _rotl16(x, numBits);
    #else
        return _rotwl(x, numBits);
    #endif
#else
    const uint16_t mask = (CHAR_BIT * sizeof(x) - 1);
    //assert(numBits <= mask);
    numBits &= mask;
    return (x << numBits) | (x >> ( (-numBits)&mask ));
#endif
}

/// rotate left and wrap around to the right
inline uint8_t rotateLeft(uint8_t x, uint8_t numBits)
{
#if defined(__x86_64__) || defined(__i386) || defined(_M_IX86) || defined(_M_X64) && !defined(__clang__)
    #ifdef _MSC_VER
        return _rotl8(x, numBits);
    #else
        return __rolb(x, numBits);
    #endif
#else
    const uint8_t mask = (CHAR_BIT * sizeof(x) - 1);
    //assert(numBits <= mask);
    numBits &= mask;
    return (x << numBits) | (x >> ( (-numBits)&mask ));
#endif
}

/// rotate right and wrap around to the left
inline uint64_t rotateRight(uint64_t x, uint8_t numBits)
{
#if (defined(__x86_64__) || defined(__i386) || defined(_M_IX86) || defined(_M_X64)) \
    && !defined(__clang__) && !defined(__MINGW32__)

    return _rotr64(x, numBits);
#else
    const uint64_t mask = (CHAR_BIT * sizeof(x) - 1);
    //assert(numBits <= mask);
    numBits &= mask;
    return (x >> numBits) | (x << ((-numBits)&mask));
#endif
}

/// rotate right and wrap around to the left
inline uint32_t rotateRight(uint32_t x, uint8_t numBits)
{
#if (defined(__x86_64__) || defined(__i386) || defined(_M_IX86) || defined(_M_X64)) && !defined(__clang__)
    return _rotr(x, numBits);
#else
    const uint32_t mask = (CHAR_BIT * sizeof(x) - 1);
    //assert(numBits <= mask);
    numBits &= mask;
    return (x >> numBits) | (x << ((-numBits)&mask));
#endif
}

/// rotate right and wrap around to the left
inline uint16_t rotateRight(uint16_t x, uint8_t numBits)
{
#if (defined(__x86_64__) || defined(__i386) || defined(_M_IX86) || defined(_M_X64)) && !defined(__clang__)
    #ifdef _MSC_VER
        return _rotr16(x, numBits);
    #else
        return _rotwr(x, numBits);
    #endif
#else
    const uint16_t mask = (CHAR_BIT * sizeof(x) - 1);
    //assert(numBits <= mask);
    numBits &= mask;
    return (x >> numBits) | (x << ((-numBits)&mask));
#endif
}

/// rotate right and wrap around to the left
inline uint8_t rotateRight(uint8_t x, uint8_t numBits)
{
#if (defined(__x86_64__) || defined(__i386) || defined(_M_IX86) || defined(_M_X64)) && !defined(__clang__)
    #ifdef _MSC_VER
        return _rotr8(x, numBits);
    #else
        return __rorb(x, numBits);
    #endif
#else
    const uint8_t mask = (CHAR_BIT * sizeof(x) - 1);
    //assert(numBits <= mask);
    numBits &= mask;
    return (x >> numBits) | (x << ((-numBits)&mask));
#endif
}

template <typename T>
inline T  big_to_native(const T &x) noexcept
{
    static_assert(std::is_integral<T>::value, "T must be any integral type.");
    return boost::endian::big_to_native(x);
}

template <typename T>
inline T native_to_big(const T &x) noexcept
{
    static_assert(std::is_integral<T>::value, "T must be any integral type.");
    return boost::endian::native_to_big(x);
}

template <typename T>
inline T little_to_native(const T &x) noexcept
{
    static_assert(std::is_integral<T>::value, "T must be any integral type.");
    return boost::endian::little_to_native(x);
}

template <typename T>
inline T native_to_little(const T &x) noexcept
{
    static_assert(std::is_integral<T>::value, "T must be any integral type.");
    return boost::endian::native_to_little(x);
}

template<typename T>
inline void big_to_native_inplace(T &x) noexcept
{
    static_assert(std::is_integral<T>::value, "T must be any integral type.");
    boost::endian::big_to_native_inplace(x);
}

template<typename T>
inline void native_to_big_inplace(T &x) noexcept
{
    static_assert(std::is_integral<T>::value, "T must be any integral type.");
    boost::endian::native_to_big_inplace(x);
}

template<typename T>
inline void little_to_native_inplace(T &x)
{
    static_assert(std::is_integral<T>::value, "T must be any integral type.");
    boost::endian::little_to_native_inplace(x);
}

template<typename T>
inline void native_to_little_inplace(T &x)
{
    static_assert(std::is_integral<T>::value, "T must be any integral type.");
    boost::endian::native_to_little_inplace(x);
}

template <typename T>
inline void integralToBytes(const T &source, std::vector<uint8_t> &destination)
{
    static_assert(std::is_integral<T>::value, "T must be and integral.");

    T data = native_to_big(source);
    const uint8_t *src = reinterpret_cast<const uint8_t*>(&data);
    destination.clear();
    destination.insert(std::end(destination), src, src + sizeof(T));
}

template <typename T>
inline void bytesToIntegral(const std::vector<uint8_t> &source, const std::size_t &index, T &destination)
{
    static_assert(std::is_integral<T>::value, "T must be and integral.");

    destination = big_to_native(*reinterpret_cast<const T*>(&source[index]));
}

template<typename T>
inline T convertToEndian(const T &data, const Order &endian)
{
    static_assert(std::is_integral<T>::value, "T must be any integral type!");

    T buffer;

    switch (endian) {
    case Order::big:
        buffer = native_to_big(data);
        break;
    case Order::little:
        buffer = native_to_little(data);
        break;
    default:
        buffer = data;
        break;
    }

    return buffer;
}

template<typename T>
inline void convertToEndianInplace(T &data, const Order &endian)
{
    static_assert(std::is_integral<T>::value, "T must be any integral type!");

    switch (endian) {
    case Order::big:
        native_to_big_inplace(data);
        break;
    case Order::little:
        native_to_little_inplace(data);
        break;
    default:
        break;
    }
}

template<typename T>
inline T convertFromEndian(const T &data, const Order &endian)
{
    static_assert(std::is_integral<T>::value, "T must be any integral type!");

    T buffer;

    switch (endian) {
    case Order::big:
        buffer = big_to_native(data);
        break;
    case Order::little:
        buffer = little_to_native(data);
        break;
    default:
        buffer = data;
        break;
    }

    return buffer;
}

template<typename T>
inline void convertFromEndianInplace(T &data, const Order &endian)
{
    static_assert(std::is_integral<T>::value, "T must be any integral type!");

    switch (endian) {
    case Order::big:
        big_to_native_inplace(data);
        break;
    case Order::little:
        little_to_native_inplace(data);
        break;
    default:
        break;
    }
}

} // endian namespace
} // keeg namespace

#endif // CONVERSION_HPP
