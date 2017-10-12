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
#ifndef SUPERFASTHASH32_HPP
#define SUPERFASTHASH32_HPP

#include <keeg/hashing/hashalgorithm.hpp>
#include <keeg/endian/conversion.hpp>
#include <keeg/common/macrohelpers.hpp>

namespace keeg { namespace hashing { namespace noncryptographic {

/// Algorithm by Paul Hsieh
class SuperFastHash32 : public HashAlgorithm
{
public:
    SuperFastHash32();

    // HashAlgorithm interface
public:
    virtual std::size_t hashSize() override;
    virtual void initialize() override;

protected:
    virtual void hashCore(const void *data, const std::size_t &dataLength, const std::size_t &startIndex) override;
    virtual std::vector<uint8_t> hashFinal() override;

private:
    static const std::size_t m_hashSize = std::numeric_limits<uint32_t>::digits;
    uint32_t m_hash;

    static_assert(std::is_same<uint8_t, unsigned char>::value,
                  "uint8_t is required to be implemented as unsigned char!");
};

SuperFastHash32::SuperFastHash32() : HashAlgorithm()
{
    initialize();
}

size_t SuperFastHash32::hashSize()
{
    return m_hashSize;
}

void SuperFastHash32::initialize()
{
    m_hash = 0;
    m_hashValue.clear();
}

void SuperFastHash32::hashCore(const void *data, const size_t &dataLength, const size_t &startIndex)
{
    const uint8_t *current = static_cast<const uint8_t*>(data) + startIndex;
    std::size_t length = dataLength;
    uint32_t temp;
    int32_t rem = length & 3;

    if (m_hash == 0)
        m_hash = static_cast<uint32_t>(length);

    length >>= 2;

    for (; length > 0; length--)
    {
        m_hash  += GET16BITS(current);
        temp    = (GET16BITS(current+2) << 11) ^ m_hash;
        m_hash  = (m_hash << 16) ^ temp;
        current += 2 * sizeof(uint16_t);
        m_hash  += m_hash >> 11;
    }

    // Handle end cases
    switch (rem)
    {
        case 3: m_hash += GET16BITS(current);
                m_hash ^= m_hash << 16;
                m_hash ^= static_cast<int8_t>(current[sizeof(uint16_t)]) << 18;
                m_hash += m_hash >> 11;
                break;
        case 2: m_hash += GET16BITS(current);
                m_hash ^= m_hash << 11;
                m_hash += m_hash >> 17;
                break;
        case 1: m_hash += *reinterpret_cast<const int8_t*>(current);
                m_hash ^= m_hash << 10;
                m_hash += m_hash >> 1;
    }
}

std::vector<uint8_t> SuperFastHash32::hashFinal()
{
    /// Force "avalanching" of final 127 bits
    m_hash ^= m_hash << 3;
    m_hash += m_hash >> 5;
    m_hash ^= m_hash << 4;
    m_hash += m_hash >> 17;
    m_hash ^= m_hash << 25;
    m_hash += m_hash >> 6;

    /// Make sure the hash is Big-Endian.
    uint32_t data = endian::native_to_big(m_hash);

    /// Convert the hash to a vector of bytes.
    std::vector<uint8_t> v(reinterpret_cast<uint8_t*>(&data),
                           reinterpret_cast<uint8_t*>(&data) + sizeof(uint32_t));
    return std::move(v);
}

} // noncryptographic namespace
} // hashing namespace
} // keeg namespace

#endif // SUPERFASTHASH32_HPP
