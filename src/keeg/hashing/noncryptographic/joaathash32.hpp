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
#ifndef JOAATHASH32_HPP
#define JOAATHASH32_HPP

#include <keeg/hashing/hashalgorithm.hpp>
#include <keeg/endian/conversion.hpp>

namespace keeg { namespace hashing { namespace noncryptographic {

/// Bob Jenkins One-at-a-Time hash
class JOAATHash32 : public HashAlgorithm
{
public:
    JOAATHash32();

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

JOAATHash32::JOAATHash32() : HashAlgorithm()
{
    initialize();
}

size_t JOAATHash32::hashSize()
{
    return m_hashSize;
}

void JOAATHash32::initialize()
{
    m_hash = 0;
    m_hashValue.clear();
}

void JOAATHash32::hashCore(const void *data, const std::size_t &dataLength, const std::size_t &startIndex)
{
    const uint8_t *current = static_cast<const uint8_t*>(data) + startIndex;

    for (std::size_t i = 0; i < dataLength; ++current, ++i)
    {
        m_hash += *current;
        m_hash += (m_hash << 10);
        m_hash ^= (m_hash >> 6);
    }
}

std::vector<uint8_t> JOAATHash32::hashFinal()
{
    m_hash += (m_hash << 3);
    m_hash ^= (m_hash >> 11);
    m_hash += (m_hash << 15);

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

#endif // JOAATHASH32_HPP
