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
#ifndef ADLER32_HPP
#define ADLER32_HPP

#include <keeg/hashing/hashalgorithm.hpp>
#include <keeg/endian/conversion.hpp>

namespace keeg { namespace hashing { namespace checksum {

#define MOD_ADLER32 UINT32_C(65521)

#define DO1(buf,i)  {a += (buf)[i]; b += a;}
#define DO2(buf,i)  DO1(buf,i); DO1(buf,i+1);
#define DO4(buf,i)  DO2(buf,i); DO2(buf,i+2);
#define DO8(buf,i)  DO4(buf,i); DO4(buf,i+4);
#define DO16(buf)   DO8(buf,0); DO8(buf,8);

#define MOD(a) ((a) %= MOD_ADLER32)

class Adler32 : public HashAlgorithm
{
public:
    Adler32();

    // HashAlgorithm interface
public:
    virtual std::size_t hashSize() override;
    virtual void initialize() override;

protected:
    virtual void hashCore(const void *data, const std::size_t &dataLength, const std::size_t &startIndex) override;

    virtual std::vector<uint8_t> hashFinal() override;

private:
    static const std::size_t m_hashSize = std::numeric_limits<uint32_t>::digits;
    const uint32_t m_modAdler = UINT32_C(65521); // largest prime smaller than 65536
    const uint32_t m_nmax     = UINT32_C(5552);
    uint32_t m_hash           = UINT32_C(1);

    static_assert(std::is_same<uint8_t, unsigned char>::value,
                  "uint8_t is required to be implemented as unsigned char!");
};

Adler32::Adler32() : HashAlgorithm()
{
    initialize();
}

std::size_t Adler32::hashSize()
{
    return m_hashSize;
}

void Adler32::initialize()
{
    m_hash = UINT32_C(1);
    m_hashValue.clear();
}

void Adler32::hashCore(const void *data, const std::size_t &dataLength, const std::size_t &startIndex)
{
    uint32_t a = m_hash & 0xFFFF;
    uint32_t b = (m_hash >> 16) & 0xFFFF;
    const uint8_t *current = static_cast<const uint8_t*>(data) + startIndex;

    if (data == nullptr)
    {
        m_hash = 1L;
    }
    else if (dataLength == 1)
    {
        a += *current;
        if (a >= m_modAdler)
            a -= m_modAdler;
        b += a;
        if (b >= m_modAdler)
            b -= m_modAdler;

        m_hash = a | (b << 16);
    }
    else
    {
        std::size_t length = dataLength;
        std::size_t k;
        while (length > 0)
        {
            k = length < m_nmax ? length : m_nmax;
            length -= k;
            while (k >= 16)
            {
                DO16(current);
                current += 16;
                k -= 16;
            }
            if (k != 0)
            {
                do
                {
                    a += *current++;
                    b += a;
                }
                while (--k);
            }
            a %= m_modAdler;
            b %= m_modAdler;
        }

        m_hash = a | (b << 16);
    }
    //        else
    //        {
    //            /* Process each byte of the data in order */
    //            for (std::size_t index = 0; index < dataLength; ++index)
    //            {
    //                a = (a + *current++) % m_modAdler;
    //                b = (b + a) % m_modAdler;
    //            }

    //            m_hash = a | (b << 16);
    //        }
}

std::vector<uint8_t> Adler32::hashFinal()
{
    /// Make sure the hash is Big-Endian.
    uint32_t data = endian::native_to_big(m_hash);

    /// Convert the hash to a vector of bytes.
    std::vector<uint8_t> v(reinterpret_cast<uint8_t*>(&data),
                           reinterpret_cast<uint8_t*>(&data) + sizeof(uint32_t));
    return std::move(v);
}

} // checksum namespace
} // hashing namespace
} // keeg namespace

#endif // ADLER32_HPP
