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

/*
 * Source is adapted from the source written by Stephan Brumme
 * Orinal source from: http://create.stephan-brumme.com/crc32/
 */

#ifndef SHA3_HPP
#define SHA3_HPP

#include <keeg/hashing/hashalgorithm.hpp>
#include <keeg/common/enums.hpp>
#include <keeg/endian/conversion.hpp>

namespace keeg { namespace hashing { namespace cryptographic {

enum class Sha3Bits : uint16_t
{
    Bits224 = 224,
    Bits256 = 256,
    Bits384 = 384,
    Bits512 = 512
};

class Sha3 : public HashAlgorithm
{
public:
    Sha3(const Sha3Bits &bits = Sha3Bits::Bits256);

    // HashAlgorithm interface
public:
    virtual std::size_t hashSize() override;
    virtual void initialize() override;

protected:
    virtual void hashCore(const void *data, const std::size_t &dataLength, const std::size_t &startIndex) override;
    virtual std::vector<uint8_t> hashFinal() override;

private:
    /// 1600 bits, stored as 25x64 bit, BlockSize is no more than 1152 bits (Keccak224)
    static const uint32_t StateSize = 1600 / (8 * 8);
    static const uint32_t MaxBlockSize = 200 - 2 * (224 / 8);

    static const uint32_t Rounds = 24;
    static const uint64_t XorMasks[Rounds] =
    {
        UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082), UINT64_C(0x800000000000808a),
        UINT64_C(0x8000000080008000), UINT64_C(0x000000000000808b), UINT64_C(0x0000000080000001),
        UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009), UINT64_C(0x000000000000008a),
        UINT64_C(0x0000000000000088), UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000a),
        UINT64_C(0x000000008000808b), UINT64_C(0x800000000000008b), UINT64_C(0x8000000000008089),
        UINT64_C(0x8000000000008003), UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
        UINT64_C(0x000000000000800a), UINT64_C(0x800000008000000a), UINT64_C(0x8000000080008081),
        UINT64_C(0x8000000000008080), UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008)
    };

    /// hash
    uint64_t    m_hash[StateSize];
    /// size of processed data in bytes
    uint64_t    m_numBytes;
    /// block size (less or equal to MaxBlockSize)
    std::size_t m_blockSize;
    /// valid bytes in m_buffer
    std::size_t m_bufferSize;
    /// bytes not processed yet
    uint8_t     m_buffer[MaxBlockSize];
    /// variant
    Sha3Bits    m_bits;

    /// process a full block
    void processBlock(const void* data);
    /// process everything left in the internal buffer
    void processBuffer();

    static_assert(std::is_same<uint8_t, unsigned char>::value,
                  "uint8_t is required to be implemented as unsigned char!");
};

/// constants and local helper functions
namespace
{

/// rotate left and wrap around to the right
#ifndef rotateLeft(x,y)
    #define rotateLeft(x,y) keeg::endian::rotateLeft((x),(y))
#endif

/// return x % 5 for 0 <= x <= 9
uint32_t mod5(uint32_t x)
{
    if (x < 5)
        return x;

    return x - 5;
}

} // anonymous namespace

Sha3::Sha3(const Sha3Bits &bits) :
    HashAlgorithm(), m_blockSize(200 - 2 * (common::enumToIntegral(bits) / 8)), m_bits(bits)
{
    initialize();
}

std::size_t Sha3::hashSize()
{
    return static_cast<std::size_t>(common::enumToIntegral(m_bits));
}

void Sha3::initialize()
{
    for (std::size_t i = 0; i < StateSize; i++)
        m_hash[i] = 0;

    m_hashValue.clear();
    m_numBytes   = 0;
    m_bufferSize = 0;
}

void Sha3::hashCore(const void *data, const size_t &dataLength, const size_t &startIndex)
{
    const uint8_t* current = static_cast<const uint8_t*>(data) + startIndex;
    std::size_t numBytes = dataLength;

    // copy data to buffer
    if (m_bufferSize > 0)
    {
        while (numBytes > 0 && m_bufferSize < m_blockSize)
        {
            m_buffer[m_bufferSize++] = *current++;
            numBytes--;
        }
    }

    // full buffer
    if (m_bufferSize == m_blockSize)
    {
        processBlock(static_cast<void*>(m_buffer));
        m_numBytes  += m_blockSize;
        m_bufferSize = 0;
    }

    // no more data ?
    if (numBytes == 0)
        return;

    // process full blocks
    while (numBytes >= m_blockSize)
    {
        processBlock(current);
        current    += m_blockSize;
        m_numBytes += m_blockSize;
        numBytes   -= m_blockSize;
    }

    // keep remaining bytes in buffer
    while (numBytes > 0)
    {
        m_buffer[m_bufferSize++] = *current++;
        numBytes--;
    }
}

std::vector<uint8_t> Sha3::hashFinal()
{
    // process remaining bytes
    processBuffer();

    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&m_hash[0]);
    std::vector<uint8_t> v(bytes, bytes + (hashSize()/std::numeric_limits<uint8_t>::digits));

    return std::move(v);
}

void Sha3::processBlock(const void *data)
{
#if defined(__BYTE_ORDER) && (__BYTE_ORDER != 0) && (__BYTE_ORDER == __BIG_ENDIAN)
    #define LITTLEENDIAN(x) endian::swap(x)
#else
    #define LITTLEENDIAN(x) (x)
#endif

    const uint64_t* data64 = static_cast<const uint64_t*>(data);

    // mix data into state
    for (uint32_t i = 0; i < m_blockSize / 8; i++)
        m_hash[i] ^= LITTLEENDIAN(data64[i]);

    // re-compute state
    for (uint32_t round = 0; round < Rounds; round++)
    {
        // Theta
        uint64_t coefficients[5];
        for (uint32_t i = 0; i < 5; i++)
            coefficients[i] = m_hash[i] ^ m_hash[i + 5] ^ m_hash[i + 10] ^ m_hash[i + 15] ^ m_hash[i + 20];

        for (uint32_t i = 0; i < 5; i++)
        {
            uint64_t one = coefficients[mod5(i + 4)] ^ rotateLeft(coefficients[mod5(i + 1)], 1);
            m_hash[i     ] ^= one;
            m_hash[i +  5] ^= one;
            m_hash[i + 10] ^= one;
            m_hash[i + 15] ^= one;
            m_hash[i + 20] ^= one;
        }

        // temporary
        uint64_t one;

        // Rho Pi
        uint64_t last = m_hash[1];
        one = m_hash[10]; m_hash[10] = rotateLeft(last,  1); last = one;
        one = m_hash[ 7]; m_hash[ 7] = rotateLeft(last,  3); last = one;
        one = m_hash[11]; m_hash[11] = rotateLeft(last,  6); last = one;
        one = m_hash[17]; m_hash[17] = rotateLeft(last, 10); last = one;
        one = m_hash[18]; m_hash[18] = rotateLeft(last, 15); last = one;
        one = m_hash[ 3]; m_hash[ 3] = rotateLeft(last, 21); last = one;
        one = m_hash[ 5]; m_hash[ 5] = rotateLeft(last, 28); last = one;
        one = m_hash[16]; m_hash[16] = rotateLeft(last, 36); last = one;
        one = m_hash[ 8]; m_hash[ 8] = rotateLeft(last, 45); last = one;
        one = m_hash[21]; m_hash[21] = rotateLeft(last, 55); last = one;
        one = m_hash[24]; m_hash[24] = rotateLeft(last,  2); last = one;
        one = m_hash[ 4]; m_hash[ 4] = rotateLeft(last, 14); last = one;
        one = m_hash[15]; m_hash[15] = rotateLeft(last, 27); last = one;
        one = m_hash[23]; m_hash[23] = rotateLeft(last, 41); last = one;
        one = m_hash[19]; m_hash[19] = rotateLeft(last, 56); last = one;
        one = m_hash[13]; m_hash[13] = rotateLeft(last,  8); last = one;
        one = m_hash[12]; m_hash[12] = rotateLeft(last, 25); last = one;
        one = m_hash[ 2]; m_hash[ 2] = rotateLeft(last, 43); last = one;
        one = m_hash[20]; m_hash[20] = rotateLeft(last, 62); last = one;
        one = m_hash[14]; m_hash[14] = rotateLeft(last, 18); last = one;
        one = m_hash[22]; m_hash[22] = rotateLeft(last, 39); last = one;
        one = m_hash[ 9]; m_hash[ 9] = rotateLeft(last, 61); last = one;
        one = m_hash[ 6]; m_hash[ 6] = rotateLeft(last, 20); last = one;
        m_hash[ 1] = rotateLeft(last, 44);

        // Chi
        for (uint32_t j = 0; j < 25; j += 5)
        {
            // temporaries
            uint64_t one = m_hash[j];
            uint64_t two = m_hash[j + 1];

            m_hash[j]     ^= m_hash[j + 2] & ~two;
            m_hash[j + 1] ^= m_hash[j + 3] & ~m_hash[j + 2];
            m_hash[j + 2] ^= m_hash[j + 4] & ~m_hash[j + 3];
            m_hash[j + 3] ^=      one      & ~m_hash[j + 4];
            m_hash[j + 4] ^=      two      & ~one;
        }

        // Iota
        m_hash[0] ^= XorMasks[round];
    }
}

void Sha3::processBuffer()
{
    // add padding
    std::size_t offset = m_bufferSize;

    // add a "1" byte
    m_buffer[offset++] = 0x06;

    // fill with zeros
    while (offset < m_blockSize)
        m_buffer[offset++] = 0;

    // and add a single set bit
    m_buffer[offset - 1] |= 0x80;

    processBlock(m_buffer);
}

} // cryptographic namespace
} // hashing namespace
} // keeg namespace

#endif // SHA3_HPP
