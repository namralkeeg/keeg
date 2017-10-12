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

#ifndef SHA1_HPP
#define SHA1_HPP

#include <keeg/hashing/hashalgorithm.hpp>
#include <keeg/endian/conversion.hpp>

namespace keeg { namespace hashing { namespace cryptographic {

class Sha1 : public HashAlgorithm
{
public:
    Sha1();

    // HashAlgorithm interface
public:
    virtual std::size_t hashSize() override;
    virtual void initialize() override;

protected:
    virtual void hashCore(const void *data, const std::size_t &dataLength, const std::size_t &startIndex) override;
    virtual std::vector<uint8_t> hashFinal() override;

private:
    static const std::size_t m_hashSize = std::numeric_limits<uint8_t>::digits * 20;

    /// split into 64 byte blocks (=> 512 bits)
    static const uint32_t BLOCK_SIZE = 512 / 8;
    static const uint32_t NUM_HASH_VALUES = 20 / 4;

    /// size of processed data in bytes
    uint64_t m_numBytes;
    /// valid bytes in m_buffer
    std::size_t m_bufferSize;
    /// bytes not processed yet
    uint8_t m_buffer[BLOCK_SIZE];
    /// hash, stored as integers
    uint32_t m_hash[NUM_HASH_VALUES];

    /// process 64 bytes
    void processBlock(const void *data);

    /// process everything left in the internal buffer
    void processBuffer();

    static_assert(std::is_same<uint8_t, unsigned char>::value,
                  "uint8_t is required to be implemented as unsigned char!");
};

namespace {

#ifndef rotateLeft(x,y)
    #define rotateLeft(x,y) keeg::endian::rotateLeft((x),(y))
#endif

// mix functions for processBlock()
inline uint32_t f1(uint32_t b, uint32_t c, uint32_t d)
{
    return d ^ (b & (c ^ d)); // original: f = (b & c) | ((~b) & d);
}

inline uint32_t f2(uint32_t b, uint32_t c, uint32_t d)
{
    return b ^ c ^ d;
}

inline uint32_t f3(uint32_t b, uint32_t c, uint32_t d)
{
    return (b & c) | (b & d) | (c & d);
}

} // anonymous namespace

Sha1::Sha1() : HashAlgorithm()
{
    initialize();
}

std::size_t Sha1::hashSize()
{
    return m_hashSize;
}

void Sha1::initialize()
{
    m_hashValue.clear();
    m_numBytes   = 0;
    m_bufferSize = 0;

    // according to RFC 1321
    m_hash[0] = UINT32_C(0x67452301);
    m_hash[1] = UINT32_C(0xefcdab89);
    m_hash[2] = UINT32_C(0x98badcfe);
    m_hash[3] = UINT32_C(0x10325476);
    m_hash[4] = UINT32_C(0xc3d2e1f0);
}

void Sha1::hashCore(const void *data, const std::size_t &dataLength, const std::size_t &startIndex)
{
    const uint8_t* current = static_cast<const uint8_t*>(data) + startIndex;
    std::size_t numBytes = dataLength;

    if (m_bufferSize > 0)
    {
        while (numBytes > 0 && m_bufferSize < BLOCK_SIZE)
        {
            m_buffer[m_bufferSize++] = *current++;
            numBytes--;
        }
    }

    // full buffer
    if (m_bufferSize == BLOCK_SIZE)
    {
        processBlock((void*)m_buffer);
        m_numBytes  += BLOCK_SIZE;
        m_bufferSize = 0;
    }

    // no more data ?
    if (numBytes == 0)
        return;

    // process full blocks
    while (numBytes >= BLOCK_SIZE)
    {
        processBlock(current);
        current    += BLOCK_SIZE;
        m_numBytes += BLOCK_SIZE;
        numBytes   -= BLOCK_SIZE;
    }

    // keep remaining bytes in buffer
    while (numBytes > 0)
    {
        m_buffer[m_bufferSize++] = *current++;
        numBytes--;
    }
}

std::vector<uint8_t> Sha1::hashFinal()
{
    // save old hash if buffer is partially filled
    uint32_t oldHash[NUM_HASH_VALUES];
    for (uint32_t i = 0; i < NUM_HASH_VALUES; i++)
        oldHash[i] = m_hash[i];

    // process remaining bytes
    processBuffer();

    std::vector<uint8_t> v;
    v.reserve(m_hashSize/std::numeric_limits<uint8_t>::digits);
    for (uint32_t i = 0; i < NUM_HASH_VALUES; i++)
    {
        v.insert(v.end(), (m_hash[i] >> 24) & 0xFF);
        v.insert(v.end(), (m_hash[i] >> 16) & 0xFF);
        v.insert(v.end(), (m_hash[i] >>  8) & 0xFF);
        v.insert(v.end(),  m_hash[i]        & 0xFF);

        // restore old hash
        m_hash[i] = oldHash[i];
    }

    return std::move(v);
}

void Sha1::processBlock(const void *data)
{
    // get last hash
    uint32_t a = m_hash[0];
    uint32_t b = m_hash[1];
    uint32_t c = m_hash[2];
    uint32_t d = m_hash[3];
    uint32_t e = m_hash[4];

    // data represented as 16x 32-bit words
    const uint32_t* input = static_cast<const uint32_t*>(data);

    // convert to big endian
    uint32_t words[80];
    for (int i = 0; i < 16; i++)
#if defined(__BYTE_ORDER) && (__BYTE_ORDER != 0) && (__BYTE_ORDER == __BIG_ENDIAN)
        words[i] = input[i];
#else
        words[i] = endian::swap(input[i]);
#endif

    // extend to 80 words
    for (int i = 16; i < 80; i++)
        words[i] = rotateLeft(words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16], 1);

    // first round
    for (int i = 0; i < 4; i++)
    {
        int offset = 5*i;
        e += rotateLeft(a,5) + f1(b,c,d) + words[offset  ] + 0x5a827999; b = rotateLeft(b,30);
        d += rotateLeft(e,5) + f1(a,b,c) + words[offset+1] + 0x5a827999; a = rotateLeft(a,30);
        c += rotateLeft(d,5) + f1(e,a,b) + words[offset+2] + 0x5a827999; e = rotateLeft(e,30);
        b += rotateLeft(c,5) + f1(d,e,a) + words[offset+3] + 0x5a827999; d = rotateLeft(d,30);
        a += rotateLeft(b,5) + f1(c,d,e) + words[offset+4] + 0x5a827999; c = rotateLeft(c,30);
    }

    // second round
    for (int i = 4; i < 8; i++)
    {
        int offset = 5*i;
        e += rotateLeft(a,5) + f2(b,c,d) + words[offset  ] + 0x6ed9eba1; b = rotateLeft(b,30);
        d += rotateLeft(e,5) + f2(a,b,c) + words[offset+1] + 0x6ed9eba1; a = rotateLeft(a,30);
        c += rotateLeft(d,5) + f2(e,a,b) + words[offset+2] + 0x6ed9eba1; e = rotateLeft(e,30);
        b += rotateLeft(c,5) + f2(d,e,a) + words[offset+3] + 0x6ed9eba1; d = rotateLeft(d,30);
        a += rotateLeft(b,5) + f2(c,d,e) + words[offset+4] + 0x6ed9eba1; c = rotateLeft(c,30);
    }

    // third round
    for (int i = 8; i < 12; i++)
    {
        int offset = 5*i;
        e += rotateLeft(a,5) + f3(b,c,d) + words[offset  ] + 0x8f1bbcdc; b = rotateLeft(b,30);
        d += rotateLeft(e,5) + f3(a,b,c) + words[offset+1] + 0x8f1bbcdc; a = rotateLeft(a,30);
        c += rotateLeft(d,5) + f3(e,a,b) + words[offset+2] + 0x8f1bbcdc; e = rotateLeft(e,30);
        b += rotateLeft(c,5) + f3(d,e,a) + words[offset+3] + 0x8f1bbcdc; d = rotateLeft(d,30);
        a += rotateLeft(b,5) + f3(c,d,e) + words[offset+4] + 0x8f1bbcdc; c = rotateLeft(c,30);
    }

    // fourth round
    for (int i = 12; i < 16; i++)
    {
        int offset = 5*i;
        e += rotateLeft(a,5) + f2(b,c,d) + words[offset  ] + 0xca62c1d6; b = rotateLeft(b,30);
        d += rotateLeft(e,5) + f2(a,b,c) + words[offset+1] + 0xca62c1d6; a = rotateLeft(a,30);
        c += rotateLeft(d,5) + f2(e,a,b) + words[offset+2] + 0xca62c1d6; e = rotateLeft(e,30);
        b += rotateLeft(c,5) + f2(d,e,a) + words[offset+3] + 0xca62c1d6; d = rotateLeft(d,30);
        a += rotateLeft(b,5) + f2(c,d,e) + words[offset+4] + 0xca62c1d6; c = rotateLeft(c,30);
    }

    // update hash
    m_hash[0] += a;
    m_hash[1] += b;
    m_hash[2] += c;
    m_hash[3] += d;
    m_hash[4] += e;
}

void Sha1::processBuffer()
{
    // the input bytes are considered as bits strings, where the first bit is the most significant bit of the byte

    // - append "1" bit to message
    // - append "0" bits until message length in bit mod 512 is 448
    // - append length as 64 bit integer

    // number of bits
    std::size_t paddedLength = m_bufferSize * 8;

    // plus one bit set to 1 (always appended)
    paddedLength++;

    // number of bits must be (numBits % 512) = 448
    std::size_t lower11Bits = paddedLength & 511;
    if (lower11Bits <= 448)
        paddedLength +=       448 - lower11Bits;
    else
        paddedLength += 512 + 448 - lower11Bits;

    // convert from bits to bytes
    paddedLength /= 8;

    // only needed if additional data flows over into a second block
    uint8_t extra[BLOCK_SIZE];

    // append a "1" bit, 128 => binary 10000000
    if (m_bufferSize < BLOCK_SIZE)
        m_buffer[m_bufferSize] = 128;
    else
        extra[0] = 128;

    std::size_t i;
    for (i = m_bufferSize + 1; i < BLOCK_SIZE; i++)
        m_buffer[i] = 0;
    for (; i < paddedLength; i++)
        extra[i - BLOCK_SIZE] = 0;

    // add message length in bits as 64 bit number
    uint64_t msgBits = 8 * (m_numBytes + m_bufferSize);

    // find right position
    uint8_t* addLength;
    if (paddedLength < BLOCK_SIZE)
        addLength = m_buffer + paddedLength;
    else
        addLength = extra + paddedLength - BLOCK_SIZE;

    // must be big endian
    *addLength++ = static_cast<uint8_t>((msgBits >> 56) & 0xFF);
    *addLength++ = static_cast<uint8_t>((msgBits >> 48) & 0xFF);
    *addLength++ = static_cast<uint8_t>((msgBits >> 40) & 0xFF);
    *addLength++ = static_cast<uint8_t>((msgBits >> 32) & 0xFF);
    *addLength++ = static_cast<uint8_t>((msgBits >> 24) & 0xFF);
    *addLength++ = static_cast<uint8_t>((msgBits >> 16) & 0xFF);
    *addLength++ = static_cast<uint8_t>((msgBits >>  8) & 0xFF);
    *addLength   = static_cast<uint8_t>( msgBits        & 0xFF);

    // process blocks
    processBlock(m_buffer);

    // flowed over into a second block ?
    if (paddedLength > BLOCK_SIZE)
        processBlock(extra);
}

} // cryptographic namespace
} // hashing namespace
} // keeg namespace

#endif // SHA1_HPP
