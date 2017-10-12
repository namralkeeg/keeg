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

#ifndef MD5_HPP
#define MD5_HPP

#include <keeg/hashing/hashalgorithm.hpp>
#include <keeg/endian/conversion.hpp>
#include <algorithm>

namespace keeg { namespace hashing { namespace cryptographic {

class Md5 : public HashAlgorithm
{
public:
    Md5();

    // HashAlgorithm interface
public:
    virtual std::size_t hashSize() override;
    virtual void initialize() override;

protected:
    virtual void hashCore(const void *data, const std::size_t &dataLength, const std::size_t &startIndex) override;

    virtual std::vector<uint8_t> hashFinal() override;

private:
    static const std::size_t m_hashSize = std::numeric_limits<uint8_t>::digits * 16;
    /// split into 64 byte blocks (=> 512 bits)
    static const uint32_t BLOCK_SIZE = 512 / 8;
    static const uint32_t NUM_HASH_VALUES = 16 / 4;

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

inline uint32_t f1(uint32_t b, uint32_t c, uint32_t d)
{
    return d ^ (b & (c ^ d)); // original: f = (b & c) | ((~b) & d);
}

inline uint32_t f2(uint32_t b, uint32_t c, uint32_t d)
{
    return c ^ (d & (b ^ c)); // original: f = (b & d) | (c & (~d));
}

inline uint32_t f3(uint32_t b, uint32_t c, uint32_t d)
{
    return b ^ c ^ d;
}

inline uint32_t f4(uint32_t b, uint32_t c, uint32_t d)
{
    return c ^ (b | ~d);
}

} // anonymous namespace block

Md5::Md5() : HashAlgorithm()
{
    initialize();
}

std::size_t Md5::hashSize()
{
    return m_hashSize;
}

void Md5::initialize()
{
    m_hashValue.clear();
    m_numBytes   = 0;
    m_bufferSize = 0;

    // according to RFC 1321
    m_hash[0] = UINT32_C(0x67452301);
    m_hash[1] = UINT32_C(0xefcdab89);
    m_hash[2] = UINT32_C(0x98badcfe);
    m_hash[3] = UINT32_C(0x10325476);
}

void Md5::hashCore(const void *data, const std::size_t &dataLength, const std::size_t &startIndex)
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
        processBlock(m_buffer);
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

std::vector<uint8_t> Md5::hashFinal()
{
    // save old hash if buffer is partially filled
    uint32_t oldHash[NUM_HASH_VALUES];
    for (uint32_t i = 0; i < NUM_HASH_VALUES; i++)
        oldHash[i] = m_hash[i];

    // process remaining bytes
    processBuffer();

    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&m_hash[0]);

    std::vector<uint8_t> v(bytes, bytes + (m_hashSize/std::numeric_limits<uint8_t>::digits));

    for (uint32_t i = 0; i < NUM_HASH_VALUES; ++i)
    {
        // restore old hash
        m_hash[i] = oldHash[i];
    }

    return std::move(v);
}

void Md5::processBlock(const void *data)
{
    // get last hash
    uint32_t a = m_hash[0];
    uint32_t b = m_hash[1];
    uint32_t c = m_hash[2];
    uint32_t d = m_hash[3];

    // data represented as 16x 32-bit words
    const uint32_t* words = static_cast<const uint32_t*>(data);

    // computations are little endian, swap data if necessary
    #if defined(__BYTE_ORDER) && (__BYTE_ORDER != 0) && (__BYTE_ORDER == __BIG_ENDIAN)
        #define LITTLEENDIAN(x) endian::swap(x)
    #else
        #define LITTLEENDIAN(x) (x)
    #endif

    // first round
    uint32_t word0  = LITTLEENDIAN(words[ 0]);
    a = rotateLeft(a + f1(b,c,d) + word0  + 0xd76aa478,  7) + b;
    uint32_t word1  = LITTLEENDIAN(words[ 1]);
    d = rotateLeft(d + f1(a,b,c) + word1  + 0xe8c7b756, 12) + a;
    uint32_t word2  = LITTLEENDIAN(words[ 2]);
    c = rotateLeft(c + f1(d,a,b) + word2  + 0x242070db, 17) + d;
    uint32_t word3  = LITTLEENDIAN(words[ 3]);
    b = rotateLeft(b + f1(c,d,a) + word3  + 0xc1bdceee, 22) + c;

    uint32_t word4  = LITTLEENDIAN(words[ 4]);
    a = rotateLeft(a + f1(b,c,d) + word4  + 0xf57c0faf,  7) + b;
    uint32_t word5  = LITTLEENDIAN(words[ 5]);
    d = rotateLeft(d + f1(a,b,c) + word5  + 0x4787c62a, 12) + a;
    uint32_t word6  = LITTLEENDIAN(words[ 6]);
    c = rotateLeft(c + f1(d,a,b) + word6  + 0xa8304613, 17) + d;
    uint32_t word7  = LITTLEENDIAN(words[ 7]);
    b = rotateLeft(b + f1(c,d,a) + word7  + 0xfd469501, 22) + c;

    uint32_t word8  = LITTLEENDIAN(words[ 8]);
    a = rotateLeft(a + f1(b,c,d) + word8  + 0x698098d8,  7) + b;
    uint32_t word9  = LITTLEENDIAN(words[ 9]);
    d = rotateLeft(d + f1(a,b,c) + word9  + 0x8b44f7af, 12) + a;
    uint32_t word10 = LITTLEENDIAN(words[10]);
    c = rotateLeft(c + f1(d,a,b) + word10 + 0xffff5bb1, 17) + d;
    uint32_t word11 = LITTLEENDIAN(words[11]);
    b = rotateLeft(b + f1(c,d,a) + word11 + 0x895cd7be, 22) + c;

    uint32_t word12 = LITTLEENDIAN(words[12]);
    a = rotateLeft(a + f1(b,c,d) + word12 + 0x6b901122,  7) + b;
    uint32_t word13 = LITTLEENDIAN(words[13]);
    d = rotateLeft(d + f1(a,b,c) + word13 + 0xfd987193, 12) + a;
    uint32_t word14 = LITTLEENDIAN(words[14]);
    c = rotateLeft(c + f1(d,a,b) + word14 + 0xa679438e, 17) + d;
    uint32_t word15 = LITTLEENDIAN(words[15]);
    b = rotateLeft(b + f1(c,d,a) + word15 + 0x49b40821, 22) + c;

    // second round
    a = rotateLeft(a + f2(b,c,d) + word1  + 0xf61e2562,  5) + b;
    d = rotateLeft(d + f2(a,b,c) + word6  + 0xc040b340,  9) + a;
    c = rotateLeft(c + f2(d,a,b) + word11 + 0x265e5a51, 14) + d;
    b = rotateLeft(b + f2(c,d,a) + word0  + 0xe9b6c7aa, 20) + c;

    a = rotateLeft(a + f2(b,c,d) + word5  + 0xd62f105d,  5) + b;
    d = rotateLeft(d + f2(a,b,c) + word10 + 0x02441453,  9) + a;
    c = rotateLeft(c + f2(d,a,b) + word15 + 0xd8a1e681, 14) + d;
    b = rotateLeft(b + f2(c,d,a) + word4  + 0xe7d3fbc8, 20) + c;

    a = rotateLeft(a + f2(b,c,d) + word9  + 0x21e1cde6,  5) + b;
    d = rotateLeft(d + f2(a,b,c) + word14 + 0xc33707d6,  9) + a;
    c = rotateLeft(c + f2(d,a,b) + word3  + 0xf4d50d87, 14) + d;
    b = rotateLeft(b + f2(c,d,a) + word8  + 0x455a14ed, 20) + c;

    a = rotateLeft(a + f2(b,c,d) + word13 + 0xa9e3e905,  5) + b;
    d = rotateLeft(d + f2(a,b,c) + word2  + 0xfcefa3f8,  9) + a;
    c = rotateLeft(c + f2(d,a,b) + word7  + 0x676f02d9, 14) + d;
    b = rotateLeft(b + f2(c,d,a) + word12 + 0x8d2a4c8a, 20) + c;

    // third round
    a = rotateLeft(a + f3(b,c,d) + word5  + 0xfffa3942,  4) + b;
    d = rotateLeft(d + f3(a,b,c) + word8  + 0x8771f681, 11) + a;
    c = rotateLeft(c + f3(d,a,b) + word11 + 0x6d9d6122, 16) + d;
    b = rotateLeft(b + f3(c,d,a) + word14 + 0xfde5380c, 23) + c;

    a = rotateLeft(a + f3(b,c,d) + word1  + 0xa4beea44,  4) + b;
    d = rotateLeft(d + f3(a,b,c) + word4  + 0x4bdecfa9, 11) + a;
    c = rotateLeft(c + f3(d,a,b) + word7  + 0xf6bb4b60, 16) + d;
    b = rotateLeft(b + f3(c,d,a) + word10 + 0xbebfbc70, 23) + c;

    a = rotateLeft(a + f3(b,c,d) + word13 + 0x289b7ec6,  4) + b;
    d = rotateLeft(d + f3(a,b,c) + word0  + 0xeaa127fa, 11) + a;
    c = rotateLeft(c + f3(d,a,b) + word3  + 0xd4ef3085, 16) + d;
    b = rotateLeft(b + f3(c,d,a) + word6  + 0x04881d05, 23) + c;

    a = rotateLeft(a + f3(b,c,d) + word9  + 0xd9d4d039,  4) + b;
    d = rotateLeft(d + f3(a,b,c) + word12 + 0xe6db99e5, 11) + a;
    c = rotateLeft(c + f3(d,a,b) + word15 + 0x1fa27cf8, 16) + d;
    b = rotateLeft(b + f3(c,d,a) + word2  + 0xc4ac5665, 23) + c;

    // fourth round
    a = rotateLeft(a + f4(b,c,d) + word0  + 0xf4292244,  6) + b;
    d = rotateLeft(d + f4(a,b,c) + word7  + 0x432aff97, 10) + a;
    c = rotateLeft(c + f4(d,a,b) + word14 + 0xab9423a7, 15) + d;
    b = rotateLeft(b + f4(c,d,a) + word5  + 0xfc93a039, 21) + c;

    a = rotateLeft(a + f4(b,c,d) + word12 + 0x655b59c3,  6) + b;
    d = rotateLeft(d + f4(a,b,c) + word3  + 0x8f0ccc92, 10) + a;
    c = rotateLeft(c + f4(d,a,b) + word10 + 0xffeff47d, 15) + d;
    b = rotateLeft(b + f4(c,d,a) + word1  + 0x85845dd1, 21) + c;

    a = rotateLeft(a + f4(b,c,d) + word8  + 0x6fa87e4f,  6) + b;
    d = rotateLeft(d + f4(a,b,c) + word15 + 0xfe2ce6e0, 10) + a;
    c = rotateLeft(c + f4(d,a,b) + word6  + 0xa3014314, 15) + d;
    b = rotateLeft(b + f4(c,d,a) + word13 + 0x4e0811a1, 21) + c;

    a = rotateLeft(a + f4(b,c,d) + word4  + 0xf7537e82,  6) + b;
    d = rotateLeft(d + f4(a,b,c) + word11 + 0xbd3af235, 10) + a;
    c = rotateLeft(c + f4(d,a,b) + word2  + 0x2ad7d2bb, 15) + d;
    b = rotateLeft(b + f4(c,d,a) + word9  + 0xeb86d391, 21) + c;

    // update hash
    m_hash[0] += a;
    m_hash[1] += b;
    m_hash[2] += c;
    m_hash[3] += d;
}

void Md5::processBuffer()
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

    // must be little endian
    *addLength++ = msgBits & 0xFF; msgBits >>= 8;
    *addLength++ = msgBits & 0xFF; msgBits >>= 8;
    *addLength++ = msgBits & 0xFF; msgBits >>= 8;
    *addLength++ = msgBits & 0xFF; msgBits >>= 8;
    *addLength++ = msgBits & 0xFF; msgBits >>= 8;
    *addLength++ = msgBits & 0xFF; msgBits >>= 8;
    *addLength++ = msgBits & 0xFF; msgBits >>= 8;
    *addLength++ = msgBits & 0xFF;

    // process blocks
    processBlock(m_buffer);

    // flowed over into a second block ?
    if (paddedLength > BLOCK_SIZE)
        processBlock(extra);
}

} // cryptographic namespace
} // keeg namespace
} // hashing namespace

#endif // MD5_HPP
