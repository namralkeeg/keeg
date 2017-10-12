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

#ifndef SHA256_HPP
#define SHA256_HPP

#include <keeg/hashing/hashalgorithm.hpp>
#include <keeg/endian/conversion.hpp>

namespace keeg { namespace hashing {

class Sha256 : public HashAlgorithm
{
public:
    Sha256();

    // HashAlgorithm interface
public:
    virtual std::size_t hashSize() override;
    virtual void initialize() override;

protected:
    virtual void hashCore(const void *data, const std::size_t &dataLength, const std::size_t &startIndex) override;
    virtual std::vector<uint8_t> hashFinal() override;

private:
    static const std::size_t m_hashSize = std::numeric_limits<uint8_t>::digits * 32;

    /// split into 64 byte blocks (=> 512 bits)
    static const uint32_t BLOCK_SIZE = 512 / 8;
    static const uint32_t NUM_HASH_VALUES = 32 / 4;

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

namespace
{

#ifndef rotateRight(x,y)
    #define rotateRight(x,y) keeg::endian::rotateRight((x),(y))
#endif

// mix functions for processBlock()
inline uint32_t f1(uint32_t e, uint32_t f, uint32_t g)
{
    uint32_t term1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
    uint32_t term2 = (e & f) ^ (~e & g); //(g ^ (e & (f ^ g)))
    return term1 + term2;
}

inline uint32_t f2(uint32_t a, uint32_t b, uint32_t c)
{
    uint32_t term1 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
    uint32_t term2 = ((a | b) & c) | (a & b); //(a & (b ^ c)) ^ (b & c);
    return term1 + term2;
}

} // anonymous namespace

Sha256::Sha256() : HashAlgorithm()
{
    initialize();
}

std::size_t Sha256::hashSize()
{
    return m_hashSize;
}

void Sha256::initialize()
{
    m_hashValue.clear();
    m_numBytes   = 0;
    m_bufferSize = 0;

    // according to RFC 1321
    m_hash[0] = UINT32_C(0x6a09e667);
    m_hash[1] = UINT32_C(0xbb67ae85);
    m_hash[2] = UINT32_C(0x3c6ef372);
    m_hash[3] = UINT32_C(0xa54ff53a);
    m_hash[4] = UINT32_C(0x510e527f);
    m_hash[5] = UINT32_C(0x9b05688c);
    m_hash[6] = UINT32_C(0x1f83d9ab);
    m_hash[7] = UINT32_C(0x5be0cd19);
}

void Sha256::hashCore(const void *data, const std::size_t &dataLength, const std::size_t &startIndex)
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

std::vector<uint8_t> Sha256::hashFinal()
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

void Sha256::processBlock(const void *data)
{
    // get last hash
    uint32_t a = m_hash[0];
    uint32_t b = m_hash[1];
    uint32_t c = m_hash[2];
    uint32_t d = m_hash[3];
    uint32_t e = m_hash[4];
    uint32_t f = m_hash[5];
    uint32_t g = m_hash[6];
    uint32_t h = m_hash[7];

    // data represented as 16x 32-bit words
    const uint32_t* input = static_cast<const uint32_t*>(data);

    // convert to big endian
    uint32_t words[64];
    int i;
    for (i = 0; i < 16; i++)
#if defined(__BYTE_ORDER) && (__BYTE_ORDER != 0) && (__BYTE_ORDER == __BIG_ENDIAN)
        words[i] =      input[i];
#else
        words[i] = endian::swap(input[i]);
#endif

    uint32_t x,y; // temporaries

    // first round
    x = h + f1(e,f,g) + 0x428a2f98 + words[ 0]; y = f2(a,b,c); d += x; h = x + y;
    x = g + f1(d,e,f) + 0x71374491 + words[ 1]; y = f2(h,a,b); c += x; g = x + y;
    x = f + f1(c,d,e) + 0xb5c0fbcf + words[ 2]; y = f2(g,h,a); b += x; f = x + y;
    x = e + f1(b,c,d) + 0xe9b5dba5 + words[ 3]; y = f2(f,g,h); a += x; e = x + y;
    x = d + f1(a,b,c) + 0x3956c25b + words[ 4]; y = f2(e,f,g); h += x; d = x + y;
    x = c + f1(h,a,b) + 0x59f111f1 + words[ 5]; y = f2(d,e,f); g += x; c = x + y;
    x = b + f1(g,h,a) + 0x923f82a4 + words[ 6]; y = f2(c,d,e); f += x; b = x + y;
    x = a + f1(f,g,h) + 0xab1c5ed5 + words[ 7]; y = f2(b,c,d); e += x; a = x + y;

    // secound round
    x = h + f1(e,f,g) + 0xd807aa98 + words[ 8]; y = f2(a,b,c); d += x; h = x + y;
    x = g + f1(d,e,f) + 0x12835b01 + words[ 9]; y = f2(h,a,b); c += x; g = x + y;
    x = f + f1(c,d,e) + 0x243185be + words[10]; y = f2(g,h,a); b += x; f = x + y;
    x = e + f1(b,c,d) + 0x550c7dc3 + words[11]; y = f2(f,g,h); a += x; e = x + y;
    x = d + f1(a,b,c) + 0x72be5d74 + words[12]; y = f2(e,f,g); h += x; d = x + y;
    x = c + f1(h,a,b) + 0x80deb1fe + words[13]; y = f2(d,e,f); g += x; c = x + y;
    x = b + f1(g,h,a) + 0x9bdc06a7 + words[14]; y = f2(c,d,e); f += x; b = x + y;
    x = a + f1(f,g,h) + 0xc19bf174 + words[15]; y = f2(b,c,d); e += x; a = x + y;

    // extend to 24 words
    for (; i < 24; i++)
        words[i] = words[i-16] +
                (rotateRight(words[i-15],  7) ^ rotateRight(words[i-15], 18) ^ (words[i-15] >>  3)) +
                words[i-7] +
                (rotateRight(words[i- 2], 17) ^ rotateRight(words[i- 2], 19) ^ (words[i- 2] >> 10));

    // third round
    x = h + f1(e,f,g) + 0xe49b69c1 + words[16]; y = f2(a,b,c); d += x; h = x + y;
    x = g + f1(d,e,f) + 0xefbe4786 + words[17]; y = f2(h,a,b); c += x; g = x + y;
    x = f + f1(c,d,e) + 0x0fc19dc6 + words[18]; y = f2(g,h,a); b += x; f = x + y;
    x = e + f1(b,c,d) + 0x240ca1cc + words[19]; y = f2(f,g,h); a += x; e = x + y;
    x = d + f1(a,b,c) + 0x2de92c6f + words[20]; y = f2(e,f,g); h += x; d = x + y;
    x = c + f1(h,a,b) + 0x4a7484aa + words[21]; y = f2(d,e,f); g += x; c = x + y;
    x = b + f1(g,h,a) + 0x5cb0a9dc + words[22]; y = f2(c,d,e); f += x; b = x + y;
    x = a + f1(f,g,h) + 0x76f988da + words[23]; y = f2(b,c,d); e += x; a = x + y;

    // extend to 32 words
    for (; i < 32; i++)
        words[i] = words[i-16] +
                (rotateRight(words[i-15],  7) ^ rotateRight(words[i-15], 18) ^ (words[i-15] >>  3)) +
                words[i-7] +
                (rotateRight(words[i- 2], 17) ^ rotateRight(words[i- 2], 19) ^ (words[i- 2] >> 10));

    // fourth round
    x = h + f1(e,f,g) + 0x983e5152 + words[24]; y = f2(a,b,c); d += x; h = x + y;
    x = g + f1(d,e,f) + 0xa831c66d + words[25]; y = f2(h,a,b); c += x; g = x + y;
    x = f + f1(c,d,e) + 0xb00327c8 + words[26]; y = f2(g,h,a); b += x; f = x + y;
    x = e + f1(b,c,d) + 0xbf597fc7 + words[27]; y = f2(f,g,h); a += x; e = x + y;
    x = d + f1(a,b,c) + 0xc6e00bf3 + words[28]; y = f2(e,f,g); h += x; d = x + y;
    x = c + f1(h,a,b) + 0xd5a79147 + words[29]; y = f2(d,e,f); g += x; c = x + y;
    x = b + f1(g,h,a) + 0x06ca6351 + words[30]; y = f2(c,d,e); f += x; b = x + y;
    x = a + f1(f,g,h) + 0x14292967 + words[31]; y = f2(b,c,d); e += x; a = x + y;

    // extend to 40 words
    for (; i < 40; i++)
        words[i] = words[i-16] +
                (rotateRight(words[i-15],  7) ^ rotateRight(words[i-15], 18) ^ (words[i-15] >>  3)) +
                words[i-7] +
                (rotateRight(words[i- 2], 17) ^ rotateRight(words[i- 2], 19) ^ (words[i- 2] >> 10));

    // fifth round
    x = h + f1(e,f,g) + 0x27b70a85 + words[32]; y = f2(a,b,c); d += x; h = x + y;
    x = g + f1(d,e,f) + 0x2e1b2138 + words[33]; y = f2(h,a,b); c += x; g = x + y;
    x = f + f1(c,d,e) + 0x4d2c6dfc + words[34]; y = f2(g,h,a); b += x; f = x + y;
    x = e + f1(b,c,d) + 0x53380d13 + words[35]; y = f2(f,g,h); a += x; e = x + y;
    x = d + f1(a,b,c) + 0x650a7354 + words[36]; y = f2(e,f,g); h += x; d = x + y;
    x = c + f1(h,a,b) + 0x766a0abb + words[37]; y = f2(d,e,f); g += x; c = x + y;
    x = b + f1(g,h,a) + 0x81c2c92e + words[38]; y = f2(c,d,e); f += x; b = x + y;
    x = a + f1(f,g,h) + 0x92722c85 + words[39]; y = f2(b,c,d); e += x; a = x + y;

    // extend to 48 words
    for (; i < 48; i++)
        words[i] = words[i-16] +
                (rotateRight(words[i-15],  7) ^ rotateRight(words[i-15], 18) ^ (words[i-15] >>  3)) +
                words[i-7] +
                (rotateRight(words[i- 2], 17) ^ rotateRight(words[i- 2], 19) ^ (words[i- 2] >> 10));

    // sixth round
    x = h + f1(e,f,g) + 0xa2bfe8a1 + words[40]; y = f2(a,b,c); d += x; h = x + y;
    x = g + f1(d,e,f) + 0xa81a664b + words[41]; y = f2(h,a,b); c += x; g = x + y;
    x = f + f1(c,d,e) + 0xc24b8b70 + words[42]; y = f2(g,h,a); b += x; f = x + y;
    x = e + f1(b,c,d) + 0xc76c51a3 + words[43]; y = f2(f,g,h); a += x; e = x + y;
    x = d + f1(a,b,c) + 0xd192e819 + words[44]; y = f2(e,f,g); h += x; d = x + y;
    x = c + f1(h,a,b) + 0xd6990624 + words[45]; y = f2(d,e,f); g += x; c = x + y;
    x = b + f1(g,h,a) + 0xf40e3585 + words[46]; y = f2(c,d,e); f += x; b = x + y;
    x = a + f1(f,g,h) + 0x106aa070 + words[47]; y = f2(b,c,d); e += x; a = x + y;

    // extend to 56 words
    for (; i < 56; i++)
        words[i] = words[i-16] +
                (rotateRight(words[i-15],  7) ^ rotateRight(words[i-15], 18) ^ (words[i-15] >>  3)) +
                words[i-7] +
                (rotateRight(words[i- 2], 17) ^ rotateRight(words[i- 2], 19) ^ (words[i- 2] >> 10));

    // seventh round
    x = h + f1(e,f,g) + 0x19a4c116 + words[48]; y = f2(a,b,c); d += x; h = x + y;
    x = g + f1(d,e,f) + 0x1e376c08 + words[49]; y = f2(h,a,b); c += x; g = x + y;
    x = f + f1(c,d,e) + 0x2748774c + words[50]; y = f2(g,h,a); b += x; f = x + y;
    x = e + f1(b,c,d) + 0x34b0bcb5 + words[51]; y = f2(f,g,h); a += x; e = x + y;
    x = d + f1(a,b,c) + 0x391c0cb3 + words[52]; y = f2(e,f,g); h += x; d = x + y;
    x = c + f1(h,a,b) + 0x4ed8aa4a + words[53]; y = f2(d,e,f); g += x; c = x + y;
    x = b + f1(g,h,a) + 0x5b9cca4f + words[54]; y = f2(c,d,e); f += x; b = x + y;
    x = a + f1(f,g,h) + 0x682e6ff3 + words[55]; y = f2(b,c,d); e += x; a = x + y;

    // extend to 64 words
    for (; i < 64; i++)
        words[i] = words[i-16] +
                (rotateRight(words[i-15],  7) ^ rotateRight(words[i-15], 18) ^ (words[i-15] >>  3)) +
                words[i-7] +
                (rotateRight(words[i- 2], 17) ^ rotateRight(words[i- 2], 19) ^ (words[i- 2] >> 10));

    // eigth round
    x = h + f1(e,f,g) + 0x748f82ee + words[56]; y = f2(a,b,c); d += x; h = x + y;
    x = g + f1(d,e,f) + 0x78a5636f + words[57]; y = f2(h,a,b); c += x; g = x + y;
    x = f + f1(c,d,e) + 0x84c87814 + words[58]; y = f2(g,h,a); b += x; f = x + y;
    x = e + f1(b,c,d) + 0x8cc70208 + words[59]; y = f2(f,g,h); a += x; e = x + y;
    x = d + f1(a,b,c) + 0x90befffa + words[60]; y = f2(e,f,g); h += x; d = x + y;
    x = c + f1(h,a,b) + 0xa4506ceb + words[61]; y = f2(d,e,f); g += x; c = x + y;
    x = b + f1(g,h,a) + 0xbef9a3f7 + words[62]; y = f2(c,d,e); f += x; b = x + y;
    x = a + f1(f,g,h) + 0xc67178f2 + words[63]; y = f2(b,c,d); e += x; a = x + y;

    // update hash
    m_hash[0] += a;
    m_hash[1] += b;
    m_hash[2] += c;
    m_hash[3] += d;
    m_hash[4] += e;
    m_hash[5] += f;
    m_hash[6] += g;
    m_hash[7] += h;
}

void Sha256::processBuffer()
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

} // hashing namespace
} // keeg namespace

#endif // SHA256_HPP
