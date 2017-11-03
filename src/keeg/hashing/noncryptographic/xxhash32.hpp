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
#ifndef XXHASH32_HPP
#define XXHASH32_HPP

#include <keeg/hashing/hashalgorithm.hpp>
#include <keeg/endian/conversion.hpp>
#include <algorithm>
#include <array>

namespace keeg { namespace hashing { namespace noncryptographic {

class XxHash32 : public HashAlgorithm
{
public:
    XxHash32(const uint32_t &seed = 0);

    // HashAlgorithm interface
public:
    virtual std::size_t hashSize() override;
    virtual void initialize() override;

protected:
    virtual void hashCore(const void *data, const std::size_t &dataLength, const std::size_t &startIndex) override;
    virtual std::vector<uint8_t> hashFinal() override;

private:
    static const std::size_t m_hashSize = std::numeric_limits<uint32_t>::digits;

    /// magic constants :-)
    static const uint32_t Prime1 = UINT32_C(2654435761);
    static const uint32_t Prime2 = UINT32_C(2246822519);
    static const uint32_t Prime3 = UINT32_C(3266489917);
    static const uint32_t Prime4 =  UINT32_C(668265263);
    static const uint32_t Prime5 =  UINT32_C(374761393);

    /// temporarily store up to 15 bytes between multiple add() calls
    static const uint32_t MaxBufferSize = 15+1;

    // internal state and temporary buffer
    std::array<uint32_t, 4> m_state; // state[2] == seed if totalLength < MaxBufferSize
    std::array<uint8_t, MaxBufferSize> m_buffer;
    uint32_t  m_bufferSize;
    uint64_t  m_totalLength;
    uint32_t  m_seed;

    /// process a block of 4x4 bytes, this is the main part of the XXHash32 algorithm
    void process(const void* data, uint32_t &state0, uint32_t &state1, uint32_t &state2, uint32_t &state3);

    static_assert(std::is_same<uint8_t, unsigned char>::value,
                  "uint8_t is required to be implemented as unsigned char!");
};

#define rotateLeft(x,y) keeg::endian::rotateLeft((x),(y))

XxHash32::XxHash32(const uint32_t &seed) : HashAlgorithm(), m_seed(seed)
{
    initialize();
}

size_t XxHash32::hashSize()
{
    return m_hashSize;
}

void XxHash32::initialize()
{
    m_state[0] = m_seed + Prime1 + Prime2;
    m_state[1] = m_seed + Prime2;
    m_state[2] = m_seed;
    m_state[3] = m_seed - Prime1;
    m_bufferSize  = 0;
    m_totalLength = 0;
    m_hashValue.clear();
    std::fill(std::begin(m_buffer), std::end(m_buffer), 0);
}

void XxHash32::hashCore(const void *data, const size_t &dataLength, const size_t &startIndex)
{
    // byte-wise access
    const uint8_t* current = static_cast<const uint8_t*>(data) + startIndex;

    uint64_t length = dataLength;
    m_totalLength += length;
    //const unsigned char* data = (const unsigned char*)input;

    // unprocessed old data plus new data still fit in temporary buffer ?
    if (m_bufferSize + length < MaxBufferSize)
    {
        // just add new data
        while (length-- > 0)
            m_buffer[m_bufferSize++] = *current++;
    }
    else
    {
        // point beyond last byte
        const uint8_t* stop      = current + length;
        const uint8_t* stopBlock = stop - MaxBufferSize;

        // some data left from previous update ?
        if (m_bufferSize > 0)
        {
            // make sure temporary buffer is full (16 bytes)
            while (m_bufferSize < MaxBufferSize)
                m_buffer[m_bufferSize++] = *current++;

            // process these 16 bytes (4x4)
            process(m_buffer.data(), m_state[0], m_state[1], m_state[2], m_state[3]);
        }

        // copying state to local variables helps optimizer A LOT
        uint32_t s0 = m_state[0], s1 = m_state[1], s2 = m_state[2], s3 = m_state[3];

        // 16 bytes at once
        while (current <= stopBlock)
        {
            // local variables s0..s3 instead of state[0]..state[3] are much faster
            process(current, s0, s1, s2, s3);
            current += 16;
        }

        // copy back
        m_state[0] = s0; m_state[1] = s1; m_state[2] = s2; m_state[3] = s3;

        // copy remainder to temporary buffer
        m_bufferSize = static_cast<uint32_t>(stop - current);
        std::copy(current, current + m_bufferSize, std::begin(m_buffer));
    }
}

std::vector<uint8_t> XxHash32::hashFinal()
{
    uint32_t result = static_cast<uint32_t>(m_totalLength);

     // fold 128 bit state into one single 32 bit value
     if (m_totalLength >= MaxBufferSize)
     {
         result += rotateLeft(m_state[0],  1) +
                   rotateLeft(m_state[1],  7) +
                   rotateLeft(m_state[2], 12) +
                   rotateLeft(m_state[3], 18);
     }
     else
     {
         // internal state wasn't set in add(), therefore original seed is still stored in state2
         result += m_state[2] + Prime5;
     }

     // process remaining bytes in temporary buffer
     const uint8_t* data = m_buffer.data();
     // point beyond last byte
     const uint8_t* stop = data + m_bufferSize;

     // at least 4 bytes left ? => eat 4 bytes per step
     for (; data + 4 <= stop; data += 4)
         result = rotateLeft(result + GET32BITS(data) * Prime3, 17) * Prime4;

     // take care of remaining 0..3 bytes, eat 1 byte per step
     while (data != stop)
         result = rotateLeft(result + (*data++) * Prime5, 11) * Prime1;

     // mix bits
     result ^= result >> 15;
     result *= Prime2;
     result ^= result >> 13;
     result *= Prime3;
     result ^= result >> 16;

     result = endian::native_to_big(result);

     return std::move(std::vector<uint8_t>(reinterpret_cast<uint8_t*>(&result),
                                           reinterpret_cast<uint8_t*>(&result) + sizeof(uint32_t)));
}

void XxHash32::process(const void *data, uint32_t &state0, uint32_t &state1, uint32_t &state2, uint32_t &state3)
{
    const uint32_t* block = static_cast<const uint32_t*>(data);

    state0 = rotateLeft(state0 + block[0] * Prime2, 13) * Prime1;
    state1 = rotateLeft(state1 + block[1] * Prime2, 13) * Prime1;
    state2 = rotateLeft(state2 + block[2] * Prime2, 13) * Prime1;
    state3 = rotateLeft(state3 + block[3] * Prime2, 13) * Prime1;
}

} // noncryptographic namespace
} // hashing namespace
} // keeg namespace

#endif // XXHASH32_HPP
