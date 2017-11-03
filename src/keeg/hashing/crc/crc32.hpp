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
 * Source is adapted from the Crc32 slicing by 16 Algorithm written by Stephan Brumme
 * Orinal source from: http://create.stephan-brumme.com/crc32/
 */

#ifndef CRC32_HPP
#define CRC32_HPP

#include <keeg/hashing/hashalgorithm.hpp>
#include <keeg/endian/conversion.hpp>
#include <array>

// zlib's CRC32 polynomial
#define ZLIB_POLYNOMIAL UINT32_C(0xEDB88320)

// If a polynomial isn't provided, default to zlib's.
#ifndef DEFAULT_POLYNOMIAL32
    #define DEFAULT_POLYNOMIAL32 ZLIB_POLYNOMIAL
#endif

#define MAX_CRC32_SLICE UINT32_C(16)

namespace keeg { namespace hashing { namespace crc {

class Crc32 : public HashAlgorithm
{
public:
    Crc32(const uint32_t &polynomial = DEFAULT_POLYNOMIAL32, const uint32_t &seed = UINT32_C(0));

    // HashAlgorithm interface
public:
    virtual std::size_t hashSize() override;
    virtual void initialize() override;

protected:
    /// compute CRC32 (Slicing-by-16 algorithm)
    virtual void hashCore(const void *data, const std::size_t &dataLength, const std::size_t &startIndex) override;

    virtual std::vector<uint8_t> hashFinal() override;

private:
    static const std::size_t MaxSlice   = MAX_CRC32_SLICE;
    static const std::size_t m_hashSize = std::numeric_limits<uint32_t>::digits;

    /// CRC32 polynomial
    uint32_t m_polynomial;
    uint32_t m_seed;
    uint32_t m_hash;
    std::array<std::array<uint32_t, 256>, MaxSlice> m_lookupTable;

    void initializeTable();

    static_assert(std::is_same<uint8_t, unsigned char>::value,
                  "uint8_t is required to be implemented as unsigned char!");
};

Crc32::Crc32(const uint32_t &polynomial, const uint32_t &seed) :
    HashAlgorithm(), m_polynomial(polynomial), m_seed(seed)
{
    initialize();
    initializeTable();
}

std::size_t Crc32::hashSize()
{
    return m_hashSize;
}

void Crc32::initialize()
{
    m_hash = m_seed;
    m_hashValue.clear();
}

void Crc32::hashCore(const void *data, const std::size_t &dataLength, const std::size_t &startIndex)
{
    uint32_t crc = ~m_hash; // same as previousCrc32 ^ 0xFFFFFFFF
    const uint8_t* currentByte = static_cast<const uint8_t*>(data) + startIndex;
    const uint32_t* current = reinterpret_cast<const uint32_t*>(currentByte);
    std::size_t numBytes = dataLength;

    // enabling optimization (at least -O2) automatically unrolls the inner for-loop
    const std::size_t Unroll = 4;
    const std::size_t BytesAtOnce = 16 * Unroll;

    // Process 64 bytes each pass.
    while (numBytes >= BytesAtOnce)
    {
      for (size_t unrolling = 0; unrolling < Unroll; unrolling++)
      {
  #if __BYTE_ORDER == __BIG_ENDIAN
          uint32_t one   = *current++ ^ swap(crc);
          uint32_t two   = *current++;
          uint32_t three = *current++;
          uint32_t four  = *current++;
          crc  = m_lookupTable[ 0][ four         & 0xFF] ^
                  m_lookupTable[ 1][(four  >>  8) & 0xFF] ^
                  m_lookupTable[ 2][(four  >> 16) & 0xFF] ^
                  m_lookupTable[ 3][(four  >> 24) & 0xFF] ^
                  m_lookupTable[ 4][ three        & 0xFF] ^
                  m_lookupTable[ 5][(three >>  8) & 0xFF] ^
                  m_lookupTable[ 6][(three >> 16) & 0xFF] ^
                  m_lookupTable[ 7][(three >> 24) & 0xFF] ^
                  m_lookupTable[ 8][ two          & 0xFF] ^
                  m_lookupTable[ 9][(two   >>  8) & 0xFF] ^
                  m_lookupTable[10][(two   >> 16) & 0xFF] ^
                  m_lookupTable[11][(two   >> 24) & 0xFF] ^
                  m_lookupTable[12][ one          & 0xFF] ^
                  m_lookupTable[13][(one   >>  8) & 0xFF] ^
                  m_lookupTable[14][(one   >> 16) & 0xFF] ^
                  m_lookupTable[15][(one   >> 24) & 0xFF];
#else
          uint32_t one   = *current++ ^ crc;
          uint32_t two   = *current++;
          uint32_t three = *current++;
          uint32_t four  = *current++;
          crc  = m_lookupTable[ 0][(four  >> 24) & 0xFF] ^
                  m_lookupTable[ 1][(four  >> 16) & 0xFF] ^
                  m_lookupTable[ 2][(four  >>  8) & 0xFF] ^
                  m_lookupTable[ 3][ four         & 0xFF] ^
                  m_lookupTable[ 4][(three >> 24) & 0xFF] ^
                  m_lookupTable[ 5][(three >> 16) & 0xFF] ^
                  m_lookupTable[ 6][(three >>  8) & 0xFF] ^
                  m_lookupTable[ 7][ three        & 0xFF] ^
                  m_lookupTable[ 8][(two   >> 24) & 0xFF] ^
                  m_lookupTable[ 9][(two   >> 16) & 0xFF] ^
                  m_lookupTable[10][(two   >>  8) & 0xFF] ^
                  m_lookupTable[11][ two          & 0xFF] ^
                  m_lookupTable[12][(one   >> 24) & 0xFF] ^
                  m_lookupTable[13][(one   >> 16) & 0xFF] ^
                  m_lookupTable[14][(one   >>  8) & 0xFF] ^
                  m_lookupTable[15][ one          & 0xFF];
#endif
      }

      numBytes -= BytesAtOnce;
      currentByte += BytesAtOnce;
    }

    // remaining 1 to 63 bytes (standard algorithm)
    while (numBytes-- != 0)
        crc = (crc >> 8) ^ m_lookupTable[0][(crc & 0xFF) ^ *currentByte++];

    m_hash = ~crc;
}

std::vector<uint8_t> Crc32::hashFinal()
{
    uint32_t data = endian::native_to_big(m_hash);
    std::vector<uint8_t> v(reinterpret_cast<uint8_t*>(&data),
                           reinterpret_cast<uint8_t*>(&data) + sizeof(uint32_t));
    return std::move(v);
}

void Crc32::initializeTable()
{
    uint32_t entry;
    for (uint32_t i = 0; i < 256; ++i)
    {
        entry = i;
        for (auto j = 0; j < 8; ++j)
        {
            entry = (entry >> 1) ^ ((entry & 1) * m_polynomial);
        }

        m_lookupTable[0][i] = entry;
    }

    for (auto i = 0; i < 256; ++i)
    {
        for (std::size_t slice = 1; slice < MaxSlice; ++slice)
        {
            m_lookupTable[slice][i] =
                    (m_lookupTable[slice - 1][i] >> 8) ^ m_lookupTable[0][m_lookupTable[slice - 1][i] & 0xFF];
        }
    }
    // slicing-by-8 algorithm (from Intel):
    // http://www.intel.com/technology/comms/perfnet/download/CRC_generators.pdf
    // http://sourceforge.net/projects/slicing-by-8/
//    for (auto i = 0; i <= 256; ++i)
//    {
//        m_lookupTable[1][i] = (m_lookupTable[0][i] >> 8) ^ m_lookupTable[0][m_lookupTable[0][i] & 0xFF];
//        m_lookupTable[2][i] = (m_lookupTable[1][i] >> 8) ^ m_lookupTable[0][m_lookupTable[1][i] & 0xFF];
//        m_lookupTable[3][i] = (m_lookupTable[2][i] >> 8) ^ m_lookupTable[0][m_lookupTable[2][i] & 0xFF];

//        m_lookupTable[4][i] = (m_lookupTable[3][i] >> 8) ^ m_lookupTable[0][m_lookupTable[3][i] & 0xFF];
//        m_lookupTable[5][i] = (m_lookupTable[4][i] >> 8) ^ m_lookupTable[0][m_lookupTable[4][i] & 0xFF];
//        m_lookupTable[6][i] = (m_lookupTable[5][i] >> 8) ^ m_lookupTable[0][m_lookupTable[5][i] & 0xFF];
//        m_lookupTable[7][i] = (m_lookupTable[6][i] >> 8) ^ m_lookupTable[0][m_lookupTable[6][i] & 0xFF];
//    }
}

} // crc namespace
} // hashing namespace
} // keeg namespace

#endif // CRC32_HPP
