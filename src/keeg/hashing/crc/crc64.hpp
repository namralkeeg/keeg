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

#ifndef CRC64_HPP
#define CRC64_HPP

#include <keeg/hashing/hashalgorithm.hpp>
#include <keeg/endian/conversion.hpp>
#include <array>

/// The CRC 64 ISO polynomial, defined in ISO 3309 and used in HDLC.
#define CRC_64_ISO_POLYNOMIAL UINT64_C(0xD800000000000000)

/// The ECMA polynomial, defined in ECMA 182.
#define ECMA_182_POLYNOMIAL UINT64_C(0xC96C5795D7870F42)

#define JONES_POLYNOMIAL UINT64_C(0xad93d23594c935a9)

// If a polynomial isn't provided, default to zlib's.
#ifndef DEFAULT_POLYNOMIAL64
    #define DEFAULT_POLYNOMIAL64 ECMA_182_POLYNOMIAL
#endif

#define MAX_CRC64_SLICE UINT64_C(16)

namespace keeg { namespace hashing { namespace crc {

class Crc64 : public HashAlgorithm
{
public:
    Crc64(const uint64_t &polynomial = DEFAULT_POLYNOMIAL64, const uint64_t &seed = UINT64_C(0));

    // HashAlgorithm interface
public:
    virtual std::size_t hashSize() override;
    virtual void initialize() override;

protected:
    /// compute CRC64 (Slicing-by-16 algorithm)
    virtual void hashCore(const void *data, const std::size_t &dataLength, const std::size_t &startIndex) override;
    virtual std::vector<uint8_t> hashFinal() override;

private:
    static const std::size_t MaxSlice   = MAX_CRC64_SLICE;
    static const std::size_t m_hashSize = std::numeric_limits<uint64_t>::digits;

    /// CRC64 Polynomial
    uint64_t m_polynomial;
    uint64_t m_seed;
    uint64_t m_hash;
//    uint64_t m_lookupTable[MaxSlice][256] = {{0}};
    std::array<std::array<uint64_t, 256>, MaxSlice> m_lookupTable;

    void initializeTable();
};

Crc64::Crc64(const uint64_t &polynomial, const uint64_t &seed) :
    HashAlgorithm(), m_polynomial(polynomial), m_seed(seed)
{
    initialize();
    initializeTable();
}

std::size_t Crc64::hashSize()
{
    return m_hashSize;
}

void Crc64::initialize()
{
    m_hash = m_seed;
    m_hashValue.clear();
}

void Crc64::hashCore(const void *data, const size_t &dataLength, const size_t &startIndex)
{
    uint64_t crc = ~m_hash; /// same as previousCrc64 ^ 0xFFFFFFFFFFFFFFFF
    const uint8_t* currentByte = static_cast<const uint8_t*>(data) + startIndex;
    const uint64_t* current = reinterpret_cast<const uint64_t*>(currentByte);
    std::size_t numBytes = dataLength;

    /// enabling optimization (at least -O2) automatically unrolls the inner for-loop
    const std::size_t Unroll = 4;
    const std::size_t BytesAtOnce = 16 * Unroll;

    /// Process 64 bytes each pass.
    while (numBytes >= BytesAtOnce)
    {
      for (std::size_t unrolling = 0; unrolling < Unroll; unrolling++)
      {
  #if __BYTE_ORDER == __BIG_ENDIAN
          uint64_t one   = *current++ ^ swap(crc);
          uint64_t two   = *current++;
          crc  = m_lookupTable[ 0][ two          & 0xFF] ^
                  m_lookupTable[ 1][(two   >>  8) & 0xFF] ^
                  m_lookupTable[ 2][(two   >> 16) & 0xFF] ^
                  m_lookupTable[ 3][(two   >> 24) & 0xFF] ^
                  m_lookupTable[ 4][(two   >> 32) & 0xFF] ^
                  m_lookupTable[ 5][(two   >> 40) & 0xFF] ^
                  m_lookupTable[ 6][(two   >> 48) & 0xFF] ^
                  m_lookupTable[ 7][(two   >> 56) & 0xFF] ^
                  m_lookupTable[ 8][ one          & 0xFF] ^
                  m_lookupTable[ 9][(one   >>  8) & 0xFF] ^
                  m_lookupTable[10][(one   >> 16) & 0xFF] ^
                  m_lookupTable[11][(one   >> 24) & 0xFF] ^
                  m_lookupTable[12][(one   >> 32  & 0xFF] ^
                                     m_lookupTable[13][(one   >> 40) & 0xFF] ^
                  m_lookupTable[14][(one   >> 48) & 0xFF] ^
                  m_lookupTable[15][(one   >> 56) & 0xFF];
#else
          uint64_t one   = *current++ ^ crc;
          uint64_t two   = *current++;

          crc  = m_lookupTable[ 0][(two   >> 56) & 0xFF] ^
                  m_lookupTable[ 1][(two   >> 48) & 0xFF] ^
                  m_lookupTable[ 2][(two   >> 40) & 0xFF] ^
                  m_lookupTable[ 3][(two   >> 32) & 0xFF] ^
                  m_lookupTable[ 4][(two   >> 24) & 0xFF] ^
                  m_lookupTable[ 5][(two   >> 16) & 0xFF] ^
                  m_lookupTable[ 6][(two   >>  8) & 0xFF] ^
                  m_lookupTable[ 7][ two          & 0xFF] ^
                  m_lookupTable[ 8][(one   >> 56) & 0xFF] ^
                  m_lookupTable[ 9][(one   >> 48) & 0xFF] ^
                  m_lookupTable[10][(one   >> 40) & 0xFF] ^
                  m_lookupTable[11][(one   >> 32) & 0xFF] ^
                  m_lookupTable[12][(one   >> 24) & 0xFF] ^
                  m_lookupTable[13][(one   >> 16) & 0xFF] ^
                  m_lookupTable[14][(one   >>  8) & 0xFF] ^
                  m_lookupTable[15][ one          & 0xFF];
#endif
      }

      numBytes -= BytesAtOnce;
      currentByte += BytesAtOnce;
    }

    /// remaining 1 to 63 bytes (standard algorithm)
    while (numBytes-- != 0)
        crc = (crc >> 8) ^ m_lookupTable[0][(crc & 0xFF) ^ *currentByte++];

    m_hash = ~crc;
}

std::vector<uint8_t> Crc64::hashFinal()
{
    uint64_t data = endian::native_to_big(m_hash);
    std::vector<uint8_t> v(reinterpret_cast<uint8_t*>(&data),
                           reinterpret_cast<uint8_t*>(&data) + sizeof(uint64_t));
    return std::move(v);
}

void Crc64::initializeTable()
{
    uint64_t entry;
    for (uint64_t i = 0; i < 256; ++i)
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

#endif // CRC64_HPP
