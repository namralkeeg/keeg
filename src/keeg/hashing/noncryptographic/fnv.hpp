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
#ifndef FNV_HPP
#define FNV_HPP

#include <keeg/hashing/hashalgorithm.hpp>
#include <keeg/common/enums.hpp>
#include <keeg/endian/conversion.hpp>
#include <algorithm>
#include <iterator>

#ifndef FNV_USE_BOOST
    #define FNV_USE_BOOST 0
#endif

#if FNV_USE_BOOST == 1
    #include <boost/multiprecision/cpp_int.hpp>
#endif

#if FNV_USE_BOOST == 1
    namespace bm = boost::multiprecision;
#endif

namespace keeg { namespace hashing { namespace noncryptographic {

template<typename T>
void calcFnv1Hash(const void* data, std::size_t dataLength, const std::size_t &startIndex,
                  T fnvPrime, T &hashValue)
{
    static_assert(std::is_same<uint8_t, unsigned char>::value,
                  "uint8_t is required to be implemented as unsigned char!");

    const uint8_t *current = static_cast<const uint8_t*>(data) + startIndex;

    for (std::size_t i = 0; i < dataLength; ++current, ++i)
    {
        hashValue = (fnvPrime * hashValue) ^ *current;
    }
}

template<typename T>
void calcFnv1aHash(const void* data, std::size_t dataLength, const std::size_t &startIndex,
                   T fnvPrime, T &hashValue)
{
    static_assert(std::is_same<uint8_t, unsigned char>::value,
                  "uint8_t is required to be implemented as unsigned char!");

    const uint8_t *current = static_cast<const uint8_t*>(data) + startIndex;

    for (std::size_t i = 0; i < dataLength; ++current, ++i)
    {
        hashValue = (*current ^ hashValue) * fnvPrime;
    }
}

enum class FnvBits : uint16_t
{
    Bits32  =  32,
    Bits64  =  64,
#if FNV_USE_BOOST == 1
    Bits128 = 128,
    Bits256 = 256,
    Bits512 = 512
#endif
};

class FnvBase : public HashAlgorithm
{
public:
    static const uint32_t fnvPrime32 = UINT32_C(16777619);
    static const uint32_t offsetBasis32 = UINT32_C(2166136261);
    static const uint64_t fnvPrime64 = UINT64_C(1099511628211);
    static const uint64_t offsetBasis64 = UINT64_C(14695981039346656037);
#if FNV_USE_BOOST == 1
    const bm::uint128_t fnvPrime128 = bm::uint128_t("0x1000000000000000000013B");
    const bm::uint128_t offsetBasis128 = bm::uint128_t("0x1000000000000000000013B");
    const bm::uint256_t fnvPrime256 = bm::uint256_t("0x1000000000000000000000000000000000000000163");
    const bm::uint256_t offsetBasis256 = bm::uint256_t("0xDD268DBCAAC550362D98C384C4E576CCC8B1536847B6BBB31023B4C8CAEE0535");
    const bm::uint512_t fnvPrime512 = bm::uint512_t("0x100000000000000000000000000000000000000000000000000000000000000000000000000000000000157");
    const bm::uint512_t offsetBasis512 = bm::uint512_t("0xB86DB0B1171F4416DCA1E50F309990ACAC87D059C90000000000000000000D21E948F68A34C192F62EA79BC942DBE7CE182036415F56E34BAC982AAC4AFE9FD9");
#endif

    FnvBase(const FnvBits &bits = FnvBits::Bits32);

    // HashAlgorithm interface
public:
    virtual std::size_t hashSize() override;

    virtual void initialize() override;

protected:
    virtual void hashCore(const void *data, const std::size_t &dataLength, const std::size_t &startIndex) = 0;

    virtual std::vector<uint8_t> hashFinal() override;

protected:
    FnvBits m_bits;
    uint32_t m_hash32;
    uint64_t m_hash64;
#if FNV_USE_BOOST == 1
    bm::uint128_t m_hash128;
    bm::uint256_t m_hash256;
    bm::uint512_t m_hash512;
#endif
};

FnvBase::FnvBase(const FnvBits &bits) : HashAlgorithm(), m_bits(bits)
{
    initialize();
}

size_t FnvBase::hashSize()
{
    return static_cast<std::size_t>(common::enumToIntegral<FnvBits>(m_bits));
}

void FnvBase::initialize()
{
    m_hashValue.clear();

    switch (m_bits) {
    case FnvBits::Bits32:
        m_hash32 = offsetBasis32;
        break;
    case FnvBits::Bits64:
        m_hash64 = offsetBasis64;
        break;
#if FNV_USE_BOOST == 1
    case FnvBits::Bits128:
        m_hash128 = offsetBasis128;
        break;
    case FnvBits::Bits256:
        m_hash256 = offsetBasis256;
        break;
    case FnvBits::Bits512:
        m_hash512 = offsetBasis512;
        break;
#endif
    default:
        break;
    }
}

std::vector<uint8_t> FnvBase::hashFinal()
{
    const std::size_t byteSize = hashSize() / std::numeric_limits<uint8_t>::digits;
    std::vector<uint8_t> v(byteSize);

    switch (m_bits) {
    case FnvBits::Bits32:
    {
        uint32_t data32 = endian::native_to_big(m_hash32);
        std::copy(reinterpret_cast<uint8_t*>(&data32),
                  reinterpret_cast<uint8_t*>(&data32) + byteSize, std::begin(v));
    }
        break;
    case FnvBits::Bits64:
    {
        uint64_t data64 = endian::native_to_big(m_hash64);
        std::copy(reinterpret_cast<uint8_t*>(&data64),
                  reinterpret_cast<uint8_t*>(&data64) + byteSize, std::begin(v));
    }
        break;
#if FNV_USE_BOOST == 1
    case FnvBits::Bits128:
        bm::export_bits(m_hash128, &v[0], 8, true);
        break;
    case FnvBits::Bits256:
        bm::export_bits(m_hash256, &v[0], 8, true);
        break;
    case FnvBits::Bits512:
        bm::export_bits(m_hash512, &v[0], 8, true);
        break;
#endif
    default:
        break;
    }

    return std::move(v);
}

} // noncryptographic namespace
} // hashing namespace
} // keeg namespace

#endif // FNV_HPP
