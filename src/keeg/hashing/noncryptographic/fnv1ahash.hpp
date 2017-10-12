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
#ifndef FNV1AHASH_HPP
#define FNV1AHASH_HPP

#include <keeg/hashing/noncryptographic/fnv.hpp>

namespace keeg { namespace hashing { namespace noncryptographic {

class Fnv1aHash : public FnvBase
{
public:
    Fnv1aHash(const FnvBits &bits = FnvBits::Bits32);

    // HashAlgorithm interface
protected:
    virtual void hashCore(const void *data, const std::size_t &dataLength, const std::size_t &startIndex) override;
};

Fnv1aHash::Fnv1aHash(const FnvBits &bits) : FnvBase(bits)
{ }

void Fnv1aHash::hashCore(const void *data, const size_t &dataLength, const size_t &startIndex)
{
    switch (m_bits) {
    case FnvBits::Bits32:
        calcFnv1aHash<uint32_t>(data, dataLength, startIndex, fnvPrime32, m_hash32);
        break;
    case FnvBits::Bits64:
        calcFnv1aHash<uint64_t>(data, dataLength, startIndex, fnvPrime64, m_hash64);
        break;
#if FNV_USE_BOOST == 1
    case FnvBits::Bits128:
        calcFnv1aHash<bm::uint128_t>(data, dataLength, startIndex, fnvPrime128, m_hash128);
        break;
    case FnvBits::Bits256:
        calcFnv1aHash<bm::uint256_t>(data, dataLength, startIndex, fnvPrime256, m_hash256);
        break;
    case FnvBits::Bits512:
        calcFnv1aHash<bm::uint512_t>(data, dataLength, startIndex, fnvPrime512, m_hash512);
        break;
#endif
    default:
        break;
    }
}

} // noncryptographic namespace
} // hashing namespace
} // keeg namespace

#endif // FNV1AHASH_HPP
