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
#ifndef HASHALGORITHM_HPP
#define HASHALGORITHM_HPP

#include <cstddef>
#include <cstdint>
#include <istream>
#include <limits>
#include <memory>
#include <string>
#include <type_traits>
#include <vector>
#include <keeg/common/stringutils.hpp>

#ifndef HASH_BLOCK_BUFFER_SIZE
    // Block of bytes to process per file read.
    // each cycle processes about 1 MByte (divisible by 144 => improves Keccak/SHA3 performance)
    #define HASH_BLOCK_BUFFER_SIZE UINT64_C(1032192) // 144 * 7 * 1024
#endif

namespace keeg { namespace hashing {

class HashAlgorithm
{
public:
    /// Size of the return hash in bits.
    virtual std::size_t hashSize() = 0;
    /// Get the hash value as vector byte array.
    std::vector<uint8_t> hashValue();

    /// Virtual destructor
    virtual ~HashAlgorithm();

    /// compute Hash of a memory block returning the hash as a byte array.
    std::vector<uint8_t> computeHash(const void* data, const std::size_t &dataLength, const std::size_t &index);
    /// compute Hash of a memory block returning the hash as a byte array.
    std::vector<uint8_t> computeHash(const void* data, const std::size_t &dataLength);
    /// Comput Hash of a stream
    std::vector<uint8_t> computeHash(std::istream &instream);

    /// Get the hash value as a hex string.
    std::string hashValueString(const bool &useUpperCase = true, const bool &insertSpaces = false);

    /// Make sure everything is setup, or reset.
    virtual void initialize() = 0;

    /// compute Hash of a memory block returning the hash as a hex string.
    std::string operator()(const void* data, const std::size_t &dataLength, const std::size_t &index);
    /// compute Hash of a memory block returning the hash as a hex string.
    std::string operator()(const void* data, const std::size_t &dataLength);
    /// compute Hash of a string, excluding final zero
    std::string operator()(const std::string &text);

protected:
    /// Computed hash value stored as a vector of bytes in Big endian order.
    /// Makes it human readable for testing.
    std::vector<uint8_t> m_hashValue;

    /// Protected ctor requires the hash size in bytes of the derived class return hash.
    HashAlgorithm(/*const size_t& hashSize*/);

    /// Interal helper combined compute hash.
    void computeHashInternal(const void* data, const std::size_t &dataLength, const std::size_t &startIndex);
    /// Interal helper combined compute hash.
    void computeHashInternal(const void* data, const std::size_t &dataLength);

    /// Hashing function that does the work. Must be implemented in the derived class.
    virtual void hashCore(const void* data, const std::size_t &dataLength, const std::size_t &startIndex) = 0;
    /// Hashing helper function that calls the function implemented in a derived class.
    void hashCore(const void* data, const std::size_t &dataLength);

    /// This is called to finalize the hash computation.
    virtual std::vector<uint8_t> hashFinal() = 0;

private:
    const std::size_t m_blockSizeBuffer = HASH_BLOCK_BUFFER_SIZE;

    static_assert(std::is_same<uint8_t, unsigned char>::value,
                  "uint8_t is required to be implemented as unsigned char!");
};

std::vector<uint8_t> HashAlgorithm::hashValue()
{
    return m_hashValue;
}

HashAlgorithm::~HashAlgorithm() { }

std::vector<uint8_t> HashAlgorithm::computeHash(const void *data, const std::size_t &dataLength, const std::size_t &index)
{
    computeHashInternal(data, dataLength, index);
    return m_hashValue;
}

std::vector<uint8_t> HashAlgorithm::computeHash(const void *data, const std::size_t &dataLength)
{
    return computeHash(data, dataLength, 0);
}

std::vector<uint8_t> HashAlgorithm::computeHash(std::istream &instream)
{
    if(!instream)
    {
        return std::move(std::vector<uint8_t>());
    }
    else
    {
        // Pointer to the filestream for the while loop.
        std::istream *input = &instream;

        // smart buffer array.
        std::unique_ptr<char[]> buffer = std::make_unique<char[]>(m_blockSizeBuffer);

        initialize();
        input->seekg(0, std::ios::beg);
        std::size_t numBytesRead = 0;
        while (*input)
        {
            input->read(buffer.get(), m_blockSizeBuffer);
            numBytesRead = static_cast<std::size_t>(input->gcount());
            hashCore(buffer.get(), numBytesRead, 0);
        }

        m_hashValue = hashFinal();
        return m_hashValue;
    }
}

std::string HashAlgorithm::hashValueString(const bool &useUpperCase, const bool &insertSpaces)
{
    return common::make_hex_string(std::begin(m_hashValue),
                                   std::end(m_hashValue), useUpperCase, insertSpaces);
}

std::string HashAlgorithm::operator()(const void *data, const std::size_t &dataLength, const std::size_t &index)
{
    computeHashInternal(data, dataLength, index);
    return hashValueString();
}

std::string HashAlgorithm::operator()(const void *data, const std::size_t &dataLength)
{
    computeHashInternal(data, dataLength, 0);
    return hashValueString();
}

std::string HashAlgorithm::operator()(const std::string &text)
{
    computeHashInternal(text.data(), text.size(), 0);
    return hashValueString();
}

HashAlgorithm::HashAlgorithm()/* :
    m_hashSize(hashSize),
    m_hashSizeBits(std::numeric_limits<uint8_t>::digits * hashSize)*/
{ }

void HashAlgorithm::computeHashInternal(const void *data, const std::size_t &dataLength, const std::size_t &startIndex)
{
    initialize();
    hashCore(data, dataLength, startIndex);
    m_hashValue = hashFinal();
}

void HashAlgorithm::computeHashInternal(const void *data, const std::size_t &dataLength)
{
    computeHashInternal(data, dataLength, 0);
}

void HashAlgorithm::hashCore(const void *data, const std::size_t &dataLength)
{
    hashCore(data, dataLength, 0);
}

} // hashing namespace
} // keeg namespace

#endif // HASHALGORITHM_HPP
