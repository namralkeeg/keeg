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
#ifndef KEYEDHASHALGORITHM_HPP
#define KEYEDHASHALGORITHM_HPP

#include <keeg/hashing/hashalgorithm.hpp>
#include <algorithm>
#include <iterator>

namespace keeg { namespace hashing {

class KeyedHashAlgorithm : public HashAlgorithm
{
public:
    std::vector<uint8_t> getKey() { return m_key; }
    void setKey(const std::vector<uint8_t> &key);
    void setkey(const std::string &key);
    void setKey(const void *key, const std::size_t &length, const std::size_t index = 0);

protected:
    std::vector<uint8_t> m_key;

    KeyedHashAlgorithm();
    virtual ~KeyedHashAlgorithm();
};

void KeyedHashAlgorithm::setKey(const std::vector<uint8_t> &key)
{
    setKey(key.data(), key.size(), 0);
}

void KeyedHashAlgorithm::setkey(const std::string &key)
{
    setKey(key.data(), key.size(), 0);
}

void KeyedHashAlgorithm::setKey(const void *key, const std::size_t &length, const std::size_t index)
{
    const uint8_t *bytes = reinterpret_cast<const uint8_t*>(key) + index;
    m_key.clear();
    std::copy(bytes, bytes+length, std::back_inserter(m_key));
}

KeyedHashAlgorithm::KeyedHashAlgorithm()
{ }

KeyedHashAlgorithm::~KeyedHashAlgorithm()
{
    /// Make sure to zero out the key in memory for security.
    std::fill(std::begin(m_key), std::end(m_key), 0);
}

} // hashing namespace
} // keeg namespace

#endif // KEYEDHASHALGORITHM_HPP
