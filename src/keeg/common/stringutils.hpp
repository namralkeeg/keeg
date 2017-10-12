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
#ifndef STRINGUTILS_HPP
#define STRINGUTILS_HPP

#include <iomanip>
#include <iterator>
#include <locale>
#include <string>
#include <sstream>

namespace keeg { namespace common {

/**
 * Usage:
 *
 * uint8_t byte_array[] = { 0xDE, 0xAD, 0xC0, 0xDE, 0x00, 0xFF };
 * auto from_array = make_hex_string(std::begin(byte_array), std::end(byte_array), true, true);
 * assert(from_array == "DE AD C0 DE 00 FF");
 *
 * std::vector<uint8_t> byte_vector(std::begin(byte_array), std::end(byte_array));
 * auto from_vector = make_hex_string(byte_vector.begin(), byte_vector.end(), false);
 * assert(from_vector == "deadc0de00ff");
 **/
template<typename TInputIter>
std::string make_hex_string(TInputIter first, TInputIter last, bool useUppercase = true, bool insertSpaces = false)
{
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');

    if (useUppercase)
        ss << std::uppercase;

    while (first != last)
    {
        ss << std::setw(2) << static_cast<int16_t>(*first++ & 0xFF);
        if (insertSpaces && first != last)
            ss << " ";
    }

    return ss.str();
}

} // common namespace
} // keeg namespace

#endif // STRINGUTILS_HPP
