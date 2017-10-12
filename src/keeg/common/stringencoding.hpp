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
#ifndef STRINGENCODING_HPP
#define STRINGENCODING_HPP

#include <exception>
#include <locale>
#include <string>
#include <boost/locale.hpp>
#include <boost/algorithm/string.hpp>

namespace keeg { namespace common {

inline std::string fromUTF8(const std::string &text, const std::string &charset)
{
    try
    {
        return boost::locale::conv::from_utf<char>(text, charset, boost::locale::conv::stop);
    }
    catch (boost::locale::conv::conversion_error &ex)
    {
        throw std::runtime_error(ex.what());
    }
}

inline std::string toUTF8(const std::string &text, const std::string &charset)
{
    try
    {
        return boost::locale::conv::to_utf<char>(text, charset, boost::locale::conv::stop);
    }
    catch (boost::locale::conv::conversion_error &ex)
    {
        throw std::runtime_error(ex.what());
    }
}

inline std::string toUTF8(const std::u16string &text)
{
    try
    {
        return boost::locale::conv::utf_to_utf<char>(text, boost::locale::conv::stop);
    }
    catch (boost::locale::conv::conversion_error &ex)
    {
        throw std::runtime_error(ex.what());
    }
}

inline std::u16string toUTF16(const std::string &text, const std::string &charset)
{
    try
    {
        return boost::locale::conv::to_utf<char16_t>(text, charset, boost::locale::conv::stop);
    }
    catch (boost::locale::conv::conversion_error &ex)
    {
        throw std::runtime_error(ex.what());
    }
}

inline std::u16string toUTF16FromUTF8(const std::string &text)
{
    try
    {
        return boost::locale::conv::utf_to_utf<char16_t>(text, boost::locale::conv::stop);
    }
    catch (boost::locale::conv::conversion_error &ex)
    {
        throw std::runtime_error(ex.what());
    }
}

inline std::string toUTF8FromLocale(const std::string &text)
{
    try
    {
        boost::locale::generator g;
        g.locale_cache_enabled(true);
        std::locale loc = g(boost::locale::util::get_system_locale());

        return boost::locale::conv::to_utf<char>(text, loc);
    }
    catch (boost::locale::conv::conversion_error &ex)
    {
        throw std::runtime_error(ex.what());
    }
}

inline std::string fromUTF8ToLocale(const std::string &text)
{
    try
    {
        boost::locale::generator g;
        g.locale_cache_enabled(true);
        std::locale loc = g(boost::locale::util::get_system_locale());

        return boost::locale::conv::from_utf<char>(text, loc);
    }
    catch (boost::locale::conv::conversion_error &ex)
    {
        throw std::runtime_error(ex.what());
    }
}

inline std::u16string toUTF16FromLocale(const std::string &text)
{
    try
    {
        boost::locale::generator g;
        g.locale_cache_enabled(true);
        std::locale loc = g(boost::locale::util::get_system_locale());

        return boost::locale::conv::to_utf<char16_t>(text, loc);
    }
    catch (boost::locale::conv::conversion_error &ex)
    {
        throw std::runtime_error(ex.what());
    }
}

inline std::string fromUTF16ToLocale(const std::u16string &text)
{
    try
    {
        boost::locale::generator g;
        g.locale_cache_enabled(true);
        std::locale loc = g(boost::locale::util::get_system_locale());

        std::string utf8string = toUTF8(text);
        return boost::locale::conv::from_utf<char>(utf8string, loc);
    }
    catch (boost::locale::conv::conversion_error &ex)
    {
        throw std::runtime_error(ex.what());
    }
}

} // common namespace
} // keeg namespace

#endif // STRINGENCODING_HPP
