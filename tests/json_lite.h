#pragma once

// A tiny JSON reader, enough for the corpus manifest (objects, arrays, strings, numbers, booleans, null).

#include <cstdlib>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace testutil {
    struct Json {
        enum class Type { Null, Bool, Number, String, Array, Object } type = Type::Null;
        bool boolean = false;
        double number = 0;
        std::string text;
        std::vector<Json> items;
        std::map<std::string, Json> members;

        bool has(const std::string &k) const { return type == Type::Object && members.count(k) > 0; }
        const Json &at(const std::string &k) const { return members.at(k); }
        std::string str(const std::string &k, const std::string &def = "") const { return has(k) ? at(k).text : def; }
        double num(const std::string &k, double def = 0) const { return has(k) ? at(k).number : def; }
        bool flag(const std::string &k, bool def = false) const { return has(k) ? at(k).boolean : def; }
    };

    class JsonParser {
    public:
        explicit JsonParser(const std::string &s) : s_(s) {}
        Json parse() { Json v = value(); skip(); if (pos_ != s_.size()) fail("trailing characters"); return v; }

    private:
        [[noreturn]] void fail(const char *m) const { throw std::runtime_error(std::string("JSON error at ") + std::to_string(pos_) + ": " + m); }
        void skip() { while (pos_ < s_.size() && std::isspace(static_cast<unsigned char>(s_[pos_]))) ++pos_; }
        char peek() { skip(); if (pos_ >= s_.size()) fail("unexpected end"); return s_[pos_]; }
        void expect(char c) { if (peek() != c) fail("unexpected character"); ++pos_; }

        std::string string() {
            expect('"');
            std::string out;
            while (pos_ < s_.size() && s_[pos_] != '"') {
                char c = s_[pos_++];
                if (c == '\\') {
                    if (pos_ >= s_.size()) fail("bad escape");
                    const char e = s_[pos_++];
                    switch (e) {
                        case 'n': out += '\n'; break;
                        case 't': out += '\t'; break;
                        case 'r': out += '\r'; break;
                        case 'u': { out += static_cast<char>(std::strtol(s_.substr(pos_, 4).c_str(), nullptr, 16)); pos_ += 4; break; }
                        default: out += e;
                    }
                } else {
                    out += c;
                }
            }
            if (pos_ >= s_.size()) fail("unterminated string");
            ++pos_;
            return out;
        }

        Json value() {
            Json v;
            const char c = peek();
            if (c == '{') {
                ++pos_; v.type = Json::Type::Object;
                if (peek() == '}') { ++pos_; return v; }
                while (true) {
                    const std::string key = string();
                    expect(':');
                    v.members[key] = value();
                    if (peek() == ',') { ++pos_; continue; }
                    expect('}');
                    return v;
                }
            }
            if (c == '[') {
                ++pos_; v.type = Json::Type::Array;
                if (peek() == ']') { ++pos_; return v; }
                while (true) {
                    v.items.push_back(value());
                    if (peek() == ',') { ++pos_; continue; }
                    expect(']');
                    return v;
                }
            }
            if (c == '"') { v.type = Json::Type::String; v.text = string(); return v; }
            if (s_.compare(pos_, 4, "true") == 0) { pos_ += 4; v.type = Json::Type::Bool; v.boolean = true; return v; }
            if (s_.compare(pos_, 5, "false") == 0) { pos_ += 5; v.type = Json::Type::Bool; return v; }
            if (s_.compare(pos_, 4, "null") == 0) { pos_ += 4; return v; }
            char *end = nullptr;
            v.number = std::strtod(s_.c_str() + pos_, &end);
            if (end == s_.c_str() + pos_) fail("unexpected token");
            pos_ = static_cast<size_t>(end - s_.c_str());
            v.type = Json::Type::Number;
            return v;
        }

        const std::string &s_;
        size_t pos_ = 0;
    };
} // namespace testutil
