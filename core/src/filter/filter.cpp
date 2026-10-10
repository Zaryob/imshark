#include "filter.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <regex>

#include "fields.h"

namespace filter {
    // ------------------------------------------------------------------------------------------------
    // Lexer
    // ------------------------------------------------------------------------------------------------
    namespace {
        enum class Tok { Word, String, LParen, RParen, LBrace, RBrace, Op, And, Or, Not, End };

        struct Token {
            Tok kind = Tok::End;
            std::string text;   // word / operator spelling / unescaped string contents
            size_t pos = 0;
        };

        struct ParseError {
            std::string message;
            size_t pos;
        };

        bool isWordChar(char c) {
            return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '.' || c == ':' || c == '/' || c == '-';
        }

        std::vector<Token> tokenize(std::string_view s) {
            std::vector<Token> out;
            size_t i = 0;
            while (i < s.size()) {
                const char c = s[i];
                if (std::isspace(static_cast<unsigned char>(c))) { ++i; continue; }
                Token t;
                t.pos = i;
                if (c == '(') { t.kind = Tok::LParen; ++i; }
                else if (c == ')') { t.kind = Tok::RParen; ++i; }
                else if (c == '{') { t.kind = Tok::LBrace; ++i; }
                else if (c == '}') { t.kind = Tok::RBrace; ++i; }
                else if (c == '&') {
                    if (i + 1 < s.size() && s[i + 1] == '&') { t.kind = Tok::And; i += 2; }
                    else throw ParseError{"Unexpected '&' (did you mean '&&'?)", i};
                } else if (c == '|') {
                    if (i + 1 < s.size() && s[i + 1] == '|') { t.kind = Tok::Or; i += 2; }
                    else throw ParseError{"Unexpected '|' (did you mean '||'?)", i};
                } else if (c == '!') {
                    if (i + 1 < s.size() && s[i + 1] == '=') { t.kind = Tok::Op; t.text = "!="; i += 2; }
                    else { t.kind = Tok::Not; ++i; }
                } else if (c == '=') {
                    if (i + 1 < s.size() && s[i + 1] == '=') { t.kind = Tok::Op; t.text = "=="; i += 2; }
                    else throw ParseError{"Unexpected '=' (did you mean '=='?)", i};
                } else if (c == '<' || c == '>') {
                    t.kind = Tok::Op;
                    t.text = std::string(1, c);
                    ++i;
                    if (i < s.size() && s[i] == '=') { t.text += '='; ++i; }
                } else if (c == '"') {
                    ++i;
                    t.kind = Tok::String;
                    bool closed = false;
                    while (i < s.size()) {
                        if (s[i] == '\\' && i + 1 < s.size()) { t.text += s[i + 1]; i += 2; continue; }
                        if (s[i] == '"') { closed = true; ++i; break; }
                        t.text += s[i++];
                    }
                    if (!closed) throw ParseError{"Unterminated string", t.pos};
                } else if (isWordChar(c)) {
                    t.kind = Tok::Word;
                    while (i < s.size() && isWordChar(s[i])) t.text += s[i++];
                } else {
                    throw ParseError{std::string("Unexpected character '") + c + "'", i};
                }
                out.push_back(std::move(t));
            }
            out.push_back(Token{Tok::End, "", s.size()});
            return out;
        }

        std::string lower(std::string s) {
            std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return s;
        }
    } // namespace

    // ------------------------------------------------------------------------------------------------
    // AST
    // ------------------------------------------------------------------------------------------------
    enum class Op { Eq, Ne, Lt, Gt, Le, Ge, Contains, Matches, In };

    struct Filter::Node {
        virtual ~Node() = default;
        virtual bool eval(const packet::PacketInfo &p, const Context &c) const = 0;
    };

    namespace {
        using NodePtr = std::shared_ptr<const Filter::Node>;

        struct OrNode : Filter::Node {
            std::vector<NodePtr> kids;
            bool eval(const packet::PacketInfo &p, const Context &c) const override {
                for (const auto &k: kids) if (k->eval(p, c)) return true;
                return false;
            }
        };

        struct AndNode : Filter::Node {
            std::vector<NodePtr> kids;
            bool eval(const packet::PacketInfo &p, const Context &c) const override {
                for (const auto &k: kids) if (!k->eval(p, c)) return false;
                return true;
            }
        };

        struct NotNode : Filter::Node {
            NodePtr kid;
            bool eval(const packet::PacketInfo &p, const Context &c) const override { return !kid->eval(p, c); }
        };

        // "field" on its own: the protocol is present / the flag is set / the field exists
        struct PresentNode : Filter::Node {
            const FieldDef *field;
            bool eval(const packet::PacketInfo &p, const Context &c) const override {
                Values v;
                field->extract(p, c, v);
                if (field->type == FieldType::Boolean) {
                    for (int i = 0; i < v.n; ++i) if (v.v[i].u != 0) return true;
                    return false;
                }
                return v.n > 0;
            }
        };

        struct URange { uint64_t lo, hi; };

        struct CompareNode : Filter::Node {
            const FieldDef *field = nullptr;
            Op op = Op::Eq;
            std::vector<URange> ranges;          // Unsigned / Boolean (Eq/Ne/In use all, ordering ops use the first)
            std::vector<double> doubles;         // Float
            std::vector<std::string> strings;    // String (Eq/Ne/In/Contains)
            std::shared_ptr<std::regex> regex;   // String, Matches
            std::vector<network::IpNetwork> nets; // addresses

            template<typename T, typename Pred>
            static bool any(const Values &v, Pred pred) {
                for (int i = 0; i < v.n; ++i) if (pred(v.v[i])) return true;
                return false;
            }

            bool matchesEq(const Values &v) const {
                switch (field->type) {
                    case FieldType::Unsigned:
                    case FieldType::Boolean:
                        return any<void>(v, [&](const Value &x) {
                            for (const auto &r: ranges) if (x.u >= r.lo && x.u <= r.hi) return true;
                            return false;
                        });
                    case FieldType::Float:
                        return any<void>(v, [&](const Value &x) { return std::find(doubles.begin(), doubles.end(), x.d) != doubles.end(); });
                    case FieldType::String:
                        return any<void>(v, [&](const Value &x) {
                            for (const auto &s: strings) if (x.s == s) return true;
                            return false;
                        });
                    case FieldType::Ipv4:
                    case FieldType::Ipv6:
                        return any<void>(v, [&](const Value &x) {
                            for (const auto &n: nets) if (n.contains(x.a)) return true;
                            return false;
                        });
                }
                return false;
            }

            bool eval(const packet::PacketInfo &p, const Context &c) const override {
                Values v;
                field->extract(p, c, v);
                switch (op) {
                    case Op::Eq:
                    case Op::In: return matchesEq(v);
                    case Op::Ne: return !matchesEq(v); // the exact negation of ==, also for absent fields
                    case Op::Lt: case Op::Gt: case Op::Le: case Op::Ge: {
                        auto cmp = [&](auto a, auto b) {
                            switch (op) {
                                case Op::Lt: return a < b;
                                case Op::Gt: return a > b;
                                case Op::Le: return a <= b;
                                default: return a >= b;
                            }
                        };
                        if (field->type == FieldType::Float) return any<void>(v, [&](const Value &x) { return cmp(x.d, doubles[0]); });
                        return any<void>(v, [&](const Value &x) { return cmp(x.u, ranges[0].lo); });
                    }
                    case Op::Contains:
                        return any<void>(v, [&](const Value &x) { return x.s.find(strings[0]) != std::string_view::npos; });
                    case Op::Matches:
                        return any<void>(v, [&](const Value &x) {
                            try {
                                return std::regex_search(x.s.data(), x.s.data() + x.s.size(), *regex);
                            } catch (const std::regex_error &) {
                                return false;   // too complex / too deep for std::regex on this input: no match, never an escaping exception
                            }
                        });
                }
                return false;
            }
        };

        // ---------------------------------------------------------------------------------------------
        // Parser
        // ---------------------------------------------------------------------------------------------
        class Parser {
        public:
            explicit Parser(std::vector<Token> tokens) : t_(std::move(tokens)) {}

            NodePtr parse() {
                if (peek().kind == Tok::End) return nullptr; // empty expression
                NodePtr n = parseOr();
                if (peek().kind != Tok::End) fail("Unexpected '" + describe(peek()) + "'", peek().pos);
                return n;
            }

        private:
            std::vector<Token> t_;
            size_t i_ = 0;

            const Token &peek() const { return t_[i_]; }
            Token next() { return t_[i_ < t_.size() - 1 ? i_++ : i_]; }
            [[noreturn]] static void fail(const std::string &m, size_t pos) { throw ParseError{m, pos}; }

            static std::string describe(const Token &t) {
                switch (t.kind) {
                    case Tok::End: return "end of expression";
                    case Tok::LParen: return "(";
                    case Tok::RParen: return ")";
                    case Tok::LBrace: return "{";
                    case Tok::RBrace: return "}";
                    case Tok::And: return "&&";
                    case Tok::Or: return "||";
                    case Tok::Not: return "!";
                    case Tok::String: return "\"" + t.text + "\"";
                    default: return t.text;
                }
            }

            bool isWord(const Token &t, const char *w) const { return t.kind == Tok::Word && lower(t.text) == w; }

            NodePtr parseOr() {
                auto first = parseAnd();
                if (!(peek().kind == Tok::Or || isWord(peek(), "or"))) return first;
                auto node = std::make_shared<OrNode>();
                node->kids.push_back(first);
                while (peek().kind == Tok::Or || isWord(peek(), "or")) { next(); node->kids.push_back(parseAnd()); }
                return node;
            }

            NodePtr parseAnd() {
                auto first = parseNot();
                if (!(peek().kind == Tok::And || isWord(peek(), "and"))) return first;
                auto node = std::make_shared<AndNode>();
                node->kids.push_back(first);
                while (peek().kind == Tok::And || isWord(peek(), "and")) { next(); node->kids.push_back(parseNot()); }
                return node;
            }

            NodePtr parseNot() {
                if (peek().kind == Tok::Not || isWord(peek(), "not")) {
                    next();
                    auto node = std::make_shared<NotNode>();
                    node->kid = parseNot();
                    return node;
                }
                return parsePrimary();
            }

            NodePtr parsePrimary() {
                const Token tok = peek();
                if (tok.kind == Tok::LParen) {
                    next();
                    auto inner = parseOr();
                    if (peek().kind != Tok::RParen) fail("Missing closing ')'", peek().pos);
                    next();
                    return inner;
                }
                if (tok.kind != Tok::Word) {
                    fail(tok.kind == Tok::End ? "Expression ends unexpectedly" : "Expected a field or protocol name, got '" + describe(tok) + "'", tok.pos);
                }
                next();
                const FieldDef *field = findField(lower(tok.text));
                if (!field) fail("Unknown field or protocol '" + tok.text + "'", tok.pos);

                // comparison operator?
                const Token &opTok = peek();
                Op op;
                bool haveOp = true;
                if (opTok.kind == Tok::Op) {
                    const std::string &s = opTok.text;
                    op = s == "==" ? Op::Eq : s == "!=" ? Op::Ne : s == "<" ? Op::Lt : s == ">" ? Op::Gt : s == "<=" ? Op::Le : Op::Ge;
                } else if (opTok.kind == Tok::Word) {
                    const std::string w = lower(opTok.text);
                    if (w == "eq") op = Op::Eq; else if (w == "ne") op = Op::Ne; else if (w == "lt") op = Op::Lt;
                    else if (w == "gt") op = Op::Gt; else if (w == "le") op = Op::Le; else if (w == "ge") op = Op::Ge;
                    else if (w == "contains") op = Op::Contains; else if (w == "matches") op = Op::Matches;
                    else if (w == "in") op = Op::In;
                    else haveOp = false;
                } else {
                    haveOp = false;
                }
                if (!haveOp) {
                    auto node = std::make_shared<PresentNode>();
                    node->field = field;
                    return node;
                }
                const size_t opPos = opTok.pos;
                next();
                return parseComparison(field, op, opPos);
            }

            NodePtr parseComparison(const FieldDef *field, Op op, size_t opPos) {
                auto node = std::make_shared<CompareNode>();
                node->field = field;
                node->op = op;
                const FieldType type = field->type;

                const bool ordering = op == Op::Lt || op == Op::Gt || op == Op::Le || op == Op::Ge;
                if (ordering && !(type == FieldType::Unsigned || type == FieldType::Float || type == FieldType::Boolean)) {
                    fail(std::string("'") + field->name + "' cannot be compared with < or >", opPos);
                }
                if ((op == Op::Contains || op == Op::Matches) && type != FieldType::String) {
                    fail(std::string("'contains' and 'matches' only work on text fields, not '") + field->name + "'", opPos);
                }

                if (op == Op::In) {
                    if (peek().kind != Tok::LBrace) fail("Expected '{' after 'in'", peek().pos);
                    next();
                    int count = 0;
                    while (peek().kind != Tok::RBrace) {
                        if (peek().kind == Tok::End) fail("Missing closing '}'", peek().pos);
                        addLiteral(*node, next(), true);
                        ++count;
                    }
                    next();
                    if (count == 0) fail("Empty set", opPos);
                    return node;
                }

                const Token value = peek();
                if (value.kind != Tok::Word && value.kind != Tok::String) {
                    fail(value.kind == Tok::End ? "Missing value after the operator" : "Expected a value, got '" + describe(value) + "'", value.pos);
                }
                next();
                addLiteral(*node, value, false);
                if (op == Op::Matches) {
                    try {
                        std::string pattern = node->strings[0];
                        auto flags = std::regex::ECMAScript;
                        if (pattern.rfind("(?i)", 0) == 0) { pattern.erase(0, 4); flags |= std::regex::icase; }
                        node->regex = std::make_shared<std::regex>(pattern, flags);
                    } catch (const std::regex_error &e) {
                        fail(std::string("Invalid regular expression: ") + e.what(), value.pos);
                    }
                }
                return node;
            }

            static bool parseUnsigned(const std::string &w, uint64_t &out) {
                if (w.empty()) return false;
                errno = 0;
                char *end = nullptr;
                const bool hex = w.size() > 2 && w[0] == '0' && (w[1] == 'x' || w[1] == 'X');
                if (!hex && !std::isdigit(static_cast<unsigned char>(w[0]))) return false;
                const unsigned long long v = std::strtoull(w.c_str(), &end, hex ? 16 : 10);
                if (errno != 0 || end != w.c_str() + w.size()) return false;
                out = v;
                return true;
            }

            void addLiteral(CompareNode &node, const Token &tok, bool inSet) {
                const FieldDef *field = node.field;
                switch (field->type) {
                    case FieldType::Unsigned:
                    case FieldType::Boolean: {
                        if (tok.kind != Tok::Word) fail("Expected a number", tok.pos);
                        const std::string w = lower(tok.text);
                        URange r{};
                        if (field->type == FieldType::Boolean && (w == "true" || w == "false")) {
                            r.lo = r.hi = (w == "true");
                        } else if (inSet && w.find("..") != std::string::npos) {
                            const auto d = w.find("..");
                            if (!parseUnsigned(w.substr(0, d), r.lo) || !parseUnsigned(w.substr(d + 2), r.hi) || r.lo > r.hi)
                                fail("Invalid range '" + tok.text + "'", tok.pos);
                        } else if (!parseUnsigned(w, r.lo)) {
                            fail("Expected a number, got '" + tok.text + "'", tok.pos);
                        } else {
                            r.hi = r.lo;
                        }
                        node.ranges.push_back(r);
                        break;
                    }
                    case FieldType::Float: {
                        if (tok.kind != Tok::Word) fail("Expected a number", tok.pos);
                        char *end = nullptr;
                        const double d = std::strtod(tok.text.c_str(), &end);
                        if (tok.text.empty() || end != tok.text.c_str() + tok.text.size() || !(std::isdigit(static_cast<unsigned char>(tok.text[0])) || tok.text[0] == '-' || tok.text[0] == '.'))
                            fail("Expected a number, got '" + tok.text + "'", tok.pos);
                        node.doubles.push_back(d);
                        break;
                    }
                    case FieldType::String:
                        if (tok.kind != Tok::String) fail("Text values must be quoted, e.g. \"" + tok.text + "\"", tok.pos);
                        node.strings.push_back(tok.text);
                        break;
                    case FieldType::Ipv4:
                    case FieldType::Ipv6: {
                        if (tok.kind != Tok::Word) fail("Expected an IP address", tok.pos);
                        const auto net = network::parseIpNetwork(tok.text);
                        if (!net) fail("'" + tok.text + "' is not a valid IP address or network", tok.pos);
                        if (net->address.v6 != (field->type == FieldType::Ipv6)) {
                            fail(field->type == FieldType::Ipv6 ? "IPv4 address used with an IPv6 field (use ip.addr)"
                                                                 : "IPv6 address used with an IPv4 field (use ipv6.addr)", tok.pos);
                        }
                        node.nets.push_back(*net);
                        break;
                    }
                }
            }
        };
    } // namespace

    // ------------------------------------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------------------------------------
    Filter::Result Filter::compile(std::string_view text) {
        Result result;
        try {
            Parser parser(tokenize(text));
            result.filter.root_ = parser.parse();
            result.ok = true;
        } catch (const ParseError &e) {
            result.ok = false;
            result.error = Error{e.message, e.pos};
        }
        return result;
    }

    bool Filter::matches(const packet::PacketInfo &packet, const Context &context) const {
        return root_ == nullptr || root_->eval(packet, context);
    }

    std::vector<FieldInfo> fieldInfos() {
        std::vector<FieldInfo> out;
        for (const auto &f: allFields()) {
            const char *type = "";
            switch (f.type) {
                case FieldType::Unsigned: type = "unsigned"; break;
                case FieldType::Boolean: type = "boolean"; break;
                case FieldType::Float: type = "float"; break;
                case FieldType::String: type = "string"; break;
                case FieldType::Ipv4: type = "IPv4 address"; break;
                case FieldType::Ipv6: type = "IPv6 address"; break;
            }
            out.push_back({f.name, type, f.description});
        }
        return out;
    }
} // namespace filter
