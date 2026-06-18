#include "fields.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <mutex>

#include "field_modules.h"

namespace filter {
    namespace {
        // The built-in table: every field module, registered once. Built on first use (before any filter is compiled and
        // before any packet is dissected) and never changed afterwards, so findField() pointers into it stay valid for the
        // life of the process. registerField() is for fields added later (plugins, tests): it keeps them in a deque,
        // whose elements never move, behind a mutex, and never touches the built table.
        const std::vector<FieldDef> &baseTable() {
            static const std::vector<FieldDef> table = [] {
                FieldRegistry registry;
                registerBuiltinFields(registry);
                if (!registry.problems().empty()) {
                    for (const auto &problem: registry.problems()) std::fprintf(stderr, "imshark: filter field table: %s\n", problem.c_str());
                    std::abort();
                }
                return registry.sorted();
            }();
            return table;
        }

        std::mutex &customMutex() {
            static std::mutex m;
            return m;
        }

        std::deque<FieldDef> &customFields() {
            static std::deque<FieldDef> list;
            return list;
        }

        const FieldDef *findBase(std::string_view lowerName) {
            const auto &t = baseTable();
            const auto it = std::lower_bound(t.begin(), t.end(), lowerName,
                                             [](const FieldDef &f, std::string_view n) { return std::string_view(f.name) < n; });
            return (it != t.end() && std::string_view(it->name) == lowerName) ? &*it : nullptr;
        }
    } // namespace

    bool FieldRegistry::add(const FieldDef &field) {
        if (field.name == nullptr || *field.name == '\0' || field.extract == nullptr) {
            problems_.push_back(std::string("incomplete field definition: ") + (field.name ? field.name : "(no name)"));
            return false;
        }
        for (const auto &f: fields_) {
            if (std::string_view(f.name) == field.name) {
                problems_.push_back(std::string("duplicate field name: ") + field.name);
                return false;
            }
        }
        fields_.push_back(field);
        return true;
    }

    std::vector<FieldDef> FieldRegistry::sorted() const {
        std::vector<FieldDef> out = fields_;
        std::sort(out.begin(), out.end(), [](const FieldDef &a, const FieldDef &b) { return std::string_view(a.name) < b.name; });
        return out;
    }

    void initFields() { baseTable(); }

    std::vector<FieldDef> allFields() {
        std::vector<FieldDef> all = baseTable();
        {
            std::lock_guard<std::mutex> lock(customMutex());
            all.insert(all.end(), customFields().begin(), customFields().end());
        }
        std::sort(all.begin(), all.end(), [](const FieldDef &a, const FieldDef &b) { return std::string_view(a.name) < b.name; });
        return all;
    }

    std::vector<FieldDef> builtinFields() { return baseTable(); }

    bool registerField(FieldDef field) {
        if (field.name == nullptr || *field.name == '\0' || field.extract == nullptr) return false;
        const std::string_view name = field.name;
        if (findBase(name) != nullptr) return false;
        std::lock_guard<std::mutex> lock(customMutex());
        for (const auto &f: customFields()) {
            if (std::string_view(f.name) == name) return false;
        }
        customFields().push_back(field);
        return true;
    }

    const FieldDef *findField(std::string_view lowerName) {
        if (const FieldDef *f = findBase(lowerName)) return f;
        std::lock_guard<std::mutex> lock(customMutex());
        for (const auto &f: customFields()) {
            if (std::string_view(f.name) == lowerName) return &f;
        }
        return nullptr;
    }
} // namespace filter
