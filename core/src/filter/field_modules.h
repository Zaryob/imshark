#pragma once

// The per-protocol filter field modules. Each is defined in core/src/dissect/<protocol>_fields.cpp, next to the
// dissector whose summary facts its extractors read, and adds that protocol's fields to the registry.

#include <filter/fields.h>

namespace filter {
    /// Registers every module below, in one explicit list (see field_modules.cpp). The only caller is the code that
    /// builds the built-in table; tests may call it on a registry of their own.
    void registerBuiltinFields(FieldRegistry &registry);
} // namespace filter
