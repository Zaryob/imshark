#pragma once

#include <string>

namespace capture {
    /// The error text of ensurePcapLibrary() on a Windows machine without Npcap.
    inline const char *const kNpcapMissing = "Npcap is not installed. Install it from https://npcap.com and try again";

    /// Call before the first libpcap function. On Windows the Npcap DLL is delay loaded, so the program starts and
    /// opens capture files on a machine without Npcap; this loads wpcap.dll from Npcap's own directory, which is not on
    /// the DLL search path unless Npcap was installed in WinPcap API-compatible mode. False with kNpcapMissing in
    /// `error` when it cannot be loaded. On other systems libpcap is an ordinary dependency and this is always true.
    bool ensurePcapLibrary(std::string &error);
} // namespace capture
