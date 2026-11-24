#include "AtomicHotUpdater.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>
#include <thread>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

namespace gclient {
namespace update {

namespace fs = std::filesystem;

namespace {

// ============================================================================
// Pure C++17 SHA-256 and MD5 fallbacks (used on non-Windows hosts / tests;
// Win32 builds use native CNG BCrypt* APIs with zero external dependencies).
// ============================================================================
#ifndef _WIN32

class Sha256Context {
public:
    Sha256Context() { reset(); }

    void reset() {
        m_state = {
            0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
            0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
        };
        m_bitLen = 0;
        m_bufLen = 0;
    }

    void update(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            m_buf[m_bufLen++] = data[i];
            if (m_bufLen == 64) {
                transform(m_buf.data());
                m_bitLen += 512;
                m_bufLen = 0;
            }
        }
    }

    std::array<uint8_t, 32> finalize() {
        uint64_t totalBits = m_bitLen + static_cast<uint64_t>(m_bufLen) * 8u;
        m_buf[m_bufLen++] = 0x80u;
        if (m_bufLen > 56) {
            while (m_bufLen < 64) m_buf[m_bufLen++] = 0x00u;
            transform(m_buf.data());
            m_bufLen = 0;
        }
        while (m_bufLen < 56) m_buf[m_bufLen++] = 0x00u;
        for (int i = 7; i >= 0; --i) {
            m_buf[m_bufLen++] = static_cast<uint8_t>((totalBits >> (i * 8)) & 0xFFu);
        }
        transform(m_buf.data());

        std::array<uint8_t, 32> digest{};
        for (size_t i = 0; i < 8; ++i) {
            digest[i * 4 + 0] = static_cast<uint8_t>((m_state[i] >> 24) & 0xFFu);
            digest[i * 4 + 1] = static_cast<uint8_t>((m_state[i] >> 16) & 0xFFu);
            digest[i * 4 + 2] = static_cast<uint8_t>((m_state[i] >> 8) & 0xFFu);
            digest[i * 4 + 3] = static_cast<uint8_t>(m_state[i] & 0xFFu);
        }
        return digest;
    }

private:
    static inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32u - n)); }

    void transform(const uint8_t block[64]) {
        static constexpr uint32_t k[64] = {
            0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
            0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
            0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
            0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
            0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
            0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
            0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
            0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
            0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
            0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
            0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
            0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
            0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
            0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
            0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
            0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
        };

        uint32_t w[64];
        for (size_t i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(block[i * 4 + 0]) << 24) |
                   (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
                   static_cast<uint32_t>(block[i * 4 + 3]);
        }
        for (size_t i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = m_state[0], b = m_state[1], c = m_state[2], d = m_state[3];
        uint32_t e = m_state[4], f = m_state[5], g = m_state[6], h = m_state[7];
        for (size_t i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + S1 + ch + k[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g; g = f; f = e; e = d + temp1;
            d = c; c = b; b = a; a = temp1 + temp2;
        }

        m_state[0] += a; m_state[1] += b; m_state[2] += c; m_state[3] += d;
        m_state[4] += e; m_state[5] += f; m_state[6] += g; m_state[7] += h;
    }

    std::array<uint32_t, 8> m_state{};
    std::array<uint8_t, 64> m_buf{};
    uint64_t m_bitLen = 0;
    size_t m_bufLen = 0;
};

class Md5Context {
public:
    Md5Context() { reset(); }

    void reset() {
        m_state = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u};
        m_bitLen = 0;
        m_bufLen = 0;
    }

    void update(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            m_buf[m_bufLen++] = data[i];
            if (m_bufLen == 64) {
                transform(m_buf.data());
                m_bitLen += 512;
                m_bufLen = 0;
            }
        }
    }

    std::array<uint8_t, 16> finalize() {
        uint64_t totalBits = m_bitLen + static_cast<uint64_t>(m_bufLen) * 8u;
        m_buf[m_bufLen++] = 0x80u;
        if (m_bufLen > 56) {
            while (m_bufLen < 64) m_buf[m_bufLen++] = 0x00u;
            transform(m_buf.data());
            m_bufLen = 0;
        }
        while (m_bufLen < 56) m_buf[m_bufLen++] = 0x00u;
        for (int i = 0; i < 8; ++i) {
            m_buf[m_bufLen++] = static_cast<uint8_t>((totalBits >> (i * 8)) & 0xFFu);
        }
        transform(m_buf.data());

        std::array<uint8_t, 16> digest{};
        for (size_t i = 0; i < 4; ++i) {
            digest[i * 4 + 0] = static_cast<uint8_t>(m_state[i] & 0xFFu);
            digest[i * 4 + 1] = static_cast<uint8_t>((m_state[i] >> 8) & 0xFFu);
            digest[i * 4 + 2] = static_cast<uint8_t>((m_state[i] >> 16) & 0xFFu);
            digest[i * 4 + 3] = static_cast<uint8_t>((m_state[i] >> 24) & 0xFFu);
        }
        return digest;
    }

private:
    static inline uint32_t rotl(uint32_t x, uint32_t n) { return (x << n) | (x >> (32u - n)); }

    void transform(const uint8_t block[64]) {
        static constexpr uint32_t s[64] = {
            7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
            5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
            4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
            6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
        };
        static constexpr uint32_t k[64] = {
            0xd76aa478u,0xe8c7b756u,0x242070dbu,0xc1bdceeeu,
            0xf57c0fafu,0x4787c62au,0xa8304613u,0xfd469501u,
            0x698098d8u,0x8b44f7afu,0xffff5bb1u,0x895cd7beu,
            0x6b901122u,0xfd987193u,0xa679438eu,0x49b40821u,
            0xf61e2562u,0xc040b340u,0x265e5a51u,0xe9b6c7aau,
            0xd62f105du,0x02441453u,0xd8a1e681u,0xe7d3fbc8u,
            0x21e1cde6u,0xc33707d6u,0xf4d50d87u,0x455a14edu,
            0xa9e3e905u,0xfcefa3f8u,0x676f02d9u,0x8d2a4c8au,
            0xfffa3942u,0x8771f681u,0x6d9d6122u,0xfde5380cu,
            0xa4beea44u,0x4bdecfa9u,0xf6bb4b60u,0xbebfbc70u,
            0x289b7ec6u,0xeaa127fau,0xd4ef3085u,0x04881d05u,
            0xd9d4d039u,0xe6db99e5u,0x1fa27cf8u,0xc4ac5665u,
            0xf4292244u,0x432aff97u,0xab9423a7u,0xfc93a039u,
            0x655b59c3u,0x8f0ccc92u,0xffeff47du,0x85845dd1u,
            0x6fa87e4fu,0xfe2ce6e0u,0xa3014314u,0x4e0811a1u,
            0xf7537e82u,0xbd3af235u,0x2ad7d2bbu,0xeb86d391u
        };

        uint32_t m[16];
        for (size_t i = 0; i < 16; ++i) {
            m[i] = static_cast<uint32_t>(block[i * 4 + 0]) |
                   (static_cast<uint32_t>(block[i * 4 + 1]) << 8) |
                   (static_cast<uint32_t>(block[i * 4 + 2]) << 16) |
                   (static_cast<uint32_t>(block[i * 4 + 3]) << 24);
        }

        uint32_t a = m_state[0], b = m_state[1], c = m_state[2], d = m_state[3];
        for (size_t i = 0; i < 64; ++i) {
            uint32_t f = 0;
            size_t g = 0;
            if (i < 16) {
                f = (b & c) | ((~b) & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | ((~d) & c);
                g = (5 * i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3 * i + 5) % 16;
            } else {
                f = c ^ (b | (~d));
                g = (7 * i) % 16;
            }
            uint32_t temp = d;
            d = c;
            c = b;
            b = b + rotl(a + f + k[i] + m[g], s[i]);
            a = temp;
        }
        m_state[0] += a; m_state[1] += b; m_state[2] += c; m_state[3] += d;
    }

    std::array<uint32_t, 4> m_state{};
    std::array<uint8_t, 64> m_buf{};
    uint64_t m_bitLen = 0;
    size_t m_bufLen = 0;
};

#endif // !_WIN32

// ============================================================================
// Minimal JSON helpers for active_manifest.json (zero third-party deps)
// ============================================================================

std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:   out.push_back(c); break;
        }
    }
    return out;
}

bool extractJsonString(const std::string& json, const std::string& key, std::string& out) {
    const std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return false;
    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) return false;
    pos = json.find('"', pos + 1);
    if (pos == std::string::npos) return false;
    ++pos;

    std::string result;
    while (pos < json.size()) {
        char c = json[pos++];
        if (c == '\\' && pos < json.size()) {
            char next = json[pos++];
            switch (next) {
                case '"':  result.push_back('"'); break;
                case '\\': result.push_back('\\'); break;
                case 'n':  result.push_back('\n'); break;
                case 'r':  result.push_back('\r'); break;
                case 't':  result.push_back('\t'); break;
                default:   result.push_back(next); break;
            }
        } else if (c == '"') {
            out = std::move(result);
            return true;
        } else {
            result.push_back(c);
        }
    }
    return false;
}

bool extractJsonUint32(const std::string& json, const std::string& key, uint32_t& out) {
    const std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return false;
    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) return false;
    ++pos;
    while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos]))) ++pos;
    if (pos >= json.size() || !std::isdigit(static_cast<unsigned char>(json[pos]))) return false;

    uint64_t val = 0;
    while (pos < json.size() && std::isdigit(static_cast<unsigned char>(json[pos]))) {
        val = val * 10u + static_cast<uint64_t>(json[pos++] - '0');
        if (val > 0xFFFFFFFFull) return false;
    }
    out = static_cast<uint32_t>(val);
    return true;
}

std::string bootStateToString(BootState state) {
    switch (state) {
        case BootState::Confirmed:           return "confirmed";
        case BootState::PendingVerification: return "pending_verification";
        case BootState::RolledBack:          return "rolled_back";
    }
    return "confirmed";
}

BootState stringToBootState(const std::string& s) {
    if (s == "pending_verification") return BootState::PendingVerification;
    if (s == "rolled_back") return BootState::RolledBack;
    return BootState::Confirmed;
}

uint64_t fnv1a64(const std::string& input) {
    uint64_t hash = 14695981039346656037ull;
    for (unsigned char c : input) {
        hash ^= c;
        hash *= 1099511628211ull;
    }
    return hash;
}

} // namespace

// ============================================================================
// CrossProcessLock
// ============================================================================

AtomicHotUpdater::CrossProcessLock::CrossProcessLock(const fs::path& patchRoot)
    : m_lockFilePath(patchRoot / "update.lock") {
    std::ostringstream oss;
    oss << "Local\\GCLIENT_HotUpdate_" << std::hex << fnv1a64(patchRoot.string());
    m_mutexName = oss.str();
}

AtomicHotUpdater::CrossProcessLock::~CrossProcessLock() {
    release();
}

bool AtomicHotUpdater::CrossProcessLock::acquire(uint32_t timeoutMs, std::string& errorOut) {
    if (m_acquired) return true;
#ifdef _WIN32
    std::wstring wideName(m_mutexName.begin(), m_mutexName.end());
    HANDLE h = CreateMutexW(nullptr, FALSE, wideName.c_str());
    if (!h) {
        errorOut = "CreateMutexW failed with Win32 error " + std::to_string(GetLastError());
        return false;
    }
    DWORD waitRes = WaitForSingleObject(h, timeoutMs);
    if (waitRes == WAIT_OBJECT_0 || waitRes == WAIT_ABANDONED) {
        m_mutexHandle = h;
        m_acquired = true;
        return true;
    }
    CloseHandle(h);
    errorOut = (waitRes == WAIT_TIMEOUT)
        ? "Timed out waiting for another Win32 Client instance to finish hot-updating"
        : "WaitForSingleObject failed with code " + std::to_string(waitRes);
    return false;
#else
    (void)timeoutMs;
    std::error_code ec;
    fs::create_directories(m_lockFilePath.parent_path(), ec);
    m_lockFd = ::open(m_lockFilePath.c_str(), O_CREAT | O_RDWR, 0644);
    if (m_lockFd < 0) {
        errorOut = "Failed to open lock file: " + m_lockFilePath.string();
        return false;
    }
    if (::flock(m_lockFd, LOCK_EX | LOCK_NB) != 0) {
        ::close(m_lockFd);
        m_lockFd = -1;
        errorOut = "Another Win32 Client instance holds the hot-update lock";
        return false;
    }
    m_acquired = true;
    return true;
#endif
}

void AtomicHotUpdater::CrossProcessLock::release() {
    if (!m_acquired) return;
#ifdef _WIN32
    if (m_mutexHandle) {
        ReleaseMutex(static_cast<HANDLE>(m_mutexHandle));
        CloseHandle(static_cast<HANDLE>(m_mutexHandle));
        m_mutexHandle = nullptr;
    }
#else
    if (m_lockFd >= 0) {
        ::flock(m_lockFd, LOCK_UN);
        ::close(m_lockFd);
        m_lockFd = -1;
    }
#endif
    m_acquired = false;
}

// ============================================================================
// AtomicHotUpdater
// ============================================================================

AtomicHotUpdater::AtomicHotUpdater(HotUpdaterConfig config)
    : m_config(std::move(config)) {}

AtomicHotUpdater::~AtomicHotUpdater() = default;

void AtomicHotUpdater::setResourceHandleHooks(ResourceHandleHooks hooks) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_hooks = std::move(hooks);
}

void AtomicHotUpdater::setDownloadTransport(DownloadTransport transport) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_transport = std::move(transport);
}

fs::path AtomicHotUpdater::stagingRoot() const {
    return m_config.patchRootDir / "staging";
}

fs::path AtomicHotUpdater::releasesRoot() const {
    return m_config.patchRootDir / "releases";
}

fs::path AtomicHotUpdater::activeManifestPath() const {
    return m_config.patchRootDir / "active_manifest.json";
}

fs::path AtomicHotUpdater::previousManifestPath() const {
    return m_config.patchRootDir / "previous_manifest.json";
}

fs::path AtomicHotUpdater::releaseDirForVersion(const std::string& version) const {
    return releasesRoot() / version;
}

bool AtomicHotUpdater::ensureDirectoryLayout(std::string& errorOut) const {
    std::error_code ec;
    fs::create_directories(m_config.patchRootDir, ec);
    if (ec) {
        errorOut = "Failed to create patch root dir: " + ec.message();
        return false;
    }
    fs::create_directories(stagingRoot(), ec);
    if (ec) {
        errorOut = "Failed to create staging dir: " + ec.message();
        return false;
    }
    fs::create_directories(releasesRoot(), ec);
    if (ec) {
        errorOut = "Failed to create releases dir: " + ec.message();
        return false;
    }
    return true;
}

StartupHealthResult AtomicHotUpdater::initializeAndCheckStartupHealth() {
    std::lock_guard<std::mutex> lock(m_mutex);
    StartupHealthResult result;

    std::string err;
    if (!ensureDirectoryLayout(err)) {
        result.diagnosticMessage = err;
        return result;
    }

    ActiveOverlayState state;
    if (!loadActiveStateLocked(state)) {
        result.hasActiveOverlay = false;
        result.diagnosticMessage = "No active hot-update overlay; booting from base Resources/.";
        return result;
    }

    // Verify the active overlay directory still exists on disk.
    std::error_code ec;
    const bool activeDirMissing = !state.activeOverlayDir.empty() &&
                                  !fs::exists(fs::path(state.activeOverlayDir), ec);

    // Trigger automatic rollback if the previous launch failed to confirm or overlay vanished.
    const bool exceededBootFailures =
        state.bootState == BootState::PendingVerification &&
        state.consecutiveBootFailures >= state.maxBootFailuresBeforeRollback;

    if (activeDirMissing || exceededBootFailures) {
        result.rolledBack = true;
        result.rolledBackFromVersion = state.activeVersion;

        ActiveOverlayState reverted = state;
        reverted.activeVersion = state.previousVersion;
        reverted.activeOverlayDir = state.previousOverlayDir;
        reverted.previousVersion.clear();
        reverted.previousOverlayDir.clear();
        reverted.bootState = BootState::RolledBack;
        reverted.consecutiveBootFailures = 0;
        reverted.activatedUtc = currentUtcIso8601();

        std::string writeErr;
        if (!writeFileAtomically(activeManifestPath(), serializeOverlayStateJson(reverted), writeErr)) {
            result.diagnosticMessage = "Auto-rollback write failed: " + writeErr;
        } else {
            result.hasActiveOverlay = !reverted.activeOverlayDir.empty();
            result.activeVersion = reverted.activeVersion;
            result.activeOverlayPath = reverted.activeOverlayDir;
            result.diagnosticMessage = activeDirMissing
                ? "Active overlay directory missing; rolled back from " + state.activeVersion
                : "Startup verification failed " + std::to_string(state.consecutiveBootFailures) +
                  " time(s); rolled back from " + state.activeVersion +
                  " to " + (reverted.activeVersion.empty() ? "base Resources/" : reverted.activeVersion);
        }
        return result;
    }

    // If this patch is still pending verification, increment consecutiveBootFailures
    // BEFORE Lua boots so that a native crash is detected on the next launch.
    if (state.bootState == BootState::PendingVerification) {
        state.consecutiveBootFailures += 1;
        std::string writeErr;
        writeFileAtomically(activeManifestPath(), serializeOverlayStateJson(state), writeErr);
    }

    result.hasActiveOverlay = !state.activeOverlayDir.empty();
    result.activeVersion = state.activeVersion;
    result.activeOverlayPath = state.activeOverlayDir;
    result.diagnosticMessage = "Overlay " + state.activeVersion + " active (" +
                               bootStateToString(state.bootState) + ").";
    return result;
}

UpdateResult AtomicHotUpdater::confirmStartupSuccess() {
    std::lock_guard<std::mutex> lock(m_mutex);
    UpdateResult res;

    ActiveOverlayState state;
    if (!loadActiveStateLocked(state)) {
        res.status = UpdateStatus::Ok;
        res.message = "No active overlay manifest to confirm.";
        return res;
    }

    if (state.bootState == BootState::Confirmed && state.consecutiveBootFailures == 0) {
        res.status = UpdateStatus::Ok;
        res.activeVersion = state.activeVersion;
        res.activeOverlayPath = state.activeOverlayDir;
        res.message = "Active overlay already confirmed.";
        return res;
    }

    state.bootState = BootState::Confirmed;
    state.consecutiveBootFailures = 0;

    std::string err;
    if (!writeFileAtomically(activeManifestPath(), serializeOverlayStateJson(state), err)) {
        res.status = UpdateStatus::IoError;
        res.message = "Failed to confirm startup state: " + err;
        return res;
    }

    res.status = UpdateStatus::Ok;
    res.activeVersion = state.activeVersion;
    res.activeOverlayPath = state.activeOverlayDir;
    res.message = "Confirmed startup health for overlay " + state.activeVersion + ".";
    return res;
}

UpdateStatus AtomicHotUpdater::checkCompatibility(
    const PatchManifest& manifest,
    std::string& reasonOut) const {
    if (manifest.patchVersion.empty() || !isValidVersionToken(manifest.patchVersion)) {
        reasonOut = "Invalid or empty patchVersion in manifest.";
        return UpdateStatus::InvalidManifest;
    }

    const auto& caps = m_config.capabilities;
    const auto& req = manifest.contract;

    if (caps.nativeBindingApiVersion < req.minNativeBindingApiVersion ||
        caps.nativeBindingApiVersion > req.maxNativeBindingApiVersion) {
        reasonOut = "Native binding API version mismatch: client=" +
                    std::to_string(caps.nativeBindingApiVersion) +
                    ", patch requires [" + std::to_string(req.minNativeBindingApiVersion) +
                    ", " + std::to_string(req.maxNativeBindingApiVersion) + "].";
        return UpdateStatus::IncompatibleNativeBinding;
    }

    if (caps.protoSchemaVersion != req.requiredProtoSchemaVersion) {
        reasonOut = "Proto2 schema version mismatch: client=" +
                    std::to_string(caps.protoSchemaVersion) +
                    ", patch requires " + std::to_string(req.requiredProtoSchemaVersion) + ".";
        return UpdateStatus::IncompatibleProtoSchema;
    }

    if (caps.dbSchemaVersion != req.requiredDbSchemaVersion) {
        reasonOut = "SQLite DB schema version mismatch: client=" +
                    std::to_string(caps.dbSchemaVersion) +
                    ", patch requires " + std::to_string(req.requiredDbSchemaVersion) + ".";
        return UpdateStatus::IncompatibleDbSchema;
    }

    if (!req.minClientVersion.empty() &&
        compareSemver(caps.clientVersion, req.minClientVersion) < 0) {
        reasonOut = "Client version " + caps.clientVersion +
                    " is older than patch minimum " + req.minClientVersion + ".";
        return UpdateStatus::IncompatibleClientVersion;
    }

    for (const auto& symbol : req.requiredNativeBindings) {
        if (caps.exportedBindings.find(symbol) == caps.exportedBindings.end()) {
            reasonOut = "Patch requires missing native C++ binding: " + symbol;
            return UpdateStatus::MissingRequiredBinding;
        }
    }

    reasonOut.clear();
    return UpdateStatus::Ok;
}

UpdateResult AtomicHotUpdater::stagePatch(
    const PatchManifest& manifest,
    const StageProgressCallback& progressCb) {
    std::lock_guard<std::mutex> lock(m_mutex);
    UpdateResult res;

    std::string compatErr;
    UpdateStatus compatStatus = checkCompatibility(manifest, compatErr);
    if (compatStatus != UpdateStatus::Ok) {
        res.status = compatStatus;
        res.message = compatErr;
        return res;
    }

    if (!m_transport) {
        res.status = UpdateStatus::DownloadFailed;
        res.message = "No DownloadTransport registered on AtomicHotUpdater.";
        return res;
    }

    std::string layoutErr;
    if (!ensureDirectoryLayout(layoutErr)) {
        res.status = UpdateStatus::IoError;
        res.message = layoutErr;
        return res;
    }

    // If the exact release is already staged & committed, verify presence.
    const fs::path targetReleaseDir = releaseDirForVersion(manifest.patchVersion);
    std::error_code ec;
    if (fs::exists(targetReleaseDir, ec) && fs::is_directory(targetReleaseDir, ec)) {
        ActiveOverlayState cur;
        if (loadActiveStateLocked(cur) && cur.activeVersion == manifest.patchVersion) {
            res.status = UpdateStatus::AlreadyUpToDate;
            res.activeVersion = cur.activeVersion;
            res.activeOverlayPath = cur.activeOverlayDir;
            res.message = "Patch " + manifest.patchVersion + " is already active.";
            return res;
        }
    }

    // Validate all relative paths upfront before creating any files.
    for (const auto& entry : manifest.files) {
        if (!isSafeRelativePath(entry.relativePath)) {
            res.status = UpdateStatus::InvalidPathTraversal;
            res.message = "Rejected unsafe relative path in manifest: " + entry.relativePath;
            return res;
        }
        if (entry.sha256.empty() && entry.md5.empty()) {
            res.status = UpdateStatus::InvalidManifest;
            res.message = "Manifest entry missing both SHA-256 and MD5 checksum: " + entry.relativePath;
            return res;
        }
    }

    // Create isolated versioned staging directory.
    const fs::path stagingDir = stagingRoot() / (manifest.patchVersion + "_" + generateStagingNonce());
    fs::create_directories(stagingDir, ec);
    if (ec) {
        res.status = UpdateStatus::IoError;
        res.message = "Failed to create staging directory: " + ec.message();
        return res;
    }

    auto cleanupStaging = [&]() {
        std::error_code rmEc;
        fs::remove_all(stagingDir, rmEc);
    };

    const size_t totalFiles = manifest.files.size();
    for (size_t i = 0; i < totalFiles; ++i) {
        const auto& entry = manifest.files[i];
        const fs::path destFile = stagingDir / fs::path(entry.relativePath);

        fs::create_directories(destFile.parent_path(), ec);
        if (ec) {
            cleanupStaging();
            res.status = UpdateStatus::IoError;
            res.message = "Failed to create parent dir for " + entry.relativePath + ": " + ec.message();
            return res;
        }

        std::string dlErr;
        if (!m_transport(entry.downloadUrl, destFile, dlErr)) {
            cleanupStaging();
            res.status = UpdateStatus::DownloadFailed;
            res.message = "Download failed for " + entry.relativePath + ": " + dlErr;
            return res;
        }

        if (entry.expectedSize > 0) {
            uint64_t actualSize = fs::file_size(destFile, ec);
            if (ec || actualSize != entry.expectedSize) {
                cleanupStaging();
                res.status = UpdateStatus::SizeMismatch;
                res.message = "Size mismatch for " + entry.relativePath +
                              " (expected " + std::to_string(entry.expectedSize) +
                              ", got " + std::to_string(actualSize) + ").";
                return res;
            }
        }

        if (!entry.sha256.empty()) {
            std::string actualSha256, hashErr;
            if (!computeFileHash(destFile, HashAlgorithm::SHA256, actualSha256, hashErr) ||
                toLowerAscii(actualSha256) != toLowerAscii(entry.sha256)) {
                cleanupStaging();
                res.status = UpdateStatus::ChecksumMismatch;
                res.message = "SHA-256 mismatch for " + entry.relativePath +
                              (hashErr.empty() ? "" : (" (" + hashErr + ")"));
                return res;
            }
        }

        if (!entry.md5.empty()) {
            std::string actualMd5, hashErr;
            if (!computeFileHash(destFile, HashAlgorithm::MD5, actualMd5, hashErr) ||
                toLowerAscii(actualMd5) != toLowerAscii(entry.md5)) {
                cleanupStaging();
                res.status = UpdateStatus::ChecksumMismatch;
                res.message = "MD5 mismatch for " + entry.relativePath +
                              (hashErr.empty() ? "" : (" (" + hashErr + ")"));
                return res;
            }
        }

        if (progressCb) {
            progressCb(i + 1, totalFiles, entry.relativePath);
        }
    }

    // Promote verified staging directory into immutable releases/<version>/.
    std::string moveErr;
    if (!moveDirectoryAtomically(stagingDir, targetReleaseDir, moveErr)) {
        cleanupStaging();
        res.status = UpdateStatus::IoError;
        res.message = "Failed to promote staged release: " + moveErr;
        return res;
    }

    res.status = UpdateStatus::Ok;
    res.activeVersion = manifest.patchVersion;
    res.activeOverlayPath = targetReleaseDir;
    res.message = "Staged and verified patch " + manifest.patchVersion +
                  " (" + std::to_string(totalFiles) + " files).";
    return res;
}

UpdateResult AtomicHotUpdater::commitStagedPatch(const std::string& patchVersion) {
    std::lock_guard<std::mutex> lock(m_mutex);
    UpdateResult res;

    if (!isValidVersionToken(patchVersion)) {
        res.status = UpdateStatus::InvalidManifest;
        res.message = "Invalid patchVersion token: " + patchVersion;
        return res;
    }

    const fs::path releaseDir = releaseDirForVersion(patchVersion);
    std::error_code ec;
    if (!fs::exists(releaseDir, ec) || !fs::is_directory(releaseDir, ec)) {
        res.status = UpdateStatus::InvalidManifest;
        res.message = "Staged release directory not found for version " + patchVersion;
        return res;
    }

    CrossProcessLock procLock(m_config.patchRootDir);
    std::string lockErr;
    if (!procLock.acquire(5000, lockErr)) {
        res.status = UpdateStatus::LockAcquisitionFailed;
        res.message = lockErr;
        return res;
    }

    ActiveOverlayState prevState;
    const bool hadPrevState = loadActiveStateLocked(prevState);
    const fs::path oldOverlayDir = hadPrevState ? fs::path(prevState.activeOverlayDir) : fs::path{};

    // Step 1: Coordinate releasing all open SQLite .db and asset handles.
    if (m_hooks.prepareForSwap) {
        std::string hookErr;
        if (!m_hooks.prepareForSwap(hookErr)) {
            if (m_hooks.abortSwap) m_hooks.abortSwap(oldOverlayDir);
            res.status = UpdateStatus::HandleReleaseFailed;
            res.message = "Subsystem refused handle release: " + hookErr;
            return res;
        }
    }

    if (m_hooks.verifyHandlesReleased) {
        std::string verifyErr;
        if (!m_hooks.verifyHandlesReleased(verifyErr)) {
            if (m_hooks.abortSwap) m_hooks.abortSwap(oldOverlayDir);
            res.status = UpdateStatus::HandleReleaseFailed;
            res.message = "Open handles still detected after prepareForSwap: " + verifyErr;
            return res;
        }
    }

    // Step 2: Probe NTFS lock on active_manifest.json before swapping.
    if (fs::exists(activeManifestPath(), ec)) {
        std::string probeErr;
        if (!probePathUnlockedWithRetry(activeManifestPath(), probeErr)) {
            if (m_hooks.abortSwap) m_hooks.abortSwap(oldOverlayDir);
            res.status = UpdateStatus::NtfsLockTimeout;
            res.message = "NTFS lock timeout on active_manifest.json: " + probeErr;
            return res;
        }
    }

    // Step 3: Backup current manifest pointer for rollback safety.
    if (hadPrevState) {
        std::string backupErr;
        writeFileAtomically(previousManifestPath(), serializeOverlayStateJson(prevState), backupErr);
    }

    // Step 4: Build new PendingVerification overlay pointer and swap atomically.
    ActiveOverlayState nextState;
    nextState.activeVersion = patchVersion;
    nextState.activeOverlayDir = releaseDir.string();
    nextState.previousVersion = hadPrevState ? prevState.activeVersion : "";
    nextState.previousOverlayDir = hadPrevState ? prevState.activeOverlayDir : "";
    nextState.bootState = BootState::PendingVerification;
    nextState.consecutiveBootFailures = 0;
    nextState.maxBootFailuresBeforeRollback = m_config.maxBootFailuresBeforeRollback;
    nextState.nativeBindingApiVersion = m_config.capabilities.nativeBindingApiVersion;
    nextState.protoSchemaVersion = m_config.capabilities.protoSchemaVersion;
    nextState.dbSchemaVersion = m_config.capabilities.dbSchemaVersion;
    nextState.activatedUtc = currentUtcIso8601();

    std::string swapErr;
    if (!writeFileAtomically(activeManifestPath(), serializeOverlayStateJson(nextState), swapErr)) {
        if (m_hooks.abortSwap) m_hooks.abortSwap(oldOverlayDir);
        res.status = UpdateStatus::SwapFailed;
        res.message = "Atomic manifest swap failed: " + swapErr;
        return res;
    }

    // Step 5: Reload engine subsystems against the new overlay. If reload fails,
    // immediately revert the manifest pointer back to the previous known-good state.
    if (m_hooks.reloadAfterSwap) {
        std::string reloadErr;
        if (!m_hooks.reloadAfterSwap(releaseDir, reloadErr)) {
            ActiveOverlayState rollbackState = hadPrevState ? prevState : ActiveOverlayState{};
            rollbackState.bootState = BootState::RolledBack;
            rollbackState.consecutiveBootFailures = 0;
            std::string rbErr;
            writeFileAtomically(activeManifestPath(), serializeOverlayStateJson(rollbackState), rbErr);
            if (m_hooks.abortSwap) {
                m_hooks.abortSwap(oldOverlayDir);
            }
            res.status = UpdateStatus::ReloadFailedRolledBack;
            res.activeVersion = rollbackState.activeVersion;
            res.activeOverlayPath = rollbackState.activeOverlayDir;
            res.message = "Subsystem reload failed (" + reloadErr + "); rolled back to " +
                          (rollbackState.activeVersion.empty() ? "base Resources/" : rollbackState.activeVersion);
            return res;
        }
    }

    res.status = UpdateStatus::Ok;
    res.activeVersion = nextState.activeVersion;
    res.activeOverlayPath = releaseDir;
    res.message = "Atomically activated overlay " + patchVersion + " (pending startup verification).";
    return res;
}

UpdateResult AtomicHotUpdater::applyPatch(
    const PatchManifest& manifest,
    const StageProgressCallback& progressCb) {
    UpdateResult stageRes = stagePatch(manifest, progressCb);
    if (!stageRes.ok() || stageRes.status == UpdateStatus::AlreadyUpToDate) {
        return stageRes;
    }
    return commitStagedPatch(manifest.patchVersion);
}

UpdateResult AtomicHotUpdater::rollbackToPrevious() {
    std::lock_guard<std::mutex> lock(m_mutex);
    UpdateResult res;

    ActiveOverlayState curState;
    if (!loadActiveStateLocked(curState)) {
        res.status = UpdateStatus::RollbackUnavailable;
        res.message = "No active overlay manifest found to roll back.";
        return res;
    }

    CrossProcessLock procLock(m_config.patchRootDir);
    std::string lockErr;
    if (!procLock.acquire(5000, lockErr)) {
        res.status = UpdateStatus::LockAcquisitionFailed;
        res.message = lockErr;
        return res;
    }

    if (m_hooks.prepareForSwap) {
        std::string hookErr;
        if (!m_hooks.prepareForSwap(hookErr)) {
            res.status = UpdateStatus::HandleReleaseFailed;
            res.message = "Could not release handles for rollback: " + hookErr;
            return res;
        }
    }

    ActiveOverlayState reverted = curState;
    reverted.activeVersion = curState.previousVersion;
    reverted.activeOverlayDir = curState.previousOverlayDir;
    reverted.previousVersion.clear();
    reverted.previousOverlayDir.clear();
    reverted.bootState = BootState::RolledBack;
    reverted.consecutiveBootFailures = 0;
    reverted.activatedUtc = currentUtcIso8601();

    std::string writeErr;
    if (!writeFileAtomically(activeManifestPath(), serializeOverlayStateJson(reverted), writeErr)) {
        res.status = UpdateStatus::RollbackFailed;
        res.message = "Failed to persist rollback manifest: " + writeErr;
        return res;
    }

    if (m_hooks.reloadAfterSwap) {
        std::string reloadErr;
        m_hooks.reloadAfterSwap(fs::path(reverted.activeOverlayDir), reloadErr);
    }

    res.status = UpdateStatus::Ok;
    res.activeVersion = reverted.activeVersion;
    res.activeOverlayPath = reverted.activeOverlayDir;
    res.message = "Rolled back from " + curState.activeVersion + " to " +
                  (reverted.activeVersion.empty() ? "base Resources/" : reverted.activeVersion) + ".";
    return res;
}

size_t AtomicHotUpdater::pruneOldReleases(size_t keepCount) {
    std::lock_guard<std::mutex> lock(m_mutex);
    size_t removed = 0;
    std::error_code ec;

    // 1. Clean abandoned staging directories.
    if (fs::exists(stagingRoot(), ec)) {
        for (const auto& entry : fs::directory_iterator(stagingRoot(), ec)) {
            std::error_code rmEc;
            fs::remove_all(entry.path(), rmEc);
            if (!rmEc) ++removed;
        }
    }

    // 2. Collect candidate releases excluding activeVersion and previousVersion.
    ActiveOverlayState curState;
    const bool hasState = loadActiveStateLocked(curState);

    std::vector<std::pair<fs::file_time_type, fs::path>> candidates;
    if (fs::exists(releasesRoot(), ec)) {
        for (const auto& entry : fs::directory_iterator(releasesRoot(), ec)) {
            if (!entry.is_directory(ec)) continue;
            const std::string ver = entry.path().filename().string();
            if (hasState && (ver == curState.activeVersion || ver == curState.previousVersion)) {
                continue;
            }
            candidates.emplace_back(entry.last_write_time(ec), entry.path());
        }
    }

    // Keep newest `keepCount` extra releases; remove older ones if unlocked.
    std::sort(candidates.begin(), candidates.end(),
              [](const auto& a, const auto& b) { return a.first > b.first; });
    for (size_t i = keepCount; i < candidates.size(); ++i) {
        std::error_code rmEc;
        fs::remove_all(candidates[i].second, rmEc);
        if (!rmEc) ++removed;
    }
    return removed;
}

std::optional<ActiveOverlayState> AtomicHotUpdater::getActiveState() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    ActiveOverlayState state;
    if (!loadActiveStateLocked(state)) return std::nullopt;
    return state;
}

std::optional<fs::path> AtomicHotUpdater::getActiveOverlayPath() const {
    auto state = getActiveState();
    if (!state || state->activeOverlayDir.empty()) return std::nullopt;
    return fs::path(state->activeOverlayDir);
}

bool AtomicHotUpdater::loadActiveStateLocked(ActiveOverlayState& outState) const {
    std::ifstream ifs(activeManifestPath(), std::ios::in | std::ios::binary);
    if (!ifs.is_open()) return false;
    std::ostringstream oss;
    oss << ifs.rdbuf();
    return parseOverlayStateJson(oss.str(), outState);
}

bool AtomicHotUpdater::writeFileAtomically(
    const fs::path& targetPath,
    const std::string& contents,
    std::string& errorOut) const {
    std::error_code ec;
    fs::create_directories(targetPath.parent_path(), ec);

    // Temp file MUST reside on the same NTFS volume/directory as targetPath so
    // MoveFileExW executes an atomic directory-entry rename.
    const fs::path tmpPath = targetPath.parent_path() /
                             (targetPath.filename().string() + "." + generateStagingNonce() + ".tmp");

#ifdef _WIN32
    HANDLE hFile = CreateFileW(
        tmpPath.wstring().c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
        nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        errorOut = "CreateFileW failed for temp manifest: Win32 error " + std::to_string(GetLastError());
        return false;
    }

    DWORD written = 0;
    BOOL writeOk = WriteFile(
        hFile,
        contents.data(),
        static_cast<DWORD>(contents.size()),
        &written,
        nullptr);
    BOOL flushOk = writeOk ? FlushFileBuffers(hFile) : FALSE;
    DWORD lastErr = GetLastError();
    CloseHandle(hFile);

    if (!writeOk || written != contents.size() || !flushOk) {
        DeleteFileW(tmpPath.wstring().c_str());
        errorOut = "WriteFile/FlushFileBuffers failed: Win32 error " + std::to_string(lastErr);
        return false;
    }

    // Retry MoveFileExW briefly in case Windows Defender or Explorer briefly locks targetPath.
    for (uint32_t attempt = 0; attempt <= m_config.lockProbeMaxRetries; ++attempt) {
        if (MoveFileExW(
                tmpPath.wstring().c_str(),
                targetPath.wstring().c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            return true;
        }
        DWORD moveErr = GetLastError();
        if (moveErr != ERROR_SHARING_VIOLATION && moveErr != ERROR_ACCESS_DENIED &&
            moveErr != ERROR_LOCK_VIOLATION) {
            DeleteFileW(tmpPath.wstring().c_str());
            errorOut = "MoveFileExW failed: Win32 error " + std::to_string(moveErr);
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(
            m_config.lockProbeBackoffMs * (attempt + 1)));
    }
    DeleteFileW(tmpPath.wstring().c_str());
    errorOut = "MoveFileExW timed out due to NTFS sharing/lock violation.";
    return false;
#else
    int fd = ::open(tmpPath.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        errorOut = "Failed to open temp file: " + tmpPath.string();
        return false;
    }
    size_t totalWritten = 0;
    while (totalWritten < contents.size()) {
        ssize_t n = ::write(fd, contents.data() + totalWritten, contents.size() - totalWritten);
        if (n <= 0) {
            ::close(fd);
            ::unlink(tmpPath.c_str());
            errorOut = "Failed to write temp file: " + tmpPath.string();
            return false;
        }
        totalWritten += static_cast<size_t>(n);
    }
    ::fsync(fd);
    ::close(fd);

    if (::rename(tmpPath.c_str(), targetPath.c_str()) != 0) {
        ::unlink(tmpPath.c_str());
        errorOut = "Atomic rename failed for: " + targetPath.string();
        return false;
    }
    return true;
#endif
}

bool AtomicHotUpdater::probePathUnlockedWithRetry(
    const fs::path& path,
    std::string& errorOut) const {
#ifdef _WIN32
    for (uint32_t attempt = 0; attempt <= m_config.lockProbeMaxRetries; ++attempt) {
        HANDLE h = CreateFileW(
            path.wstring().c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0, // Exclusive share mode: fails with ERROR_SHARING_VIOLATION if any handle is open.
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
            return true;
        }
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND) {
            return true;
        }
        if (err != ERROR_SHARING_VIOLATION && err != ERROR_LOCK_VIOLATION &&
            err != ERROR_ACCESS_DENIED) {
            errorOut = "Unexpected Win32 error probing lock: " + std::to_string(err);
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(
            m_config.lockProbeBackoffMs * (attempt + 1)));
    }
    errorOut = "File remains locked after " + std::to_string(m_config.lockProbeMaxRetries) + " retries.";
    return false;
#else
    (void)path;
    (void)errorOut;
    return true;
#endif
}

bool AtomicHotUpdater::moveDirectoryAtomically(
    const fs::path& srcDir,
    const fs::path& dstDir,
    std::string& errorOut) const {
    std::error_code ec;
    if (fs::exists(dstDir, ec)) {
        // Move any stale pre-existing unactivated directory aside before replacing.
        fs::path trashDir = stagingRoot() / ("replaced_" + generateStagingNonce());
        fs::rename(dstDir, trashDir, ec);
        if (ec) {
            errorOut = "Existing release directory is locked or busy: " + ec.message();
            return false;
        }
        std::error_code rmEc;
        fs::remove_all(trashDir, rmEc);
    }

    fs::rename(srcDir, dstDir, ec);
    if (ec) {
        errorOut = "Failed to promote staging dir to releases/: " + ec.message();
        return false;
    }
    return true;
}

// ============================================================================
// Static Utilities (JSON, Hashing, Path Safety, Semver)
// ============================================================================

std::string AtomicHotUpdater::serializeOverlayStateJson(const ActiveOverlayState& state) {
    std::ostringstream oss;
    oss << "{\n"
        << "  \"activeVersion\": \"" << jsonEscape(state.activeVersion) << "\",\n"
        << "  \"activeOverlayDir\": \"" << jsonEscape(state.activeOverlayDir) << "\",\n"
        << "  \"previousVersion\": \"" << jsonEscape(state.previousVersion) << "\",\n"
        << "  \"previousOverlayDir\": \"" << jsonEscape(state.previousOverlayDir) << "\",\n"
        << "  \"bootState\": \"" << bootStateToString(state.bootState) << "\",\n"
        << "  \"consecutiveBootFailures\": " << state.consecutiveBootFailures << ",\n"
        << "  \"maxBootFailuresBeforeRollback\": " << state.maxBootFailuresBeforeRollback << ",\n"
        << "  \"nativeBindingApiVersion\": " << state.nativeBindingApiVersion << ",\n"
        << "  \"protoSchemaVersion\": " << state.protoSchemaVersion << ",\n"
        << "  \"dbSchemaVersion\": " << state.dbSchemaVersion << ",\n"
        << "  \"activatedUtc\": \"" << jsonEscape(state.activatedUtc) << "\"\n"
        << "}\n";
    return oss.str();
}

bool AtomicHotUpdater::parseOverlayStateJson(const std::string& json, ActiveOverlayState& outState) {
    ActiveOverlayState parsed;
    std::string bootStr;
    if (!extractJsonString(json, "activeVersion", parsed.activeVersion)) return false;
    extractJsonString(json, "activeOverlayDir", parsed.activeOverlayDir);
    extractJsonString(json, "previousVersion", parsed.previousVersion);
    extractJsonString(json, "previousOverlayDir", parsed.previousOverlayDir);
    if (extractJsonString(json, "bootState", bootStr)) {
        parsed.bootState = stringToBootState(bootStr);
    }
    extractJsonUint32(json, "consecutiveBootFailures", parsed.consecutiveBootFailures);
    extractJsonUint32(json, "maxBootFailuresBeforeRollback", parsed.maxBootFailuresBeforeRollback);
    extractJsonUint32(json, "nativeBindingApiVersion", parsed.nativeBindingApiVersion);
    extractJsonUint32(json, "protoSchemaVersion", parsed.protoSchemaVersion);
    extractJsonUint32(json, "dbSchemaVersion", parsed.dbSchemaVersion);
    extractJsonString(json, "activatedUtc", parsed.activatedUtc);
    outState = std::move(parsed);
    return true;
}

bool AtomicHotUpdater::computeFileHash(
    const fs::path& filePath,
    HashAlgorithm algo,
    std::string& hexDigestOut,
    std::string& errorOut) {
    std::ifstream ifs(filePath, std::ios::in | std::ios::binary);
    if (!ifs.is_open()) {
        errorOut = "Cannot open file for hashing: " + filePath.string();
        return false;
    }

#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    const LPCWSTR algId = (algo == HashAlgorithm::SHA256) ? BCRYPT_SHA256_ALGORITHM : BCRYPT_MD5_ALGORITHM;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, algId, nullptr, 0);
    if (status < 0) {
        errorOut = "BCryptOpenAlgorithmProvider failed.";
        return false;
    }

    DWORD hashObjSize = 0, cbData = 0, hashLen = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&hashObjSize), sizeof(DWORD), &cbData, 0);
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLen), sizeof(DWORD), &cbData, 0);

    std::vector<uint8_t> hashObj(hashObjSize);
    std::vector<uint8_t> digest(hashLen);

    status = BCryptCreateHash(hAlg, &hHash, hashObj.data(), hashObjSize, nullptr, 0, 0);
    if (status < 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        errorOut = "BCryptCreateHash failed.";
        return false;
    }

    std::array<char, 65536> buf{};
    while (ifs.good()) {
        ifs.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        std::streamsize n = ifs.gcount();
        if (n > 0) {
            status = BCryptHashData(hHash, reinterpret_cast<PUCHAR>(buf.data()), static_cast<ULONG>(n), 0);
            if (status < 0) break;
        }
    }

    if (status >= 0) {
        status = BCryptFinishHash(hHash, digest.data(), hashLen, 0);
    }
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (status < 0) {
        errorOut = "BCrypt hashing failed.";
        return false;
    }
    hexDigestOut = toLowerHex(digest.data(), digest.size());
    return true;
#else
    std::array<char, 65536> buf{};
    if (algo == HashAlgorithm::SHA256) {
        Sha256Context ctx;
        while (ifs.good()) {
            ifs.read(buf.data(), static_cast<std::streamsize>(buf.size()));
            std::streamsize n = ifs.gcount();
            if (n > 0) ctx.update(reinterpret_cast<const uint8_t*>(buf.data()), static_cast<size_t>(n));
        }
        auto digest = ctx.finalize();
        hexDigestOut = toLowerHex(digest.data(), digest.size());
    } else {
        Md5Context ctx;
        while (ifs.good()) {
            ifs.read(buf.data(), static_cast<std::streamsize>(buf.size()));
            std::streamsize n = ifs.gcount();
            if (n > 0) ctx.update(reinterpret_cast<const uint8_t*>(buf.data()), static_cast<size_t>(n));
        }
        auto digest = ctx.finalize();
        hexDigestOut = toLowerHex(digest.data(), digest.size());
    }
    return true;
#endif
}

bool AtomicHotUpdater::isSafeRelativePath(const std::string& relativePath) {
    if (relativePath.empty()) return false;
    if (relativePath.find('\0') != std::string::npos) return false;
    if (relativePath[0] == '/' || relativePath[0] == '\\') return false;
    if (relativePath.find(':') != std::string::npos) return false; // Block Win32 drive letters / ADS

    fs::path p(relativePath);
    if (p.is_absolute()) return false;
    for (const auto& part : p) {
        if (part == "..") return false;
    }
    return true;
}

int AtomicHotUpdater::compareSemver(const std::string& lhs, const std::string& rhs) {
    auto parseParts = [](const std::string& v) {
        std::array<uint32_t, 3> parts = {0, 0, 0};
        size_t idx = 0, start = 0;
        while (idx < 3 && start < v.size()) {
            size_t dot = v.find('.', start);
            std::string tok = (dot == std::string::npos) ? v.substr(start) : v.substr(start, dot - start);
            uint32_t num = 0;
            for (char c : tok) {
                if (!std::isdigit(static_cast<unsigned char>(c))) break;
                num = num * 10u + static_cast<uint32_t>(c - '0');
            }
            parts[idx++] = num;
            if (dot == std::string::npos) break;
            start = dot + 1;
        }
        return parts;
    };
    const auto a = parseParts(lhs);
    const auto b = parseParts(rhs);
    for (size_t i = 0; i < 3; ++i) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

std::string AtomicHotUpdater::currentUtcIso8601() {
    auto now = std::chrono::system_clock::now();
    std::time_t tt = std::chrono::system_clock::to_time_t(now);
    std::tm utcTm{};
#ifdef _WIN32
    gmtime_s(&utcTm, &tt);
#else
    gmtime_r(&tt, &utcTm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &utcTm);
    return std::string(buf);
}

std::string AtomicHotUpdater::generateStagingNonce() {
    static thread_local std::mt19937_64 rng(
        static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::ostringstream oss;
    oss << std::hex << std::setw(12) << std::setfill('0') << (rng() & 0xFFFFFFFFFFFFull);
    return oss.str();
}

std::string AtomicHotUpdater::toLowerHex(const uint8_t* data, size_t len) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[i * 2 + 0] = hex[(data[i] >> 4) & 0x0Fu];
        out[i * 2 + 1] = hex[data[i] & 0x0Fu];
    }
    return out;
}

std::string AtomicHotUpdater::toLowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

bool AtomicHotUpdater::isValidVersionToken(const std::string& version) {
    if (version.empty() || version.size() > 64) return false;
    for (unsigned char c : version) {
        if (!std::isalnum(c) && c != '.' && c != '-' && c != '_') return false;
    }
    return version != "." && version != "..";
}

} // namespace update
} // namespace gclient
