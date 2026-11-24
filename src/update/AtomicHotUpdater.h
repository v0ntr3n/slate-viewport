#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace gclient {
namespace update {

/// Supported cryptographic digest algorithms for patch payload verification.
enum class HashAlgorithm {
    SHA256,
    MD5
};

/// Lifecycle state of the currently active overlay manifest.
enum class BootState {
    Confirmed,           ///< Last launch succeeded and confirmed startup health.
    PendingVerification, ///< Newly swapped patch; awaiting ConfirmStartupSuccess().
    RolledBack           ///< Automatically reverted after startup failure.
};

/// Outcome codes for hot-update operations.
enum class UpdateStatus {
    Ok,
    AlreadyUpToDate,
    IncompatibleNativeBinding,
    IncompatibleProtoSchema,
    IncompatibleDbSchema,
    IncompatibleClientVersion,
    MissingRequiredBinding,
    InvalidManifest,
    InvalidPathTraversal,
    DownloadFailed,
    SizeMismatch,
    ChecksumMismatch,
    HandleReleaseFailed,
    NtfsLockTimeout,
    SwapFailed,
    ReloadFailedRolledBack,
    RollbackUnavailable,
    RollbackFailed,
    LockAcquisitionFailed,
    IoError
};

/// Native client capability contract used to gate incoming hot-updates.
struct ClientCapabilities {
    uint32_t nativeBindingApiVersion = 1;
    uint32_t protoSchemaVersion = 1;
    uint32_t dbSchemaVersion = 1;
    std::string clientVersion = "1.0.0";
    /// Set of C++/tolua++ native binding symbols exported by this Win32 executable.
    std::unordered_set<std::string> exportedBindings;
};

/// Compatibility constraints declared inside a remote patch manifest.
struct CompatibilityContract {
    uint32_t minNativeBindingApiVersion = 1;
    uint32_t maxNativeBindingApiVersion = 1;
    uint32_t requiredProtoSchemaVersion = 1;
    uint32_t requiredDbSchemaVersion = 1;
    std::string minClientVersion = "1.0.0";
    std::vector<std::string> requiredNativeBindings;
};

/// Single file entry within a hot-update patch manifest.
struct PatchFileEntry {
    /// Forward-slash relative path inside the overlay (e.g., "script/main.lua").
    std::string relativePath;
    /// Source URL (or local path when using a local transport).
    std::string downloadUrl;
    /// Expected file size in bytes (0 skips size check only if not specified).
    uint64_t expectedSize = 0;
    /// Lowercase hex SHA-256 digest (optional if md5 is provided, recommended).
    std::string sha256;
    /// Lowercase hex MD5 digest (optional if sha256 is provided).
    std::string md5;
};

/// Complete remote patch manifest describing an atomic overlay release.
struct PatchManifest {
    std::string patchVersion;
    std::string baseVersion;
    CompatibilityContract contract;
    std::vector<PatchFileEntry> files;
};

/// Persisted overlay pointer state stored in active_manifest.json.
struct ActiveOverlayState {
    std::string activeVersion;
    std::string activeOverlayDir;
    std::string previousVersion;
    std::string previousOverlayDir;
    BootState bootState = BootState::Confirmed;
    uint32_t consecutiveBootFailures = 0;
    uint32_t maxBootFailuresBeforeRollback = 2;
    uint32_t nativeBindingApiVersion = 1;
    uint32_t protoSchemaVersion = 1;
    uint32_t dbSchemaVersion = 1;
    std::string activatedUtc;
};

/// Detailed result returned by hot-update operations.
struct UpdateResult {
    UpdateStatus status = UpdateStatus::Ok;
    std::string message;
    std::string activeVersion;
    std::filesystem::path activeOverlayPath;

    bool ok() const {
        return status == UpdateStatus::Ok || status == UpdateStatus::AlreadyUpToDate;
    }
};

/// Result of startup health inspection and automatic rollback check.
struct StartupHealthResult {
    bool rolledBack = false;
    bool hasActiveOverlay = false;
    std::string activeVersion;
    std::filesystem::path activeOverlayPath;
    std::string rolledBackFromVersion;
    std::string diagnosticMessage;
};

/// Progress callback invoked during staged patch downloads.
using StageProgressCallback = std::function<void(
    size_t completedFiles,
    size_t totalFiles,
    const std::string& currentRelativePath)>;

/// Pluggable transport callback that downloads `url` into `destinationPath`.
/// Returns true on success; sets `errorOut` on failure.
using DownloadTransport = std::function<bool(
    const std::string& url,
    const std::filesystem::path& destinationPath,
    std::string& errorOut)>;

/// Subsystem coordination hooks to release Windows NTFS file locks before
/// swapping the active overlay manifest pointer (e.g., closing 171 SQLite .db
/// handles in CConfigurationManager and releasing cached asset views).
struct ResourceHandleHooks {
    /// Flush and close all open SQLite DBs, mmap views, and asset file handles.
    /// Must return true only when all handles have been released.
    std::function<bool(std::string& errorOut)> prepareForSwap;

    /// Optional verification hook confirming zero open handles remain.
    std::function<bool(std::string& errorOut)> verifyHandlesReleased;

    /// Re-bind CCFileUtils search path overlay and reopen SQLite DBs against
    /// `newOverlayDir` (empty string means base Resources/ only).
    std::function<bool(const std::filesystem::path& newOverlayDir, std::string& errorOut)> reloadAfterSwap;

    /// Optional recovery hook called if swap is aborted before committing.
    std::function<void(const std::filesystem::path& currentOverlayDir)> abortSwap;
};

/// Configuration for AtomicHotUpdater.
struct HotUpdaterConfig {
    /// Read-only base Win32 Client Resources/ directory (never modified in place).
    std::filesystem::path baseResourcesDir;
    /// Writable root for staging/, releases/, and active_manifest.json.
    std::filesystem::path patchRootDir;
    /// Host Win32 client capabilities for compatibility gating.
    ClientCapabilities capabilities;
    /// Number of consecutive failed startups before auto-rollback triggers.
    uint32_t maxBootFailuresBeforeRollback = 2;
    /// Retry count when probing NTFS file locks before swapping.
    uint32_t lockProbeMaxRetries = 12;
    /// Base backoff in milliseconds between NTFS lock probes.
    uint32_t lockProbeBackoffMs = 50;
};

/// Windows-safe atomic hot-update pipeline for the Win32 Client Win32 C++ client.
///
/// Design principles:
///  1. Never mutates base `Resources/` or active overlay files in place.
///  2. Downloads and verifies all payloads (size + SHA-256/MD5) into a
///     versioned `staging/<version>_<nonce>/` directory.
///  3. Gates every patch on native binding API, proto2 schema, DB schema, and
///     required binding symbol compatibility before download or activation.
///  4. Coordinates releasing open SQLite/asset handles via ResourceHandleHooks,
///     probes NTFS locks, and atomically swaps `active_manifest.json` using
///     FlushFileBuffers + MoveFileExW(MOVEFILE_REPLACE_EXISTING | WRITE_THROUGH).
///  5. Tracks `PendingVerification` boot state so any crash before
///     ConfirmStartupSuccess() automatically rolls back to the previous
///     known-good overlay on the next launch.
class AtomicHotUpdater {
public:
    explicit AtomicHotUpdater(HotUpdaterConfig config);
    ~AtomicHotUpdater();

    AtomicHotUpdater(const AtomicHotUpdater&) = delete;
    AtomicHotUpdater& operator=(const AtomicHotUpdater&) = delete;

    /// Register subsystem handle-release/reload hooks (DBs, FileUtils, caches).
    void setResourceHandleHooks(ResourceHandleHooks hooks);

    /// Register HTTP/local download transport implementation.
    void setDownloadTransport(DownloadTransport transport);

    /// Called at early startup (before Lua/DB init). Inspects active_manifest.json,
    /// increments pending boot failure counter, and automatically rolls back to
    /// the previous known-good overlay if the previous launch failed to confirm.
    StartupHealthResult initializeAndCheckStartupHealth();

    /// Called once the Win32 client has successfully initialized Lua, DBs, and
    /// entered the main scene. Marks the active overlay as Confirmed.
    UpdateResult confirmStartupSuccess();

    /// Validates patch compatibility against this binary's ClientCapabilities.
    UpdateStatus checkCompatibility(const PatchManifest& manifest, std::string& reasonOut) const;

    /// Downloads and verifies all files in `manifest` into a versioned staging
    /// directory and promotes the verified directory into `releases/<version>/`.
    /// Does NOT affect currently running overlays or open file handles.
    UpdateResult stagePatch(
        const PatchManifest& manifest,
        const StageProgressCallback& progressCb = nullptr);

    /// Releases open DB/asset handles, verifies NTFS locks are clear, atomically
    /// swaps `active_manifest.json` to `patchVersion`, and reloads subsystems.
    /// Automatically rolls back if `reloadAfterSwap` fails.
    UpdateResult commitStagedPatch(const std::string& patchVersion);

    /// Convenience helper running stagePatch() followed by commitStagedPatch().
    UpdateResult applyPatch(
        const PatchManifest& manifest,
        const StageProgressCallback& progressCb = nullptr);

    /// Atomically reverts `active_manifest.json` to the previous known-good
    /// overlay (or base Resources/ if no previous overlay exists).
    UpdateResult rollbackToPrevious();

    /// Removes abandoned staging directories and old releases beyond `keepCount`
    /// while preserving both `activeVersion` and `previousVersion` and skipping
    /// any release currently locked by another running Win32 instance.
    size_t pruneOldReleases(size_t keepCount = 2);

    /// Returns the currently persisted ActiveOverlayState (if any).
    std::optional<ActiveOverlayState> getActiveState() const;

    /// Returns the active overlay directory path if an overlay is active,
    /// otherwise returns std::nullopt (client uses base Resources/ only).
    std::optional<std::filesystem::path> getActiveOverlayPath() const;

    /// Serializes / parses ActiveOverlayState JSON (no external JSON dependency).
    static std::string serializeOverlayStateJson(const ActiveOverlayState& state);
    static bool parseOverlayStateJson(const std::string& json, ActiveOverlayState& outState);

    /// Cryptographic file hashing helpers (lowercase hex).
    static bool computeFileHash(
        const std::filesystem::path& filePath,
        HashAlgorithm algo,
        std::string& hexDigestOut,
        std::string& errorOut);

    /// Validates that a relative path from a manifest cannot escape staging/.
    static bool isSafeRelativePath(const std::string& relativePath);

    /// Compares dotted semantic versions ("major.minor.patch").
    /// Returns <0 if lhs < rhs, 0 if equal, >0 if lhs > rhs.
    static int compareSemver(const std::string& lhs, const std::string& rhs);

private:
    std::filesystem::path stagingRoot() const;
    std::filesystem::path releasesRoot() const;
    std::filesystem::path activeManifestPath() const;
    std::filesystem::path previousManifestPath() const;
    std::filesystem::path releaseDirForVersion(const std::string& version) const;

    bool ensureDirectoryLayout(std::string& errorOut) const;
    bool loadActiveStateLocked(ActiveOverlayState& outState) const;
    bool writeFileAtomically(
        const std::filesystem::path& targetPath,
        const std::string& contents,
        std::string& errorOut) const;
    bool probePathUnlockedWithRetry(
        const std::filesystem::path& path,
        std::string& errorOut) const;
    bool moveDirectoryAtomically(
        const std::filesystem::path& srcDir,
        const std::filesystem::path& dstDir,
        std::string& errorOut) const;

    static std::string currentUtcIso8601();
    static std::string generateStagingNonce();
    static std::string toLowerHex(const uint8_t* data, size_t len);
    static std::string toLowerAscii(std::string value);
    static bool isValidVersionToken(const std::string& version);

    class CrossProcessLock {
    public:
        explicit CrossProcessLock(const std::filesystem::path& patchRoot);
        ~CrossProcessLock();
        bool acquire(uint32_t timeoutMs, std::string& errorOut);
        void release();

    private:
        std::filesystem::path m_lockFilePath;
        std::string m_mutexName;
        bool m_acquired = false;
#ifdef _WIN32
        void* m_mutexHandle = nullptr;
#else
        int m_lockFd = -1;
#endif
    };

    HotUpdaterConfig m_config;
    ResourceHandleHooks m_hooks;
    DownloadTransport m_transport;
    mutable std::mutex m_mutex;
};

} // namespace update
} // namespace gclient
