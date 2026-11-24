#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <cwchar>
#endif

#include "platform/VngAuthProvider.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

#include <curl/curl.h>
#include <openssl/evp.h>

namespace bt {

namespace {

namespace fs = std::filesystem;

constexpr const char* kDefaultVngGhk = "d345c6c5c29669eae007b682625fbf42";
constexpr const char* kDefaultGtsdkGameId = "OMG";
constexpr const char* kDefaultUserUrl = "https://pp.m.zing.vn";
constexpr const char* kDefaultGameVersion = "1.0.38";

std::string trimCopy(const std::string& s) {
    size_t b = 0;
    while (b < s.size() && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    size_t e = s.size();
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

std::string stripTrailingSlashes(std::string s) {
    s = trimCopy(s);
    while (!s.empty() && (s.back() == '/' || s.back() == '\\')) {
        s.pop_back();
    }
    return s;
}

std::string toLowerAsciiNormSlashes(std::string s) {
    for (char& ch : s) {
        if (ch == '\\') {
            ch = '/';
        } else {
            ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        }
    }
    while (!s.empty() && s.back() == '/') {
        s.pop_back();
    }
    return s;
}

#ifdef _WIN32
std::wstring utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return {};
    int req = ::MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    if (req <= 0) return {};
    std::wstring w(static_cast<size_t>(req), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), w.data(), req);
    return w;
}

std::string wideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int req = ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (req <= 0) return {};
    std::string u(static_cast<size_t>(req), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), u.data(), req, nullptr, nullptr);
    return u;
}

fs::path utf8ToFsPath(const std::string& utf8) {
    return fs::path(utf8ToWide(utf8));
}

std::string fsPathToUtf8(const fs::path& p) {
    return wideToUtf8(p.wstring());
}

std::string getWindowTextUtf8(HWND hwnd) {
    int len = ::GetWindowTextLengthW(hwnd);
    if (len <= 0) return {};
    std::wstring buf(static_cast<size_t>(len) + 1, L'\0');
    int copied = ::GetWindowTextW(hwnd, buf.data(), len + 1);
    if (copied <= 0) return {};
    buf.resize(static_cast<size_t>(copied));
    return trimCopy(wideToUtf8(buf));
}
#else
fs::path utf8ToFsPath(const std::string& utf8) {
    return fs::path(utf8);
}

std::string fsPathToUtf8(const fs::path& p) {
    return p.string();
}
#endif

std::string readEnvVar(const char* name) {
    if (!name || !*name) return {};
#ifdef _WIN32
    const std::wstring wName = utf8ToWide(name);
    if (!wName.empty()) {
        const DWORD needed = ::GetEnvironmentVariableW(wName.c_str(), nullptr, 0);
        if (needed > 1) {
            std::wstring wBuf(static_cast<size_t>(needed), L'\0');
            const DWORD wLen = ::GetEnvironmentVariableW(wName.c_str(), wBuf.data(), needed);
            if (wLen > 0 && wLen < needed) {
                wBuf.resize(wLen);
                return wideToUtf8(wBuf);
            }
        }
    }
#endif
    if (const char* v = std::getenv(name)) {
        return std::string(v);
    }
    return {};
}

bool isTruthyEnvFlag(const char* name) {
    const std::string val = trimCopy(readEnvVar(name));
    return val == "1" || val == "true" || val == "TRUE" || val == "yes" || val == "YES";
}

bool isValidHexTokenId(const std::string& s) {
    if (s.size() < 16 || s.size() > 64) return false;
    for (unsigned char ch : s) {
        if (!std::isalnum(ch) && ch != '-' && ch != '_') return false;
    }
    return true;
}

void ensureCurlGlobalInit() {
    static std::once_flag onceFlag;
    std::call_once(onceFlag, []() {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    });
}

void configureCurlTlsOptions(CURL* curl) {
    if (!curl) return;

#ifdef CURLSSLOPT_NATIVE_CA
    curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, static_cast<long>(CURLSSLOPT_NATIVE_CA));
#endif

    std::string caBundle = trimCopy(readEnvVar("GCLIENT_CA_BUNDLE"));
    if (caBundle.empty()) {
        caBundle = trimCopy(readEnvVar("CURL_CA_BUNDLE"));
    }
    if (!caBundle.empty()) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, caBundle.c_str());
    }

    if (isTruthyEnvFlag("GCLIENT_INSECURE_TLS")) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
}

std::string md5HexLower(const std::string& input) {
    unsigned char digest[EVP_MAX_MD_SIZE] = {};
    unsigned int dlen = 0;
    EVP_Digest(input.data(), input.size(), digest, &dlen, EVP_md5(), nullptr);
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(dlen * 2);
    for (unsigned int i = 0; i < dlen; ++i) {
        out[i * 2] = kHex[(digest[i] >> 4) & 0x0F];
        out[i * 2 + 1] = kHex[digest[i] & 0x0F];
    }
    return out;
}

std::string urlEncode(const std::string& in) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(in.size() * 3);
    for (unsigned char c : in) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(kHex[(c >> 4) & 0x0F]);
            out.push_back(kHex[c & 0x0F]);
        }
    }
    return out;
}

std::string extractJsonStringField(const std::string& json, const std::string& key) {
    const std::string pattern = "\"" + key + "\"";
    size_t pos = json.find(pattern);
    if (pos == std::string::npos) return {};
    pos = json.find(':', pos + pattern.size());
    if (pos == std::string::npos) return {};
    ++pos;
    while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos]))) ++pos;
    if (pos >= json.size()) return {};
    if (json[pos] == '"') {
        ++pos;
        std::string out;
        while (pos < json.size()) {
            char c = json[pos++];
            if (c == '\\' && pos < json.size()) {
                out.push_back(json[pos++]);
            } else if (c == '"') {
                break;
            } else {
                out.push_back(c);
            }
        }
        return out;
    }
    size_t end = pos;
    while (end < json.size() && json[end] != ',' && json[end] != '}' &&
           !std::isspace(static_cast<unsigned char>(json[end]))) {
        ++end;
    }
    std::string raw = json.substr(pos, end - pos);
    return (raw == "null") ? std::string() : raw;
}

std::string escapeJson(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else out.push_back(c);
    }
    return out;
}

VngAuthProvider::Config resolveEffectiveAuthConfig(const VngAuthProvider::Config& base) {
    VngAuthProvider::Config effective = base;
    if (effective.ghk.empty()) effective.ghk = kDefaultVngGhk;
    if (effective.gtsdkGameId.empty()) effective.gtsdkGameId = kDefaultGtsdkGameId;
    if (effective.userUrl.empty()) effective.userUrl = kDefaultUserUrl;
    if (effective.gameVersion.empty()) effective.gameVersion = kDefaultGameVersion;

    const std::string envGhk = trimCopy(readEnvVar("GCLIENT_VNG_GHK"));
    if (!envGhk.empty()) {
        effective.ghk = envGhk;
    }
    const std::string envUserUrl = stripTrailingSlashes(readEnvVar("GCLIENT_VNG_USER_URL"));
    if (!envUserUrl.empty()) {
        effective.userUrl = envUserUrl;
    } else {
        effective.userUrl = stripTrailingSlashes(effective.userUrl);
    }
    const std::string envGameVer = trimCopy(readEnvVar("GCLIENT_GAME_VERSION"));
    if (!envGameVer.empty()) {
        effective.gameVersion = envGameVer;
    }
    return effective;
}

std::string postQueryMap(const std::string& baseUrl,
                         const std::map<std::string, std::string>& params,
                         long* outHttpCode = nullptr,
                         std::string* outError = nullptr) {
    ensureCurlGlobalInit();
    if (outHttpCode) *outHttpCode = 0;
    if (outError) outError->clear();

    CURL* curl = curl_easy_init();
    if (!curl) {
        if (outError) *outError = "curl_easy_init failed";
        return {};
    }

    std::string fullUrl = baseUrl;
    bool first = (fullUrl.find('?') == std::string::npos);
    for (const auto& kv : params) {
        fullUrl.push_back(first ? '?' : '&');
        first = false;
        fullUrl += kv.first + "=" + urlEncode(kv.second);
    }

    std::string response;
    char errBuf[CURL_ERROR_SIZE] = {0};
    auto writeCb = +[](char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
        auto* buf = static_cast<std::string*>(userdata);
        buf->append(ptr, size * nmemb);
        return size * nmemb;
    };

    configureCurlTlsOptions(curl);
    curl_easy_setopt(curl, CURLOPT_URL, fullUrl.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "okhttp/3.10.0");
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errBuf);

    const CURLcode rc = curl_easy_perform(curl);
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    if (outHttpCode) *outHttpCode = httpCode;
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK) {
        if (outError) {
            std::string detail = (errBuf[0] != '\0') ? std::string(errBuf) : std::string(curl_easy_strerror(rc));
            detail += " (curl=" + std::to_string(static_cast<int>(rc)) +
                      ", http=" + std::to_string(httpCode) + ")";
            *outError = detail;
        }
        return {};
    }

    if (httpCode >= 400 && extractJsonStringField(response, "returnCode").empty()) {
        if (outError) {
            std::string detail = "HTTP " + std::to_string(httpCode);
            if (!response.empty()) {
                detail += ": " + trimCopy(response.substr(0, 160));
            }
            *outError = detail;
        }
        return {};
    }

    if (response.empty()) {
        if (outError) {
            *outError = "Empty HTTP response (status " + std::to_string(httpCode) + ")";
        }
        return {};
    }

    return response;
}

bool callVngZingAuth(const VngAuthProvider::Config& rawConfig,
                     const std::string& username,
                     const std::string& password,
                     AuthSession& outSession,
                     std::string& outError) {
    if (username.empty() || password.empty()) {
        outError = "Please enter both ZingID username and password.";
        return false;
    }

    const VngAuthProvider::Config cfg = resolveEffectiveAuthConfig(rawConfig);
    const std::string passMd5 = md5HexLower(password);
    const std::string ts = std::to_string(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    const std::string sig = md5HexLower(cfg.ghk + cfg.gtsdkGameId + username + passMd5 + ts);

    long httpCode = 0;
    std::string netErr;
    const std::string resp = postQueryMap(
        cfg.userUrl + "/api/login/auth/zing",
        {
            {"u", username},
            {"p", passMd5},
            {"timestamp", ts},
            {"sig", sig},
            {"gameID", cfg.gtsdkGameId},
            {"game_version", cfg.gameVersion},
            {"lang", "vi"},
            {"country_login", "VN"},
            {"country", "VN"},
            {"ver", "v2.0"}
        },
        &httpCode,
        &netErr);

    if (resp.empty()) {
        outError = "Network error contacting " + cfg.userUrl + ": " +
                   (netErr.empty() ? "no response" : netErr);
        return false;
    }
    const std::string rc = extractJsonStringField(resp, "returnCode");
    if (rc == "1" || rc == "2") {
        std::string uid = extractJsonStringField(resp, "userID");
        std::string sid = extractJsonStringField(resp, "sessionID");
        std::string acc = extractJsonStringField(resp, "accountName");
        if (!uid.empty() && !sid.empty()) {
            outSession.pid = uid;
            outSession.token = sid;
            outSession.username = acc.empty() ? username : acc;
            outSession.authenticated = true;
            return true;
        }
    }
    std::string msg = extractJsonStringField(resp, "message");
    outError = msg.empty() ? ("VNG auth failed (returnCode=" + rc + ")") : (msg + " (code " + rc + ")");
    return false;
}

bool callVngGuestAuth(const VngAuthProvider::Config& rawConfig,
                      const std::string& sessionFileHint,
                      AuthSession& outSession,
                      std::string& outError) {
    const VngAuthProvider::Config cfg = resolveEffectiveAuthConfig(rawConfig);
    const std::string ts = std::to_string(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    const std::string deviceId = VngAuthProvider::resolvePersistentDeviceId(sessionFileHint);
    const std::string sig = md5HexLower(cfg.ghk + cfg.gtsdkGameId + deviceId + ts);

    long httpCode = 0;
    std::string netErr;
    const std::string resp = postQueryMap(
        cfg.userUrl + "/api/login/createUser/guest",
        {
            {"deviceID", deviceId},
            {"timestamp", ts},
            {"sig", sig},
            {"gameID", cfg.gtsdkGameId},
            {"game_version", cfg.gameVersion},
            {"lang", "vi"},
            {"country", "VN"},
            {"ver", "v2.0"}
        },
        &httpCode,
        &netErr);

    if (resp.empty()) {
        outError = "Network error contacting " + cfg.userUrl + ": " +
                   (netErr.empty() ? "no response" : netErr);
        return false;
    }
    const std::string rc = extractJsonStringField(resp, "returnCode");
    if (rc == "1" || rc == "2") {
        std::string uid = extractJsonStringField(resp, "userID");
        std::string sid = extractJsonStringField(resp, "sessionID");
        if (!uid.empty() && !sid.empty()) {
            outSession.pid = uid;
            outSession.token = sid;
            outSession.username = "Guest";
            outSession.authenticated = true;
            return true;
        }
    }
    std::string msg = extractJsonStringField(resp, "message");
    outError = msg.empty() ? ("VNG guest failed (returnCode=" + rc + ")") : (msg + " (code " + rc + ")");
    return false;
}

#ifdef _WIN32
enum ControlIds {
    kIdUserEdit = 1001,
    kIdPassEdit = 1002,
    kIdBtnZing  = 1003,
    kIdBtnGuest = 1004,
    kIdPidEdit  = 1005,
    kIdTokEdit  = 1006,
    kIdBtnPid   = 1007,
    kIdBtnStub  = 1008,
    kIdStatus   = 1009,
    kIdBtnClear = 1010,
};

struct LoginDialogState {
    HWND hwnd = nullptr;
    HWND userEdit = nullptr;
    HWND passEdit = nullptr;
    HWND pidEdit = nullptr;
    HWND tokEdit = nullptr;
    HWND statusLabel = nullptr;
    HFONT font = nullptr;
    bool completed = false;
    bool cancelled = false;
    AuthSession session;
    VngAuthProvider* provider = nullptr;
    VngAuthProvider::Config authConfig;
    const std::atomic<bool>* cancelFlag = nullptr;
};

LRESULT CALLBACK loginWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* st = reinterpret_cast<LoginDialogState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_CREATE: {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        st = static_cast<LoginDialogState*>(cs->lpCreateParams);
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(st));
        st->hwnd = hwnd;

        st->font = ::CreateFontW(
            -14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

        auto makeCtrl = [&](const wchar_t* cls, const wchar_t* text, DWORD style, int x, int y, int w, int h, int id) -> HWND {
            HWND c = ::CreateWindowExW(
                (std::wcscmp(cls, L"EDIT") == 0) ? WS_EX_CLIENTEDGE : 0,
                cls, text, WS_CHILD | WS_VISIBLE | style,
                x, y, w, h, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                ::GetModuleHandleW(nullptr), nullptr);
            if (c && st->font) {
                ::SendMessageW(c, WM_SETFONT, reinterpret_cast<WPARAM>(st->font), TRUE);
            }
            return c;
        };

        makeCtrl(L"STATIC", L"ZingID Username:", 0, 16, 14, 140, 20, 0);
        st->userEdit = makeCtrl(L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL, 16, 36, 372, 24, kIdUserEdit);

        makeCtrl(L"STATIC", L"Password:", 0, 16, 68, 140, 20, 0);
        st->passEdit = makeCtrl(L"EDIT", L"", WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL, 16, 90, 372, 24, kIdPassEdit);

        makeCtrl(L"BUTTON", L"Sign In (ZingID)", WS_TABSTOP | BS_DEFPUSHBUTTON, 16, 124, 180, 30, kIdBtnZing);
        makeCtrl(L"BUTTON", L"Guest Login (VNG)", WS_TABSTOP, 208, 124, 180, 30, kIdBtnGuest);

        makeCtrl(L"STATIC", L"--- Or enter existing VNG PID & Session Token ---", 0, 16, 166, 372, 20, 0);
        makeCtrl(L"STATIC", L"VNG PID / UID:", 0, 16, 190, 140, 20, 0);
        st->pidEdit = makeCtrl(L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL, 16, 212, 372, 24, kIdPidEdit);

        makeCtrl(L"STATIC", L"Session Token:", 0, 16, 244, 140, 20, 0);
        st->tokEdit = makeCtrl(L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL, 16, 266, 372, 24, kIdTokEdit);

        makeCtrl(L"BUTTON", L"Use PID & Token", WS_TABSTOP, 16, 300, 180, 30, kIdBtnPid);
        makeCtrl(L"BUTTON", L"Quick Offline Guest", WS_TABSTOP, 208, 300, 180, 30, kIdBtnStub);
        makeCtrl(L"BUTTON", L"Clear Saved Session", WS_TABSTOP, 16, 336, 372, 28, kIdBtnClear);

        st->statusLabel = makeCtrl(L"STATIC", L"Ready.", 0, 16, 372, 372, 42, kIdStatus);
        ::SetFocus(st->userEdit);
        return 0;
    }
    case WM_COMMAND: {
        if (!st) break;
        const int id = LOWORD(wParam);
        if (id == kIdBtnZing) {
            std::string u = getWindowTextUtf8(st->userEdit);
            std::string p = getWindowTextUtf8(st->passEdit);
            ::SetWindowTextW(st->statusLabel, L"Signing in via VNG ZingID...");
            std::string err;
            if (callVngZingAuth(st->authConfig, u, p, st->session, err)) {
                st->completed = true;
                ::DestroyWindow(hwnd);
            } else {
                ::SetWindowTextW(st->statusLabel, utf8ToWide(err).c_str());
            }
            return 0;
        }
        if (id == kIdBtnGuest) {
            ::SetWindowTextW(st->statusLabel, L"Creating VNG guest session...");
            std::string err;
            const std::string sessHint = st->provider ? st->provider->resolveSessionFilePath()
                                                      : VngAuthProvider::defaultSessionFile();
            if (callVngGuestAuth(st->authConfig, sessHint, st->session, err)) {
                st->completed = true;
                ::DestroyWindow(hwnd);
            } else {
                ::SetWindowTextW(st->statusLabel, utf8ToWide(err).c_str());
            }
            return 0;
        }
        if (id == kIdBtnPid) {
            std::string pid = getWindowTextUtf8(st->pidEdit);
            std::string tok = getWindowTextUtf8(st->tokEdit);
            if (pid.empty() || tok.empty()) {
                ::SetWindowTextW(st->statusLabel, L"Please enter both VNG PID and Session Token.");
                return 0;
            }
            st->session.pid = pid;
            st->session.token = tok;
            st->session.username = pid;
            st->session.authenticated = true;
            st->completed = true;
            ::DestroyWindow(hwnd);
            return 0;
        }
        if (id == kIdBtnStub) {
            st->session.pid = "win32_guest_0001";
            st->session.token = "win32_guest_token";
            st->session.username = "Win32Player";
            st->session.authenticated = true;
            st->completed = true;
            ::DestroyWindow(hwnd);
            return 0;
        }
        if (id == kIdBtnClear) {
            if (st->provider) {
                st->provider->clearCachedSession();
            }
            VngAuthProvider::purgePoisonedLocalAppDataSession();
            ::SetWindowTextW(st->statusLabel, L"Cleared cached VNG session files.");
            return 0;
        }
        break;
    }
    case WM_CLOSE:
        if (st) st->cancelled = true;
        ::DestroyWindow(hwnd);
        return 0;
    case WM_TIMER:
        if (st && st->cancelFlag && st->cancelFlag->load()) {
            st->cancelled = true;
            ::DestroyWindow(hwnd);
        }
        return 0;
    case WM_DESTROY:
        ::KillTimer(hwnd, 1);
        if (st && st->font) {
            ::DeleteObject(st->font);
            st->font = nullptr;
        }
        ::PostQuitMessage(0);
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool showNativeWin32LoginDialog(VngAuthProvider* provider,
                                const VngAuthProvider::Config& authConfig,
                                AuthSession& outSession,
                                std::string& outError,
                                const std::atomic<bool>& cancelFlag) {
    static const wchar_t* kClassName = L"GCLIENT_VngLoginDialog";
    HINSTANCE hInst = ::GetModuleHandleW(nullptr);

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = loginWndProc;
    wc.hInstance = hInst;
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = kClassName;
    ::RegisterClassExW(&wc);

    LoginDialogState state;
    state.provider = provider;
    state.authConfig = authConfig;
    state.cancelFlag = &cancelFlag;

    RECT rc{0, 0, 404, 424};
    DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU;
    ::AdjustWindowRect(&rc, style, FALSE);
    const int winW = rc.right - rc.left;
    const int winH = rc.bottom - rc.top;
    const int screenW = ::GetSystemMetrics(SM_CXSCREEN);
    const int screenH = ::GetSystemMetrics(SM_CYSCREEN);

    HWND hwnd = ::CreateWindowExW(
        WS_EX_TOPMOST,
        kClassName,
        L"Win32 Client - VNG Sign In",
        style | WS_VISIBLE,
        (screenW - winW) / 2,
        (screenH - winH) / 2,
        winW,
        winH,
        nullptr,
        nullptr,
        hInst,
        &state);

    if (!hwnd) {
        outError = "Failed to create Win32 login dialog.";
        return false;
    }

    ::SetTimer(hwnd, 1, 100, nullptr);
    ::SetForegroundWindow(hwnd);

    MSG msg{};
    while (!cancelFlag.load() && ::GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (!::IsDialogMessageW(hwnd, &msg)) {
            ::TranslateMessage(&msg);
            ::DispatchMessageW(&msg);
        }
    }

    if (cancelFlag.load() && ::IsWindow(hwnd)) {
        ::DestroyWindow(hwnd);
    }

    if (state.completed) {
        outSession = state.session;
        return true;
    }
    outError = cancelFlag.load() ? "Login cancelled" : "Login window closed";
    return false;
}
#endif

std::mutex& workerThreadLifecycleMutex() {
    static std::mutex s_workerMutex;
    return s_workerMutex;
}

} // namespace

bool VngAuthProvider::isOfflineStubToken(const std::string& tok) {
    return tok.empty() || tok == "win32_guest_token" || tok == "local_stub_session_token";
}

bool VngAuthProvider::isEphemeralPidInstancePath(const std::string& path) {
    if (path.empty()) return false;
    const std::string norm = toLowerAsciiNormSlashes(path);
    return norm.find("/instances/pid_") != std::string::npos ||
           norm.find("instances/pid_") == 0;
}

std::string VngAuthProvider::defaultSessionFile() {
    // 1. Explicit file override (set by --profile-dir, secondary instance_N slot, or user env).
    const std::string envOverride = trimCopy(readEnvVar("GCLIENT_SESSION_FILE"));
    if (!envOverride.empty()) {
        return envOverride;
    }

    const std::string localAppData = trimCopy(readEnvVar("LOCALAPPDATA"));
    const std::string normAppDataRoot = localAppData.empty()
        ? std::string()
        : toLowerAsciiNormSlashes(fsPathToUtf8(utf8ToFsPath(localAppData) / "GCLIENT"));

    auto isDefaultPrimarySlotPath = [&](const std::string& dir) -> bool {
        if (dir.empty()) return false;
        if (isEphemeralPidInstancePath(dir)) return true;
        if (normAppDataRoot.empty()) return false;
        const std::string normDir = toLowerAsciiNormSlashes(dir);
        return normDir == (normAppDataRoot + "/profiles/default") ||
               normDir == (normAppDataRoot + "/profiles/default/writable");
    };

    // 2. Non-ephemeral custom profile directory (e.g., --profile-dir or secondary instance_2+ slot).
    const std::string profileDir = trimCopy(readEnvVar("GCLIENT_PROFILE_DIR"));
    if (!profileDir.empty() && !isDefaultPrimarySlotPath(profileDir)) {
        return fsPathToUtf8(utf8ToFsPath(profileDir) / "vng_session.json");
    }

    // 3. Non-ephemeral custom writable directory (e.g., isolated test or custom portable dir).
    const std::string writableDir = trimCopy(readEnvVar("GCLIENT_WRITABLE_DIR"));
    if (!writableDir.empty() && !isDefaultPrimarySlotPath(writableDir)) {
        return fsPathToUtf8(utf8ToFsPath(writableDir) / "vng_session.json");
    }

    // 4. Persistent user-level %LOCALAPPDATA%/GCLIENT/vng_session.json across launches.
    if (!localAppData.empty()) {
        return fsPathToUtf8(utf8ToFsPath(localAppData) / "GCLIENT" / "vng_session.json");
    }

    return "vng_session.json";
}

std::string VngAuthProvider::resolvePersistentDeviceId(const std::string& sessionFileHint) {
    fs::path uuidPath;
    const std::string envUuidFile = trimCopy(readEnvVar("GCLIENT_UUID_FILE"));
    if (!envUuidFile.empty()) {
        uuidPath = utf8ToFsPath(envUuidFile);
    } else {
        const std::string sessFile = sessionFileHint.empty() ? defaultSessionFile() : sessionFileHint;
        const fs::path sessPath = utf8ToFsPath(sessFile);
        if (sessPath.has_parent_path()) {
            uuidPath = sessPath.parent_path() / "device_uuid.txt";
        } else {
            uuidPath = fs::path("device_uuid.txt");
        }
    }

    std::error_code ec;
    if (fs::is_regular_file(uuidPath, ec)) {
        std::ifstream ifs(uuidPath, std::ios::binary);
        if (ifs.is_open()) {
            std::string existing;
            std::getline(ifs, existing);
            existing = trimCopy(existing);
            if (isValidHexTokenId(existing)) {
                return existing;
            }
        }
    }

    const auto nowNs = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    const std::string generated = md5HexLower(
        "gclient_win32_device_" + std::to_string(nowNs) + "_" + fsPathToUtf8(uuidPath));

    if (uuidPath.has_parent_path()) {
        fs::create_directories(uuidPath.parent_path(), ec);
    }
    std::ofstream ofs(uuidPath, std::ios::binary | std::ios::trunc);
    if (ofs.is_open()) {
        ofs << generated << "\n";
    }
    return generated;
}

bool VngAuthProvider::purgePoisonedLocalAppDataSession() {
    const std::string localAppData = trimCopy(readEnvVar("LOCALAPPDATA"));
    if (localAppData.empty()) return false;

    const fs::path legacyPath = utf8ToFsPath(localAppData) / "GCLIENT" / "vng_session.json";
    std::error_code ec;
    if (!fs::is_regular_file(legacyPath, ec)) {
        return false;
    }

    std::string json;
    {
        std::ifstream ifs(legacyPath, std::ios::binary);
        if (!ifs.is_open()) return false;
        std::ostringstream oss;
        oss << ifs.rdbuf();
        json = oss.str();
    }

    const std::string tok = extractJsonStringField(json, "token");
    if (isOfflineStubToken(tok)) {
        fs::remove(legacyPath, ec);
        return !ec;
    }
    return false;
}

VngAuthProvider::VngAuthProvider() {
    purgePoisonedLocalAppDataSession();
}

VngAuthProvider::VngAuthProvider(Config config) : config_(std::move(config)) {
    purgePoisonedLocalAppDataSession();
}

VngAuthProvider::~VngAuthProvider() {
    cancelPendingLogin();
}

VngAuthProvider::Config VngAuthProvider::getConfig() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

std::string VngAuthProvider::resolveSessionFilePath() const {
    std::string explicitPath;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        explicitPath = config_.sessionFilePath;
    }
    if (!explicitPath.empty()) {
        return explicitPath;
    }
    return defaultSessionFile();
}

void VngAuthProvider::cancelPendingLogin() {
    cancelRequested_.store(true);
    std::thread toJoin;
    {
        std::lock_guard<std::mutex> workerLock(workerThreadLifecycleMutex());
        if (workerThread_.joinable()) {
            if (workerThread_.get_id() == std::this_thread::get_id()) {
                // Avoid resource_deadlock_would_occur if invoked from workerThread_ itself.
                workerThread_.detach();
            } else {
                toJoin = std::move(workerThread_);
            }
        }
    }
    if (toJoin.joinable()) {
        toJoin.join();
    }
    loginInProgress_.store(false);
    cancelRequested_.store(false);
}

bool VngAuthProvider::initialize(const std::map<std::string, std::string>& initParams) {
    purgePoisonedLocalAppDataSession();
    std::lock_guard<std::mutex> lock(mutex_);

    auto pickFirst = [&](std::initializer_list<const char*> keys, std::string& target) {
        for (const char* k : keys) {
            auto it = initParams.find(k);
            if (it != initParams.end() && !trimCopy(it->second).empty()) {
                target = trimCopy(it->second);
                return;
            }
        }
    };

    pickFirst({"gn"}, config_.gameId);
    pickFirst({"vng_auth_url"}, config_.authorizeUrl);
    pickFirst({"vng_token_url"}, config_.tokenUrl);
    pickFirst({"ghk", "appKey", "app_key", "vng_ghk"}, config_.ghk);
    pickFirst({"gameID", "gtsdk_game_id"}, config_.gtsdkGameId);
    pickFirst({"userUrl", "user_url", "vng_user_url"}, config_.userUrl);
    pickFirst({"game_version", "gameVersion"}, config_.gameVersion);
    pickFirst({"vng_session_file"}, config_.sessionFilePath);

    initialized_ = true;
    return true;
}

bool VngAuthProvider::authenticateWithZingId(const std::string& username,
                                             const std::string& password,
                                             AuthSession& outSession,
                                             std::string& outError) {
    if (!callVngZingAuth(getConfig(), username, password, outSession, outError)) {
        return false;
    }
    if (!isOfflineStubToken(outSession.token)) {
        saveCachedSession(outSession);
    }
    std::lock_guard<std::mutex> lock(mutex_);
    session_ = outSession;
    return true;
}

bool VngAuthProvider::authenticateAsVngGuest(AuthSession& outSession,
                                             std::string& outError) {
    if (!callVngGuestAuth(getConfig(), resolveSessionFilePath(), outSession, outError)) {
        return false;
    }
    if (!isOfflineStubToken(outSession.token)) {
        saveCachedSession(outSession);
    }
    std::lock_guard<std::mutex> lock(mutex_);
    session_ = outSession;
    return true;
}

void VngAuthProvider::login(AuthCallback onComplete) {
    bool expected = false;
    if (!loginInProgress_.compare_exchange_strong(expected, true)) {
        return;
    }

    purgePoisonedLocalAppDataSession();

    // 1. Check explicit environment variable override (for CI / automated testing / launcher injection)
    const std::string envPid = trimCopy(readEnvVar("GCLIENT_VNG_PID"));
    const std::string envTok = trimCopy(readEnvVar("GCLIENT_VNG_TOKEN"));
    if (!envPid.empty() && !envTok.empty()) {
        AuthResult res;
        res.success = true;
        res.session.pid = envPid;
        res.session.token = envTok;
        res.session.username = envPid;
        res.session.authenticated = true;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            session_ = res.session;
        }
        loginInProgress_.store(false);
        enqueueResult(std::move(onComplete), res);
        return;
    }

    // 2. Check cached persistent session (auto-purging any offline stub token)
    AuthSession cached;
    if (tryLoadCachedSession(cached)) {
        AuthResult res;
        res.success = true;
        res.fromCache = true;
        res.session = cached;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            session_ = cached;
        }
        loginInProgress_.store(false);
        enqueueResult(std::move(onComplete), res);
        return;
    }

#ifdef _WIN32
    // 3. Reclaim any completed previous UI worker thread safely before spawning a new dialog thread
    {
        std::thread staleWorker;
        {
            std::lock_guard<std::mutex> workerLock(workerThreadLifecycleMutex());
            if (workerThread_.joinable()) {
                if (workerThread_.get_id() == std::this_thread::get_id()) {
                    workerThread_.detach();
                } else {
                    staleWorker = std::move(workerThread_);
                }
            }
        }
        if (staleWorker.joinable()) {
            staleWorker.join();
        }
    }
    cancelRequested_.store(false);

    const Config cfgSnapshot = getConfig();
    std::thread nextWorker([this, cfgSnapshot, cb = std::move(onComplete)]() mutable {
        AuthResult result;
        AuthSession sess;
        std::string err;
        if (showNativeWin32LoginDialog(this, cfgSnapshot, sess, err, cancelRequested_)) {
            result.success = true;
            result.fromCache = false;
            result.session = sess;
            if (!isOfflineStubToken(sess.token)) {
                saveCachedSession(sess);
            }
            std::lock_guard<std::mutex> lock(mutex_);
            session_ = sess;
        } else {
            result.success = false;
            result.errorCode = cancelRequested_.load() ? -3 : -2;
            result.errorMessage = err;
        }
        loginInProgress_.store(false);
        enqueueResult(std::move(cb), result);
    });

    {
        std::lock_guard<std::mutex> workerLock(workerThreadLifecycleMutex());
        if (workerThread_.joinable()) {
            if (workerThread_.get_id() == std::this_thread::get_id()) {
                workerThread_.detach();
            } else {
                workerThread_.join();
            }
        }
        workerThread_ = std::move(nextWorker);
    }
#else
    loginInProgress_.store(false);
    AuthResult res;
    res.success = false;
    res.errorCode = -2;
    res.errorMessage = "Native Win32 login dialog unavailable on non-Win32 host";
    enqueueResult(std::move(onComplete), res);
#endif
}

void VngAuthProvider::logout(LogoutCallback onComplete) {
    cancelPendingLogin();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        session_ = AuthSession{};
    }
    clearCachedSession();
    purgePoisonedLocalAppDataSession();
    if (onComplete) {
        onComplete(true);
    }
}

bool VngAuthProvider::isAuthenticated() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return session_.authenticated;
}

AuthSession VngAuthProvider::currentSession() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return session_;
}

void VngAuthProvider::poll() {
    std::deque<std::pair<AuthCallback, AuthResult>> batch;
    {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        batch.swap(pendingCallbacks_);
    }
    for (auto& item : batch) {
        if (item.first) {
            item.first(item.second);
        }
    }
}

void VngAuthProvider::enqueueResult(AuthCallback cb, AuthResult res) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    pendingCallbacks_.emplace_back(std::move(cb), std::move(res));
}

bool VngAuthProvider::tryLoadCachedSession(AuthSession& outSession) const {
    const std::string path = resolveSessionFilePath();
    if (path.empty()) return false;

    const fs::path fsPath = utf8ToFsPath(path);
    std::error_code ec;
    if (!fs::is_regular_file(fsPath, ec)) {
        return false;
    }

    std::string json;
    {
        std::ifstream ifs(fsPath, std::ios::binary);
        if (!ifs.is_open()) return false;
        std::ostringstream oss;
        oss << ifs.rdbuf();
        json = oss.str();
    }

    std::string pid = extractJsonStringField(json, "pid");
    std::string token = extractJsonStringField(json, "token");
    std::string username = extractJsonStringField(json, "username");

    if (isOfflineStubToken(token) || pid.empty()) {
        fs::remove(fsPath, ec);
        return false;
    }

    outSession.pid = pid;
    outSession.token = token;
    outSession.username = username.empty() ? pid : username;
    outSession.authenticated = true;
    return true;
}

void VngAuthProvider::saveCachedSession(const AuthSession& session) const {
    if (session.pid.empty() || isOfflineStubToken(session.token)) {
        return;
    }

    const std::string path = resolveSessionFilePath();
    if (path.empty()) return;

    std::error_code ec;
    const fs::path p = utf8ToFsPath(path);
    if (p.has_parent_path()) {
        fs::create_directories(p.parent_path(), ec);
    }
    std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open()) return;
    ofs << "{\"pid\":\"" << escapeJson(session.pid)
        << "\",\"token\":\"" << escapeJson(session.token)
        << "\",\"username\":\"" << escapeJson(session.username) << "\"}\n";
    ofs.flush();
}

void VngAuthProvider::clearCachedSession() const {
    const std::string path = resolveSessionFilePath();
    if (!path.empty()) {
        std::error_code ec;
        fs::remove(utf8ToFsPath(path), ec);
    }
}

} // namespace bt
