#include "ui/ZYWebViewWin32.h"
#include "diagnostics/CrashAndTelemetry.h"

#ifdef _WIN32
#include <shellapi.h>
#ifdef GCLIENT_ENABLE_WEBVIEW2
#include <wrl.h>
#include "WebView2.h"
#endif
#endif

namespace gclient::ui {

ZYWebViewWin32* ZYWebViewWin32::getInstance() {
    static ZYWebViewWin32 instance;
    return &instance;
}

ZYWebViewWin32::~ZYWebViewWin32() {
    removeWebView();
}

#ifdef _WIN32
void ZYWebViewWin32::setParentWindow(HWND hwnd) {
    m_parentHwnd = hwnd;
}
#endif

void ZYWebViewWin32::displayWebView(int x, int y, int width, int height) {
    m_x = x;
    m_y = y;
    m_width = width;
    m_height = height;

#if defined(_WIN32) && defined(GCLIENT_ENABLE_WEBVIEW2)
    m_visible = true;
    if (!m_parentHwnd) {
        diagnostics::CrashAndTelemetry::log(
            diagnostics::LogLevel::Warn, "ZYWebViewWin32",
            "displayWebView called before parent HWND was bound.");
        return;
    }
    if (!m_hostHwnd) {
        m_hostHwnd = CreateWindowExW(
            0, L"STATIC", L"",
            WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
            m_x, m_y, m_width, m_height,
            m_parentHwnd, nullptr, GetModuleHandleW(nullptr), nullptr);
    } else {
        MoveWindow(m_hostHwnd, m_x, m_y, m_width, m_height, TRUE);
        ShowWindow(m_hostHwnd, SW_SHOW);
    }
#else
    // When GCLIENT_ENABLE_WEBVIEW2 is disabled, NEVER create an opaque WS_VISIBLE STATIC
    // child HWND over the OpenGL viewport (which would block rendering and mouse input).
    m_visible = false;
    diagnostics::CrashAndTelemetry::log(
        diagnostics::LogLevel::Info, "ZYWebViewWin32",
        "displayWebView(%d,%d,%d,%d): skipping child HWND creation (GCLIENT_ENABLE_WEBVIEW2 disabled).",
        m_x, m_y, m_width, m_height);
#endif
}

void ZYWebViewWin32::updateURL(const std::string& url) {
    m_currentUrl = url;
    if (url.empty()) return;

#ifdef _WIN32
#ifdef GCLIENT_ENABLE_WEBVIEW2
    // When WebView2 NuGet package is enabled in CMake, navigate the embedded controller here.
    diagnostics::CrashAndTelemetry::log(
        diagnostics::LogLevel::Info, "ZYWebViewWin32",
        "WebView2 navigating to: %s", url.c_str());
#else
    // Lightweight fallback: open in-game notice/help URL in the user's Windows browser.
    if (url.rfind("http://", 0) == 0 || url.rfind("https://", 0) == 0) {
        ShellExecuteA(m_parentHwnd, "open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    }
    diagnostics::CrashAndTelemetry::log(
        diagnostics::LogLevel::Info, "ZYWebViewWin32",
        "Opened URL in external browser (WebView2 disabled): %s", url.c_str());
#endif
#endif
}

void ZYWebViewWin32::removeWebView() {
    m_visible = false;
#ifdef _WIN32
    if (m_hostHwnd) {
        DestroyWindow(m_hostHwnd);
        m_hostHwnd = nullptr;
    }
#endif
}

void ZYWebViewWin32::onParentResized(int /*clientWidth*/, int /*clientHeight*/) {
#if defined(_WIN32) && defined(GCLIENT_ENABLE_WEBVIEW2)
    if (m_visible && m_hostHwnd) {
        MoveWindow(m_hostHwnd, m_x, m_y, m_width, m_height, TRUE);
    }
#endif
}

} // namespace gclient::ui
