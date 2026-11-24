#pragma once
#include <string>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#endif

namespace gclient::ui {

// Native Win32 replacement for org.go3k.utilities.ZYWebView.
// Hosts an embedded Microsoft Edge WebView2 child view ONLY when GCLIENT_ENABLE_WEBVIEW2 is defined
// and WebView2Loader is linked; otherwise falls back cleanly to opening URLs in the default
// Windows browser WITHOUT creating an opaque child HWND over the OpenGL viewport.
class ZYWebViewWin32 {
public:
    static ZYWebViewWin32* getInstance();

#ifdef _WIN32
    void setParentWindow(HWND hwnd);
#endif

    // Mirrors ZYWebView.displayWebView(x, y, width, height)
    void displayWebView(int x, int y, int width, int height);

    // Mirrors ZYWebView.updateURL(url)
    void updateURL(const std::string& url);

    // Mirrors ZYWebView.removeWebView()
    void removeWebView();

    // Reposition active overlay when the Win32 game window resizes
    void onParentResized(int clientWidth, int clientHeight);
    bool isVisible() const { return m_visible; }

    bool hasNativeHostWindow() const {
#ifdef _WIN32
        return m_hostHwnd != nullptr;
#else
        return false;
#endif
    }

    const std::string& currentUrl() const { return m_currentUrl; }

private:
    ZYWebViewWin32() = default;
    ~ZYWebViewWin32();

#ifdef _WIN32
    HWND m_parentHwnd = nullptr;
    HWND m_hostHwnd   = nullptr;
#endif
    int         m_x = 0;
    int         m_y = 0;
    int         m_width = 0;
    int         m_height = 0;
    bool        m_visible = false;
    std::string m_currentUrl;
};

} // namespace gclient::ui
