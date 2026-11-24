#pragma once
#include <string>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#endif

namespace gclient::ui {

// Native Win32 desktop playability bridge:
// - Maps Escape -> Android Back button (bt::Platform::onPressBack)
// - Maps F11    -> Borderless fullscreen toggle
// - Maps M      -> Audio mute toggle
// - Preserves 1136x640 aspect ratio on resize and notifies ZYWebViewWin32
// - Provides a simple native Win32 modal prompt for local/broker account login
class Win32DesktopBridge {
public:
    static Win32DesktopBridge& instance();

#ifdef _WIN32
    void attachToWindow(HWND hwnd);
    void detach();
#endif

    void toggleFullscreen();
    void toggleMute();
    bool isMuted() const { return m_muted; }

    // Native Win32 file picker replacement for GameTemplate.GetImageFromGallery
    std::string pickImageFileDialog();

private:
    Win32DesktopBridge() = default;

#ifdef _WIN32
    static LRESULT CALLBACK subclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    HWND    m_hwnd = nullptr;
    WNDPROC m_origProc = nullptr;
    WINDOWPLACEMENT m_savedPlacement{};
#endif
    bool m_fullscreen = false;
    bool m_muted = false;
};

} // namespace gclient::ui
