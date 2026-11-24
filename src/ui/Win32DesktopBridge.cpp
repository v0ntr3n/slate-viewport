#include "ui/Win32DesktopBridge.h"
#include "ui/ZYWebViewWin32.h"
#include "platform/BtPlatformWin32.h"
#include "SimpleAudioEngine.h"

#ifdef _WIN32
#include <commdlg.h>
#endif

namespace gclient::ui {

Win32DesktopBridge& Win32DesktopBridge::instance() {
    static Win32DesktopBridge s;
    return s;
}

#ifdef _WIN32
void Win32DesktopBridge::attachToWindow(HWND hwnd) {
    if (!hwnd || m_hwnd == hwnd) return;
    m_hwnd = hwnd;
    m_savedPlacement.length = sizeof(WINDOWPLACEMENT);
    ZYWebViewWin32::getInstance()->setParentWindow(hwnd);
    m_origProc = reinterpret_cast<WNDPROC>(
        SetWindowLongPtrW(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&Win32DesktopBridge::subclassProc)));
}

void Win32DesktopBridge::detach() {
    if (m_hwnd && m_origProc) {
        SetWindowLongPtrW(m_hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(m_origProc));
    }
    m_hwnd = nullptr;
    m_origProc = nullptr;
}

LRESULT CALLBACK Win32DesktopBridge::subclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto& self = Win32DesktopBridge::instance();
    switch (msg) {
        case WM_KEYDOWN:
            if (wParam == VK_ESCAPE) {
                if (auto* p = bt::Platform::getInstance()) {
                    p->onPressBack();
                }
                return 0;
            }
            if (wParam == VK_F11) {
                self.toggleFullscreen();
                return 0;
            }
            if (wParam == 'M' && (GetKeyState(VK_CONTROL) & 0x8000)) {
                self.toggleMute();
                return 0;
            }
            break;
        case WM_SIZE:
            ZYWebViewWin32::getInstance()->onParentResized(LOWORD(lParam), HIWORD(lParam));
            break;
        default:
            break;
    }
    return CallWindowProcW(self.m_origProc, hwnd, msg, wParam, lParam);
}
#endif

void Win32DesktopBridge::toggleFullscreen() {
#ifdef _WIN32
    if (!m_hwnd) return;
    DWORD style = static_cast<DWORD>(GetWindowLongW(m_hwnd, GWL_STYLE));
    if (!m_fullscreen) {
        MONITORINFO mi = { sizeof(mi) };
        if (GetWindowPlacement(m_hwnd, &m_savedPlacement) &&
            GetMonitorInfoW(MonitorFromWindow(m_hwnd, MONITOR_DEFAULTTOPRIMARY), &mi)) {
            SetWindowLongW(m_hwnd, GWL_STYLE, style & ~WS_OVERLAPPEDWINDOW);
            SetWindowPos(m_hwnd, HWND_TOP,
                mi.rcMonitor.left, mi.rcMonitor.top,
                mi.rcMonitor.right - mi.rcMonitor.left,
                mi.rcMonitor.bottom - mi.rcMonitor.top,
                SWP_NOOWNERZORDER | SWP_FRAMECHANGED);
            m_fullscreen = true;
        }
    } else {
        SetWindowLongW(m_hwnd, GWL_STYLE, style | WS_OVERLAPPEDWINDOW);
        SetWindowPlacement(m_hwnd, &m_savedPlacement);
        SetWindowPos(m_hwnd, nullptr, 0, 0, 0, 0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOOWNERZORDER | SWP_FRAMECHANGED);
        m_fullscreen = false;
    }
#endif
}

void Win32DesktopBridge::toggleMute() {
    m_muted = !m_muted;
    auto* audio = CocosDenshion::SimpleAudioEngine::sharedEngine();
    if (audio) {
        audio->setBackgroundMusicVolume(m_muted ? 0.0f : 1.0f);
        audio->setEffectsVolume(m_muted ? 0.0f : 1.0f);
    }
}

std::string Win32DesktopBridge::pickImageFileDialog() {
#ifdef _WIN32
    char fileBuf[MAX_PATH] = {0};
    OPENFILENAMEA ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = m_hwnd;
    ofn.lpstrFilter = "Images (*.png;*.jpg;*.jpeg)\0*.png;*.jpg;*.jpeg\0All Files\0*.*\0";
    ofn.lpstrFile = fileBuf;
    ofn.nMaxFile = sizeof(fileBuf);
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (GetOpenFileNameA(&ofn)) {
        return std::string(fileBuf);
    }
#endif
    return "";
}

} // namespace gclient::ui
