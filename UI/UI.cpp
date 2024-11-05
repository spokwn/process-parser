#include "UI.h"
#include "../ProcessParser/string_parser.h"
#include "../ProcessParser/process_strings.h"
#include "font.h"
#include "..\rules\yara.h"
#include <thread>

std::vector<GenericRule> genericRules;

LPDIRECT3D9 UI::g_pD3D = nullptr;
LPDIRECT3DDEVICE9 UI::g_pd3dDevice = nullptr;
D3DPRESENT_PARAMETERS UI::g_d3dpp = {};
HWND UI::hwnd = nullptr;
WNDCLASSEX UI::wc = {};

bool UI::CreateDeviceD3D() {
    g_pD3D = Direct3DCreate9(D3D_SDK_VERSION);
    if (g_pD3D == nullptr) return false;

    ZeroMemory(&g_d3dpp, sizeof(g_d3dpp));
    g_d3dpp.Windowed = TRUE;
    g_d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    g_d3dpp.BackBufferFormat = D3DFMT_UNKNOWN;
    g_d3dpp.EnableAutoDepthStencil = TRUE;
    g_d3dpp.AutoDepthStencilFormat = D3DFMT_D16;
    g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_ONE;

    if (g_pD3D->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hwnd,
        D3DCREATE_HARDWARE_VERTEXPROCESSING, &g_d3dpp, &g_pd3dDevice) < 0)
        return false;

    return true;
}

void UI::CleanupDeviceD3D() {
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
    if (g_pD3D) { g_pD3D->Release(); g_pD3D = nullptr; }
}

void UI::ResetDevice() {
    ImGui_ImplDX9_InvalidateDeviceObjects();
    HRESULT hr = g_pd3dDevice->Reset(&g_d3dpp);
    if (hr == D3DERR_INVALIDCALL)
        IM_ASSERT(0);
    ImGui_ImplDX9_CreateDeviceObjects();
}

LRESULT WINAPI UI::WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg) {
    case WM_SIZE:
        if (g_pd3dDevice != nullptr && wParam != SIZE_MINIMIZED) {
            g_d3dpp.BackBufferWidth = LOWORD(lParam);
            g_d3dpp.BackBufferHeight = HIWORD(lParam);
            ResetDevice();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU)
            return 0;
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

bool UI::Initialize() {
    wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, _T("Process Parser"), nullptr };
    RegisterClassEx(&wc);

    hwnd = CreateWindow(wc.lpszClassName, _T("Process Parser"), WS_OVERLAPPEDWINDOW, 100, 100, 800, 600, nullptr, nullptr, wc.hInstance, nullptr);
    if (!CreateDeviceD3D()) {
        CleanupDeviceD3D();
        UnregisterClass(wc.lpszClassName, wc.hInstance);
        return false;
    }

    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    ImGui::StyleColorsDark();

    ImFontConfig CustomFont;
    CustomFont.FontDataOwnedByAtlas = false;
    io.Fonts->AddFontFromMemoryTTF((void*)Custom.data(), (int)Custom.size(), 17.5f, &CustomFont);
    io.Fonts->AddFontDefault();

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX9_Init(g_pd3dDevice);

    return true;
}

bool UI::ShouldClose() {
    MSG msg;
    while (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
        if (msg.message == WM_QUIT)
            return true;
    }
    return false;
}

void UI::BeginFrame() {
    ImGui_ImplDX9_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
    ImGui::Begin("##MainWindow", nullptr,
        ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoCollapse);

    // Add padding
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20, 20));
}


struct PathInfo {
    std::string path;
    std::string signature;
    std::vector<std::string> matched_rules;
};

static std::vector<PathInfo> pathInfos;
static bool dumpFinished = false;

void DumpDiagTrack() {
    STRING_OPTIONS options;
    options.pagination = false;
    options.ecoMode = false;
    options.printAsciiOnly = false;
    options.printUnicodeOnly = false;
    options.printNormal = true;
    options.minCharacters = 24;

    auto parser = std::make_unique<string_parser>(options);
    auto process = std::make_unique<process_strings>(parser.get());
    process->dump_process(process::getInstance()->getDiagtrackPID(), false, false, "DiagTrack");
    dumpFinished = true;
}

void DumpAppInfo() {
    STRING_OPTIONS options;
    options.pagination = false;
    options.ecoMode = false;
    options.printAsciiOnly = false;
    options.printUnicodeOnly = false;
    options.printNormal = true;
    options.minCharacters = 5;

    auto parser = std::make_unique<string_parser>(options);
    auto process = std::make_unique<process_strings>(parser.get());
    process->dump_process(process::getInstance()->getAppInfoPID(), false, false, "AppInfo");
    dumpFinished = true;
}
void ProcessPaths() {
    while (!dumpFinished) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    pathInfos.clear();

    for (const auto& path : processedPaths) {
        PathInfo info;
        info.path = path;
        info.signature = getDigitalSignature(path);
        if (info.signature != "Deleted" && info.signature != "Signed") {
            std::vector<std::string> matched_rules;
            if (scan_with_yara(path, matched_rules)) {
                info.matched_rules = matched_rules;
            }
        }

        pathInfos.push_back(info);
    }
}


void UI::Render() {
    static bool clicked = false;
    static std::thread dumpThread;
    static std::thread pathThread;
    static bool isDumping = false;
    static bool isProcessingPaths = false;
    static bool showNotSignedOnly = false;
    static bool showFlaggedOnly = false;

    const float windowCenterX = (ImGui::GetWindowSize().x - 250) * 0.5f;
    const float windowCenterY = (ImGui::GetWindowSize().y - 70) * 0.5f;

    if (clicked) {
        if (ImGui::Button("Return", ImVec2(100, 30))) {
            clicked = false;
            showNotSignedOnly = false;
            showFlaggedOnly = false;
            processedPaths.clear();
            pathInfos.clear();
            ImGui::PopStyleVar();
            ImGui::End();
            return;
        }

        ImGui::SameLine();
        ImGui::Checkbox("Not Signed Only", &showNotSignedOnly);
        ImGui::SameLine();
        ImGui::Checkbox("Flagged Only", &showFlaggedOnly);

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        float signatureMaxWidth = ImGui::CalcTextSize("Signature").x;
        float rulesMaxWidth = ImGui::CalcTextSize("Rules").x;

        for (const auto& info : pathInfos) {
            signatureMaxWidth = std::max(signatureMaxWidth, ImGui::CalcTextSize(info.signature.c_str()).x);

            std::string rules;
            for (const auto& rule : info.matched_rules) {
                rules += rule + ", ";
            }
            if (!rules.empty()) {
                rules = rules.substr(0, rules.length() - 2);
                rulesMaxWidth = std::max(rulesMaxWidth, ImGui::CalcTextSize(rules.c_str()).x);
            }
        }

        signatureMaxWidth += 30;
        rulesMaxWidth += 30;

        ImGui::Columns(3, "ProcessColumns", true);

        ImGui::SetColumnWidth(0, ImGui::GetWindowContentRegionWidth() - signatureMaxWidth - rulesMaxWidth); 
        ImGui::SetColumnWidth(1, signatureMaxWidth);
        ImGui::SetColumnWidth(2, rulesMaxWidth);

        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetColorU32(ImVec4(1.0f, 1.0f, 1.0f, 1.0f)));
        ImGui::Text("Filepath"); ImGui::NextColumn();
        ImGui::Text("Signature"); ImGui::NextColumn();
        ImGui::Text("Rules"); ImGui::NextColumn();
        ImGui::PopStyleColor();

        ImGui::Separator();

        for (const auto& info : pathInfos) {
            bool shouldShow = true;

            if (showNotSignedOnly && (info.signature == "Signed" || info.signature == "Deleted")) {
                shouldShow = false;
            }

            if (showFlaggedOnly && info.matched_rules.empty()) {
                shouldShow = false;
            }

            if (shouldShow) {
                ImGui::Text("%s", info.path.c_str()); ImGui::NextColumn();

                if (info.signature == "Signed") {
                    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetColorU32(ImVec4(0.0f, 1.0f, 0.0f, 1.0f)));
                }
                else {
                    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetColorU32(ImVec4(1.0f, 1.0f, 0.0f, 1.0f)));
                }
                ImGui::Text("%s", info.signature.c_str());
                ImGui::PopStyleColor();
                ImGui::NextColumn();

                if (!info.matched_rules.empty()) {
                    std::string rules;
                    for (size_t i = 0; i < info.matched_rules.size(); i++) {
                        rules += info.matched_rules[i];
                        if (i < info.matched_rules.size() - 1) {
                            rules += ", ";
                        }
                    }
                    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetColorU32(ImVec4(1.0f, 0.0f, 0.0f, 1.0f)));
                    ImGui::Text("%s", rules.c_str());
                    ImGui::PopStyleColor();
                }
                else {
                    ImGui::Text("-");
                }
                ImGui::NextColumn();
            }
        }

        ImGui::Columns(1);
    }

    if (!clicked) {
        ImGui::SetCursorPos(ImVec2(windowCenterX, windowCenterY));
        char buttonLabel1[64];
        snprintf(buttonLabel1, sizeof(buttonLabel1), "svchost (DiagTrack) - %i", process::getInstance()->getDiagtrackPID());
        if (ImGui::Button(buttonLabel1, ImVec2(250, 30)) && !isDumping) {
            clicked = true;
            isDumping = true;
            dumpFinished = false;

            if (dumpThread.joinable()) dumpThread.join();
            if (pathThread.joinable()) pathThread.join();

            dumpThread = std::thread(DumpDiagTrack);
            dumpThread.detach();

            pathThread = std::thread(ProcessPaths);
            pathThread.detach();

            isDumping = false;
        }

        ImGui::SetCursorPos(ImVec2(windowCenterX, windowCenterY + 40));
        char buttonLabel2[64];
        snprintf(buttonLabel2, sizeof(buttonLabel2), "svchost (AppInfo) - %i", process::getInstance()->getAppInfoPID());
        if (ImGui::Button(buttonLabel2, ImVec2(250, 30)) && !isDumping) {
            clicked = true;
            isDumping = true;
            dumpFinished = false;

            if (dumpThread.joinable()) dumpThread.join();
            if (pathThread.joinable()) pathThread.join();

            dumpThread = std::thread(DumpAppInfo);
            dumpThread.detach();

            pathThread = std::thread(ProcessPaths);
            pathThread.detach();

            isDumping = false;
        }
    }

    ImGui::PopStyleVar();
    ImGui::End();
}

void UI::EndFrame() {
    ImGui::EndFrame();
    g_pd3dDevice->SetRenderState(D3DRS_ZENABLE, FALSE);
    g_pd3dDevice->SetRenderState(D3DRS_ALPHABLENDENABLE, FALSE);
    g_pd3dDevice->SetRenderState(D3DRS_SCISSORTESTENABLE, FALSE);

    D3DCOLOR clear_col_dx = D3DCOLOR_RGBA(0, 0, 0, 255);
    g_pd3dDevice->Clear(0, nullptr, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, clear_col_dx, 1.0f, 0);

    if (g_pd3dDevice->BeginScene() >= 0) {
        ImGui::Render();
        ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
        g_pd3dDevice->EndScene();
    }

    HRESULT result = g_pd3dDevice->Present(nullptr, nullptr, nullptr, nullptr);
    if (result == D3DERR_DEVICELOST && g_pd3dDevice->TestCooperativeLevel() == D3DERR_DEVICENOTRESET)
        ResetDevice();
}

void UI::Shutdown() {
    ImGui_ImplDX9_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClass(wc.lpszClassName, wc.hInstance);
}