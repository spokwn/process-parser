#include "UI/UI.h"
#include "rules/yara.h"

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    if (!getMaximumPrivileges(GetCurrentProcess())) {
        return 1;
    }

    process proc;
    process::setInstance(&proc);
    proc.initialize();

    initializeGenericRules();

    if (!UI::Initialize())
        return 1;

    while (!UI::ShouldClose()) {
        UI::BeginFrame();
        UI::Render();
        UI::EndFrame();
    }

    UI::Shutdown();
    return 0;
}