#include <windows.h>
#include <string>
#include <unordered_map>
#include <algorithm>
#include <vector>
#include <cctype>

inline std::string ToLower(const std::string& str) {
    std::string lowerStr = str;
    std::transform(
        lowerStr.begin(), lowerStr.end(), lowerStr.begin(),
        [](unsigned char c) { return std::tolower(c); });
    return lowerStr;
}

inline std::string CleanDevicePath(const std::string& devicePath) {
    std::string lowerPath = ToLower(devicePath);
    std::string pattern = "harddiskvolume";
    size_t pos = lowerPath.find(pattern);
    if (pos != std::string::npos) {
        return devicePath.substr(pos);
    }
    return devicePath;
}

inline std::unordered_map<std::string, std::string> GetDeviceToDriveMap() {
    std::unordered_map<std::string, std::string> deviceMap;
    DWORD drives = GetLogicalDrives();
    if (drives == 0) {
        return deviceMap;
    }
    for (char drive = 'A'; drive <= 'Z'; ++drive) {
        if (drives & 1) {
            std::string driveLetter = std::string(1, drive) + ":";
            char devicePath[MAX_PATH] = { 0 };
            DWORD result =
                QueryDosDeviceA(driveLetter.c_str(), devicePath, MAX_PATH);
            if (result != 0) {
                std::string cleanedDevicePath = CleanDevicePath(devicePath);
                std::string lowerDevicePath = ToLower(cleanedDevicePath);
                deviceMap[lowerDevicePath] = driveLetter;
            }
        }
        drives >>= 1;
    }
    return deviceMap;
}

inline std::string convertPath(const std::string& devicePath) {
    static std::unordered_map<std::string, std::string> deviceMap =
        GetDeviceToDriveMap();
    std::string cleanedInputPath = CleanDevicePath(devicePath);
    std::string lowerInputPath = ToLower(cleanedInputPath);
    std::string matchedDrive = "";
    size_t matchedLength = 0;
    for (const auto& [ device, drive] : deviceMap) {
        if (lowerInputPath.find(device) == 0 && device.length() > matchedLength) {
            matchedDrive = drive;
            matchedLength = device.length();
        }
    }
    if (!matchedDrive.empty()) {
        return matchedDrive + cleanedInputPath.substr(matchedLength);
    }
    return devicePath;
}
