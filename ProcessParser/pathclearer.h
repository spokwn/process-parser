#include <string>
#include <algorithm>

class PathClearer {
private:
    std::string path;

    // Helper function to remove surrounding quotes if they exist
    void removeQuotes() {
        if (path.length() >= 2 && path.front() == '"' && path.back() == '"') {
            path = path.substr(1, path.length() - 2);
        }
    }

    // Helper function to process the path
    bool processPath() {
        // Find the position of the first ":\"
        size_t colonSlashPos = path.find(":\\");
        if (colonSlashPos == std::string::npos || colonSlashPos < 1) {
            // Invalid path format
            return false;
        }

        // Determine the start index (one character before ":\")
        size_t startIndex = colonSlashPos - 1;

        // Find the position of ".exe" starting from startIndex
        size_t exePos = path.find(".exe", startIndex);
        if (exePos == std::string::npos) {
            // ".exe" not found
            return false;
        }

        // Calculate the end position to include ".exe"
        size_t endIndex = exePos + 4; // 4 characters for ".exe"

        // Extract the valid path substring
        path = path.substr(startIndex, endIndex - startIndex);

        return true;
    }

public:
    // Constructor
    PathClearer(const std::string& inputPath) : path(inputPath) {
        removeQuotes();
    }

    // Get the processed path
    std::string getProcessedPath() {
        if (processPath()) {
            return path;
        }
        return "";
    }
};
