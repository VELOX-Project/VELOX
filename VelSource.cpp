#include <windows.h>
#include <Shlwapi.h>
#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <memory>
#include <vector>
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shlwapi.lib")

// Color codes for Windows 10+ terminals
#define COLOR_INFO    "\033[1;36m"
#define COLOR_ERROR   "\033[1;31m"
#define COLOR_WARN    "\033[1;33m"
#define COLOR_SUCCESS "\033[1;32m"
#define COLOR_RESET   "\033[0m"

enum class LogLevel { Info, Warn, Error, Success };

class Logger {
public:
    Logger(const std::string& filename)
        : logFile(filename, std::ios::app) {}

    void log(const std::string& msg, LogLevel level = LogLevel::Info) {
        const char* color = COLOR_INFO;
        const char* tag = "[INFO]";
        if (level == LogLevel::Warn) { color = COLOR_WARN; tag = "[WARN]"; }
        else if (level == LogLevel::Error) { color = COLOR_ERROR; tag = "[ERROR]"; }
        else if (level == LogLevel::Success) { color = COLOR_SUCCESS; tag = "[SUCCESS]"; }

        std::string timestamp = getTimestamp();
        std::cout << color << "[VELOX] " << tag << " " << timestamp << " " << msg << COLOR_RESET << std::endl;
        if (logFile.is_open())
            logFile << "[VELOX] " << tag << " " << timestamp << " " << msg << std::endl;
    }

    void logError(const std::string& msg, DWORD err = GetLastError()) {
        std::string sysMsg = getSystemErrorMsg(err);
        log(msg + " (Error " + std::to_string(err) + ": " + sysMsg + ")", LogLevel::Error);
    }

private:
    std::ofstream logFile;

    std::string getTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        std::tm tm;
        localtime_s(&tm, &t);
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
        return oss.str();
    }

    std::string getSystemErrorMsg(DWORD err) {
        char* buf = nullptr;
        FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, err, 0, (LPSTR)&buf, 0, NULL);
        std::string msg = buf ? buf : "Unknown error";
        if (buf) LocalFree(buf);
        return msg;
    }
};

// RAII wrapper for SC_HANDLE
class ServiceHandle {
public:
    ServiceHandle(SC_HANDLE h = nullptr) : handle(h) {}
    ~ServiceHandle() { if (handle) CloseServiceHandle(handle); }
    operator SC_HANDLE() const { return handle; }
    bool valid() const { return handle != nullptr; }
    void reset(SC_HANDLE h = nullptr) {
        if (handle) CloseServiceHandle(handle);
        handle = h;
    }
private:
    SC_HANDLE handle;
};

std::wstring SanitizePath(std::wstring_view raw) {
    std::wstring path(raw);
    // Remove quotes
    path.erase(std::remove(path.begin(), path.end(), L'"'), path.end());
    // Trim spaces
    auto first = path.find_first_not_of(L" \t\r\n");
    auto last = path.find_last_not_of(L" \t\r\n");
    if (first == std::wstring::npos || last == std::wstring::npos)
        return L"";
    path = path.substr(first, last - first + 1);
    // Normalize slashes
    std::replace(path.begin(), path.end(), L'/', L'\\');
    return path;
}

bool IsAdmin(Logger& logger) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        logger.logError("Failed to open process token");
        return false;
    }
    DWORD size = 0;
    TOKEN_ELEVATION elevation;
    if (!GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
        CloseHandle(token);
        logger.logError("Failed to get token elevation");
        return false;
    }
    CloseHandle(token);
    return elevation.TokenIsElevated != 0;
}

bool IsValidSysFile(const std::wstring& path, Logger& logger) {
    if (!PathFileExistsW(path.c_str())) {
        logger.log("File does not exist: " + std::string(path.begin(), path.end()), LogLevel::Error);
        return false;
    }
    if (!PathMatchSpecW(path.c_str(), L"*.sys")) {
        logger.log("File is not a .sys driver: " + std::string(path.begin(), path.end()), LogLevel::Error);
        return false;
    }
    return true;
}

std::wstring GetServiceName(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/");
    std::wstring filename = (pos != std::wstring::npos) ? path.substr(pos + 1) : path;
    pos = filename.find_last_of(L".");
    return (pos != std::wstring::npos) ? filename.substr(0, pos) : filename;
}

bool ServiceExists(ServiceHandle& scm, const std::wstring& name) {
    ServiceHandle svc(OpenServiceW(scm, name.c_str(), SERVICE_QUERY_STATUS));
    return svc.valid();
}

bool DeleteService(ServiceHandle& scm, const std::wstring& name, Logger& logger) {
    ServiceHandle svc(OpenServiceW(scm, name.c_str(), DELETE));
    if (!svc.valid()) {
        logger.logError("OpenService for delete failed");
        return false;
    }
    if (!::DeleteService(svc)) {
        logger.logError("DeleteService failed");
        return false;
    }
    logger.log("Service deleted: " + std::string(name.begin(), name.end()), LogLevel::Warn);
    return true;
}

bool DeleteDriverFile(const std::wstring& path, Logger& logger) {
    if (!DeleteFileW(path.c_str())) {
        logger.logError("Failed to delete driver file: " + std::string(path.begin(), path.end()));
        return false;
    }
    logger.log("Driver file deleted: " + std::string(path.begin(), path.end()), LogLevel::Success);
    return true;
}

ServiceHandle CreateDriverService(ServiceHandle& scm, const std::wstring& name, const std::wstring& path, Logger& logger) {
    ServiceHandle svc(CreateServiceW(
        scm,
        name.c_str(),
        name.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_BOOT_START,
        SERVICE_ERROR_NORMAL,
        path.c_str(),
        NULL, NULL, NULL, NULL, NULL
    ));
    if (!svc.valid()) {
        logger.logError("CreateService failed");
    }
    return svc;
}

void PrintBanner() {
    std::cout << COLOR_INFO
        << "\n"
        << " __      ________ _      ______   __  \n"
        << " \\ \\    / /  ____| |    / __ \\ \\ / /  \n"
        << "  \\ \\  / /| |__  | |   | |  | \\ V /   \n"
        << "   \\ \\/ / |  __| | |   | |  | |> <    \n"
        << "    \\  /  | |____| |___| |__| / . \\   \n"
        << "     \\/   |______|______\\____/_/ \\_\\  \n"
        << "                                      \n"
        << "------------------------------------------\n"
        << " VELOX - Professional Driver Loader\n"
        << "------------------------------------------\n"
        << " For legitimate development & research\n"
        << " Absolutely NO cheating or bypassing!\n"
        << "------------------------------------------\n"
        << COLOR_RESET << std::endl;
}



std::wstring GetUserInput(const std::wstring& prompt) {
    std::wcout << COLOR_INFO << prompt << COLOR_RESET;
    std::wstring input;
    std::getline(std::wcin, input);
    return input;
}

bool PromptYesNo(const std::string& prompt, Logger& logger, LogLevel level = LogLevel::Warn) {
    std::cout << COLOR_WARN << prompt << " (y/n): " << COLOR_RESET;
    std::string choice;
    std::getline(std::cin, choice);
    if (choice.empty()) return false;
    char c = std::tolower(choice[0]);
    bool result = (c == 'y');
    logger.log(std::string("User selected: ") + (result ? "Yes" : "No"), level);
    return result;
}

void InstallDriver(Logger& logger) {
    logger.log("Driver installation selected.", LogLevel::Info);

    std::wstring rawPath = GetUserInput(L"Enter full path to .sys driver (or drag & drop): ");
    std::wstring driverPath = SanitizePath(rawPath);

    if (driverPath.empty()) {
        logger.log("No path entered.", LogLevel::Error);
        return;
    }
    logger.log("Sanitized driver path: " + std::string(driverPath.begin(), driverPath.end()));

    if (!IsValidSysFile(driverPath, logger)) {
        logger.logError("Invalid or missing .sys file.");
        return;
    }
    logger.log("Driver file validated.");

    std::wstring serviceName = GetServiceName(driverPath);
    logger.log("Service name: " + std::string(serviceName.begin(), serviceName.end()));

    ServiceHandle scm(OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS));
    if (!scm.valid()) {
        logger.logError("Could not open Service Control Manager.");
        return;
    }
    logger.log("Connected to Service Control Manager.");

    if (ServiceExists(scm, serviceName)) {
        logger.log("Service name already exists.", LogLevel::Warn);
        if (PromptYesNo("Overwrite existing service?", logger)) {
            if (!DeleteService(scm, serviceName, logger)) {
                logger.logError("Failed to delete existing service.");
                return;
            }
        } else {
            logger.log("Operation cancelled by user.", LogLevel::Warn);
            return;
        }
    }

    ServiceHandle svc = CreateDriverService(scm, serviceName, driverPath, logger);
    if (!svc.valid()) {
        logger.logError("Failed to create service.");
        return;
    }
    logger.log("Service created successfully.", LogLevel::Success);

    logger.log("Boot-start drivers are loaded at system boot. Please reboot to activate the driver.", LogLevel::Warn);

    logger.log("Setup complete. Driver will load at next boot.", LogLevel::Success);
}

void UninstallDriver(Logger& logger) {
    logger.log("Driver uninstallation selected.", LogLevel::Info);

    std::wstring rawPath = GetUserInput(L"Enter full path to .sys driver to uninstall (or drag & drop): ");
    std::wstring driverPath = SanitizePath(rawPath);

    if (driverPath.empty()) {
        logger.log("No path entered.", LogLevel::Error);
        return;
    }
    logger.log("Sanitized driver path: " + std::string(driverPath.begin(), driverPath.end()));

    std::wstring serviceName = GetServiceName(driverPath);
    logger.log("Service name: " + std::string(serviceName.begin(), serviceName.end()));

    ServiceHandle scm(OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS));
    if (!scm.valid()) {
        logger.logError("Could not open Service Control Manager.");
        return;
    }
    logger.log("Connected to Service Control Manager.");

    if (!ServiceExists(scm, serviceName)) {
        logger.log("Service does not exist: " + std::string(serviceName.begin(), serviceName.end()), LogLevel::Error);
    } else {
        if (DeleteService(scm, serviceName, logger)) {
            logger.log("Service deleted successfully.", LogLevel::Success);
        } else {
            logger.logError("Failed to delete service.");
            return;
        }
    }

    if (PathFileExistsW(driverPath.c_str())) {
        if (PromptYesNo("Delete driver file as well?", logger, LogLevel::Warn)) {
            if (DeleteDriverFile(driverPath, logger)) {
                logger.log("Driver file removed.", LogLevel::Success);
            }
        }
    }

    logger.log("Uninstall process complete.", LogLevel::Success);
}

int main() {
    Logger logger("velox.log");
    PrintBanner();
    logger.log("Starting VELOX...", LogLevel::Info);

    if (!IsAdmin(logger)) {
        logger.logError("Administrative privileges required.");
        return 1;
    }
    logger.log("Admin privileges verified.", LogLevel::Success);

    std::cout << COLOR_INFO << "\nPlease select an operation:\n"
              << COLOR_SUCCESS << "  [1] Install a kernel-mode driver\n"
              << COLOR_WARN    << "  [2] Uninstall a kernel-mode driver\n"
              << COLOR_INFO    << "  [Q] Quit\n" << COLOR_RESET;

    std::string choice;
    std::cout << COLOR_INFO << "Enter your choice: " << COLOR_RESET;
    std::getline(std::cin, choice);

    if (choice.empty() || choice[0] == 'q' || choice[0] == 'Q') {
        logger.log("Exiting VELOX. Have a great day!", LogLevel::Info);
        return 0;
    }

    if (choice[0] == '1') {
        InstallDriver(logger);
    } else if (choice[0] == '2') {
        UninstallDriver(logger);
    } else {
        logger.log("Invalid selection. Exiting.", LogLevel::Error);
    }

    logger.log("Operation finished. Thank you for using VELOX!", LogLevel::Success);
    return 0;
}
