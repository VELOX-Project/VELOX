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
#include <random>
#include <sstream>
#include <filesystem>
#include <wincrypt.h>
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Crypt32.lib")

enum class LogLevel { Info, Warn, Error, Success };

class Logger {
public:
    Logger(const std::string& filename)
        : logFile(filename, std::ios::app) {}

    void log(const std::string& msg, LogLevel level = LogLevel::Info) {
        const char* tag = "[INFO]";
        if (level == LogLevel::Warn) { tag = "[WARN]"; }
        else if (level == LogLevel::Error) { tag = "[ERROR]"; }
        else if (level == LogLevel::Success) { tag = "[SUCCESS]"; }

        std::string timestamp = getTimestamp();
        std::cout << "[VELOX] " << tag << " " << timestamp << " " << msg << std::endl;
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

namespace Helpers {
    std::string SanitizePath(const std::string& raw) {
        std::string path = raw;
        path.erase(std::remove(path.begin(), path.end(), '"'), path.end());
        auto first = path.find_first_not_of(" \t\r\n");
        auto last = path.find_last_not_of(" \t\r\n");
        if (first == std::string::npos || last == std::string::npos)
            return "";
        path = path.substr(first, last - first + 1);
        std::replace(path.begin(), path.end(), '/', '\\');
        return path;
    }

    std::string GetServiceName(const std::string& path) {
        size_t pos = path.find_last_of("\\/");
        std::string filename = (pos != std::string::npos) ? path.substr(pos + 1) : path;
        pos = filename.find_last_of(".");
        std::string base = (pos != std::string::npos) ? filename.substr(0, pos) : filename;
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 0xFFFF);
        std::ostringstream ss;
        ss << base << "_" << std::hex << std::setw(4) << std::setfill('0') << dis(gen);
        return ss.str();
    }

    bool PromptYesNo(const std::string& prompt, Logger& logger, LogLevel level = LogLevel::Warn) {
        std::cout << prompt << " (y/n): ";
        std::string choice;
        std::getline(std::cin, choice);
        if (choice.empty()) return false;
        char c = std::tolower(choice[0]);
        bool result = (c == 'y');
        logger.log(std::string("User selected: ") + (result ? "Yes" : "No"), level);
        return result;
    }

    std::string GetUserInput(const std::string& prompt) {
        std::cout << prompt;
        std::string input;
        std::getline(std::cin, input);
        return input;
    }

    std::string GetFileHash(const std::string& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file) return "";
        std::vector<char> buffer(std::istreambuf_iterator<char>(file), {});
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        BYTE hash[20];
        DWORD hashLen = 20;
        std::ostringstream oss;
        if (CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            if (CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
                CryptHashData(hHash, (BYTE*)buffer.data(), buffer.size(), 0);
                if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
                    for (DWORD i = 0; i < hashLen; ++i)
                        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
                }
                CryptDestroyHash(hHash);
            }
            CryptReleaseContext(hProv, 0);
        }
        return oss.str();
    }

    bool IsDriverSigned(const std::string& path) {
        DWORD encoding, contentType, formatType;
        HCERTSTORE hStore = NULL;
        HCRYPTMSG hMsg = NULL;
        BOOL result = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            path.c_str(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            &encoding,
            &contentType,
            &formatType,
            &hStore,
            &hMsg,
            NULL
        );
        if (hStore) CertCloseStore(hStore, 0);
        if (hMsg) CryptMsgClose(hMsg);
        return result == TRUE;
    }

    bool IsTestSigned(const std::string& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file) return false;
        std::string contents((std::istreambuf_iterator<char>(file)), {});
        return contents.find("TESTSIGNING") != std::string::npos;
    }

    void SaveServiceName(const std::string& serviceName, const std::string& driverPath) {
        std::filesystem::path txtPath = std::filesystem::path(driverPath).replace_extension(".servicename.txt");
        std::ofstream out(txtPath);
        out << serviceName;
    }
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

bool IsValidSysFile(const std::string& path, Logger& logger) {
    if (!PathFileExistsA(path.c_str())) {
        logger.log("File does not exist: " + path, LogLevel::Error);
        return false;
    }
    if (!PathMatchSpecA(path.c_str(), "*.sys")) {
        logger.log("File is not a .sys driver: " + path, LogLevel::Error);
        return false;
    }
    return true;
}

bool ServiceExists(ServiceHandle& scm, const std::string& name) {
    ServiceHandle svc(OpenServiceA(scm, name.c_str(), SERVICE_QUERY_STATUS));
    return svc.valid();
}

bool StopService(ServiceHandle& scm, const std::string& name, Logger& logger) {
    ServiceHandle svc(OpenServiceA(scm, name.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS));
    if (!svc.valid()) {
        logger.logError("OpenService for stop failed");
        return false;
    }
    SERVICE_STATUS status = {};
    if (!ControlService(svc, SERVICE_CONTROL_STOP, &status)) {
        logger.logError("ControlService (stop) failed");
        return false;
    }
    logger.log("Service stopped: " + name, LogLevel::Warn);
    return true;
}

bool DeleteService(ServiceHandle& scm, const std::string& name, Logger& logger) {
    StopService(scm, name, logger); // Try to stop before delete
    ServiceHandle svc(OpenServiceA(scm, name.c_str(), DELETE));
    if (!svc.valid()) {
        logger.logError("OpenService for delete failed");
        return false;
    }
    if (!::DeleteService(svc)) {
        logger.logError("DeleteService failed");
        return false;
    }
    logger.log("Service deleted: " + name, LogLevel::Warn);
    return true;
}

bool DeleteDriverFile(const std::string& path, Logger& logger) {
    if (!DeleteFileA(path.c_str())) {
        logger.logError("Failed to delete driver file: " + path);
        return false;
    }
    logger.log("Driver file deleted: " + path, LogLevel::Success);
    return true;
}

ServiceHandle CreateDriverService(ServiceHandle& scm, const std::string& name, const std::string& path, DWORD startType, Logger& logger) {
    ServiceHandle svc(CreateServiceA(
        scm,
        name.c_str(),
        name.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        startType,
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
    std::cout 
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
        << std::endl;
}

void ShowDriverInfo(const std::string& driverPath, Logger& logger) {
    std::filesystem::path fsPath(driverPath);
    logger.log("Driver full path: " + driverPath);
    logger.log("Driver filename: " + fsPath.filename().string());
    logger.log("Driver directory: " + fsPath.parent_path().string());
    logger.log("Driver size: " + std::to_string(std::filesystem::file_size(fsPath)) + " bytes");
    logger.log("Driver SHA1 hash: " + Helpers::GetFileHash(driverPath));
    if (!Helpers::IsDriverSigned(driverPath)) {
        logger.log("WARNING: Driver is NOT signed!", LogLevel::Warn);
    } else if (Helpers::IsTestSigned(driverPath)) {
        logger.log("WARNING: Driver is test-signed.", LogLevel::Warn);
    } else {
        logger.log("Driver appears to be signed.", LogLevel::Info);
    }
}

void InstallDriver(Logger& logger, const std::string& driverPathArg = "", DWORD startTypeArg = SERVICE_DEMAND_START, bool scripting = false) {
    logger.log("Driver installation selected.", LogLevel::Info);

    std::string driverPath = driverPathArg;
    if (driverPath.empty()) {
        std::string rawPath = Helpers::GetUserInput("Enter full path to .sys driver (or drag & drop): ");
        driverPath = Helpers::SanitizePath(rawPath);
    }

    if (driverPath.empty()) {
        logger.log("No path entered.", LogLevel::Error);
        return;
    }
    logger.log("Sanitized driver path: " + driverPath);

    if (!IsValidSysFile(driverPath, logger)) {
        logger.logError("Invalid or missing .sys file.");
        return;
    }
    logger.log("Driver file validated.");

    ShowDriverInfo(driverPath, logger);

    std::string serviceName = Helpers::GetServiceName(driverPath);
    logger.log("Service name: " + serviceName);

    ServiceHandle scm(OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS));
    if (!scm.valid()) {
        logger.logError("Could not open Service Control Manager.");
        return;
    }
    logger.log("Connected to Service Control Manager.");

    if (ServiceExists(scm, serviceName)) {
        logger.log("Service name already exists.", LogLevel::Warn);
        if (scripting || Helpers::PromptYesNo("Overwrite existing service?", logger)) {
            if (!DeleteService(scm, serviceName, logger)) {
                logger.logError("Failed to delete existing service.");
                return;
            }
        } else {
            logger.log("Operation cancelled by user.", LogLevel::Warn);
            return;
        }
    }

    DWORD startType = startTypeArg;
    if (!scripting) {
        std::cout << "Select service start type:\n"
                  << "  [1] Demand Start (default)\n"
                  << "  [2] System Start\n"
                  << "  [3] Boot Start\n"
                  << "Enter choice: ";
        std::string startTypeChoice;
        std::getline(std::cin, startTypeChoice);
        if (!startTypeChoice.empty()) {
            if (startTypeChoice[0] == '2') startType = SERVICE_SYSTEM_START;
            else if (startTypeChoice[0] == '3') startType = SERVICE_BOOT_START;
        }
    }

    ServiceHandle svc = CreateDriverService(scm, serviceName, driverPath, startType, logger);
    if (!svc.valid()) {
        logger.logError("Failed to create service.");
        return;
    }
    logger.log("Service created successfully.", LogLevel::Success);

    Helpers::SaveServiceName(serviceName, driverPath);
    logger.log("Service name saved to .servicename.txt for future uninstall.", LogLevel::Info);

    bool startNow = scripting ? true : Helpers::PromptYesNo("Start driver now (no reboot required)?", logger, LogLevel::Info);
    if (startNow) {
        if (!StartServiceA(svc, 0, nullptr)) {
            logger.logError("Failed to start driver service.");
        } else {
            logger.log("Driver started successfully.", LogLevel::Success);
        }
    } else {
        logger.log("Boot/system start selected. Driver will load at next boot.", LogLevel::Warn);
    }

    logger.log("Setup complete.", LogLevel::Success);
}

void UninstallDriver(Logger& logger, const std::string& driverPathArg = "", bool scripting = false) {
    logger.log("Driver uninstallation selected.", LogLevel::Info);

    std::string driverPath = driverPathArg;
    if (driverPath.empty()) {
        std::string rawPath = Helpers::GetUserInput("Enter full path to .sys driver to uninstall (or drag & drop): ");
        driverPath = Helpers::SanitizePath(rawPath);
    }

    if (driverPath.empty()) {
        logger.log("No path entered.", LogLevel::Error);
        return;
    }
    logger.log("Sanitized driver path: " + driverPath);

    ShowDriverInfo(driverPath, logger);

    std::filesystem::path fsPath(driverPath);
    std::string serviceName = Helpers::GetServiceName(driverPath);

    std::filesystem::path txtPath = fsPath.replace_extension(".servicename.txt");
    if (std::filesystem::exists(txtPath)) {
        std::ifstream in(txtPath);
        std::string name;
        std::getline(in, name);
        if (!name.empty()) serviceName = name;
        logger.log("Loaded service name from .servicename.txt: " + name, LogLevel::Info);
    }

    logger.log("Service name: " + serviceName);

    ServiceHandle scm(OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS));
    if (!scm.valid()) {
        logger.logError("Could not open Service Control Manager.");
        return;
    }
    logger.log("Connected to Service Control Manager.");

    if (!ServiceExists(scm, serviceName)) {
        logger.log("Service does not exist: " + serviceName, LogLevel::Error);
    } else {
        if (DeleteService(scm, serviceName, logger)) {
            logger.log("Service deleted successfully.", LogLevel::Success);
        } else {
            logger.logError("Failed to delete service.");
            return;
        }
    }

    if (PathFileExistsA(driverPath.c_str())) {
        bool deleteFile = scripting ? true : Helpers::PromptYesNo("Delete driver file as well?", logger, LogLevel::Warn);
        if (deleteFile) {
            if (DeleteDriverFile(driverPath, logger)) {
                logger.log("Driver file removed.", LogLevel::Success);
            }
        }
    }

    logger.log("Uninstall process complete.", LogLevel::Success);
}

void ParseArgs(int argc, char** argv, Logger& logger) {
    std::string driverPath;
    DWORD startType = SERVICE_DEMAND_START;
    bool scripting = false;
    bool uninstall = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--install" && i + 1 < argc) {
            driverPath = Helpers::SanitizePath(argv[i + 1]);
            scripting = true;
            ++i;
        } else if (arg == "--uninstall" && i + 1 < argc) {
            driverPath = Helpers::SanitizePath(argv[i + 1]);
            uninstall = true;
            scripting = true;
            ++i;
        } else if (arg.find("--start=") == 0) {
            std::string val = arg.substr(8);
            if (val == "boot") startType = SERVICE_BOOT_START;
            else if (val == "system") startType = SERVICE_SYSTEM_START;
            else startType = SERVICE_DEMAND_START;
        }
    }

    if (scripting && !driverPath.empty()) {
        if (uninstall)
            UninstallDriver(logger, driverPath, true);
        else
            InstallDriver(logger, driverPath, startType, true);
        exit(0);
    }
}

int main(int argc, char** argv) {
    Logger logger("velox.log");
    PrintBanner();
    logger.log("Starting VELOX...", LogLevel::Info);

    if (!IsAdmin(logger)) {
        logger.logError("Administrative privileges required.");
        return 1;
    }
    logger.log("Admin privileges verified.", LogLevel::Success);

    ParseArgs(argc, argv, logger);

    std::cout << "\nPlease select an operation:\n"
              << "  [1] Install a kernel-mode driver\n"
              << "  [2] Uninstall a kernel-mode driver\n"
              << "  [Q] Quit\n" << std::endl;

    std::string choice;
    std::cout << "Enter your choice: ";
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
