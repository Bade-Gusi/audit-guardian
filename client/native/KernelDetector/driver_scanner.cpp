#include <windows.h>
#include <vector>
#include <string>
#include <fstream>
#include <json/json.h>

// Windows Native API
typedef NTSTATUS (NTAPI* pNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

#define SystemModuleInformation 11

typedef struct _SYSTEM_MODULE {
    PVOID Reserved1;
    PVOID Reserved2;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    WORD LoadOrderIndex;
    WORD InitOrderIndex;
    WORD LoadCount;
    WORD ModuleNameOffset;
    CHAR ImageName[256];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG ModulesCount;
    SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

Json::Value scan_drivers(const std::string& signature_path) {
    Json::Value result;
    result["filter_drivers"] = Json::arrayValue;

    // 1. Enumerate loaded kernel modules
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return result;

    auto NtQuerySystemInformation = (pNtQuerySystemInformation)
        GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) return result;

    ULONG buffer_size = 0;
    NtQuerySystemInformation(SystemModuleInformation, nullptr, 0, &buffer_size);

    if (buffer_size == 0) return result;

    std::vector<BYTE> buffer(buffer_size);
    auto status = NtQuerySystemInformation(
        SystemModuleInformation,
        buffer.data(),
        buffer_size,
        &buffer_size
    );

    if (status != 0) return result;

    auto module_info = (PSYSTEM_MODULE_INFORMATION)buffer.data();

    // 2. Load signature database
    std::string process_blacklist_path = signature_path + "/driver_blacklist.json";
    Json::Value blacklist;
    std::ifstream file(process_blacklist_path);
    if (file.is_open()) {
        Json::CharReaderBuilder reader;
        std::string errors;
        Json::parseFromStream(reader, file, &blacklist, &errors);
        file.close();
    }

    // 3. Check each driver against blacklist patterns
    for (ULONG i = 0; i < module_info->ModulesCount; i++) {
        auto& mod = module_info->Modules[i];
        std::string driver_name = mod.ImageName;
        std::string short_name = driver_name;
        auto pos = driver_name.find_last_of('\\');
        if (pos != std::string::npos) {
            short_name = driver_name.substr(pos + 1);
        }

        // Convert to lowercase for matching
        for (auto& c : short_name) c = tolower(c);

        // Check against blacklist patterns
        for (const auto& rule : blacklist) {
            std::string pattern = rule["patterns"][0].asString();
            for (auto& c : pattern) c = tolower(c);

            // Simple wildcard matching
            if (pattern.find('*') != std::string::npos) {
                std::string prefix = pattern.substr(0, pattern.find('*'));
                if (short_name.find(prefix) == 0) {
                    Json::Value driver;
                    driver["name"] = mod.ImageName;
                    driver["matched_rule"] = rule["name"].asString();
                    driver["severity"] = rule["severity"].asString();
                    driver["description"] = rule["description"].asString();
                    result["filter_drivers"].append(driver);
                }
            }
        }
    }

    return result;
}
