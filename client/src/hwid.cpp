#include "hwid.h"
#include "utils.h"

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#include <winternl.h>
#include <iphlpapi.h>
#include <setupapi.h>
#include <devguid.h>
#include <comdef.h>
#include <Wbemidl.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "wbemuuid.lib")
#else
#include <unistd.h>
#include <fstream>
#include <sys/ioctl.h>
#include <net/if.h>
#include <cstring>
#endif

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <array>
#include <vector>

namespace hwid {

std::string get_cpu_id() {
#ifdef _WIN32
    int cpuInfo[4] = { -1 };
    __cpuid(cpuInfo, 0);
    std::stringstream ss;
    for (int i = 0; i < 4; ++i)
        ss << std::hex << cpuInfo[i];
    __cpuid(cpuInfo, 1);
    for (int i = 0; i < 4; ++i)
        ss << std::hex << cpuInfo[i];
    return ss.str();
#else
    std::ifstream cpuinfo("/proc/cpuinfo");
    if (!cpuinfo.is_open()) return "unknown";
    std::string line;
    while (std::getline(cpuinfo, line)) {
        if (line.find("Serial") != std::string::npos) {
            auto pos = line.find(':');
            if (pos != std::string::npos)
                return utils::trim(line.substr(pos + 1));
        }
    }
    return "unknown";
#endif
}

std::string get_disk_serial() {
#ifdef _WIN32
    // Use WMI to get disk serial
    HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) return "unknown";

    hres = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE, nullptr);

    IWbemLocator* pLoc = nullptr;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) { CoUninitialize(); return "unknown"; }

    IWbemServices* pSvc = nullptr;
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr, 0, 0, 0, 0, &pSvc);
    if (FAILED(hres)) { pLoc->Release(); CoUninitialize(); return "unknown"; }

    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
        nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE);

    IEnumWbemClassObject* pEnumerator = nullptr;
    hres = pSvc->ExecQuery(bstr_t("WQL"),
        bstr_t("SELECT SerialNumber FROM Win32_DiskDrive"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr, &pEnumerator);
    if (FAILED(hres)) { pSvc->Release(); pLoc->Release(); CoUninitialize(); return "unknown"; }

    std::string serial = "unknown";
    IWbemClassObject* pclsObj = nullptr;
    ULONG uReturn = 0;
    if (pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn) == S_OK) {
        VARIANT vtProp;
        VariantInit(&vtProp);
        if (pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0) == S_OK) {
            _bstr_t bstr = vtProp.bstrVal;
            serial = (const char*)bstr;
            serial = utils::trim(serial);
        }
        VariantClear(&vtProp);
        pclsObj->Release();
    }

    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    return serial;
#else
    std::ifstream f("/etc/machine-id");
    if (f.is_open()) {
        std::string id;
        std::getline(f, id);
        return utils::trim(id);
    }
    return "unknown";
#endif
}

std::string get_mac_address() {
#ifdef _WIN32
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD bufLen = sizeof(adapterInfo);
    if (GetAdaptersInfo(adapterInfo, &bufLen) != ERROR_SUCCESS)
        return "unknown";

    PIP_ADAPTER_INFO pAdapter = adapterInfo;
    // Prefer first non-loopback adapter with valid MAC
    while (pAdapter) {
        if (pAdapter->Type != MIB_IF_TYPE_LOOPBACK &&
            pAdapter->AddressLength == 6) {
            // Check if MAC is not all zeros
            bool valid = false;
            for (UINT i = 0; i < pAdapter->AddressLength; ++i) {
                if (pAdapter->Address[i] != 0) { valid = true; break; }
            }
            if (valid) {
                std::stringstream ss;
                for (UINT i = 0; i < pAdapter->AddressLength; ++i) {
                    if (i > 0) ss << ":";
                    ss << std::hex << std::setw(2) << std::setfill('0')
                       << (int)pAdapter->Address[i];
                }
                return ss.str();
            }
        }
        pAdapter = pAdapter->Next;
    }
    return "unknown";
#else
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return "unknown";

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        strncpy(ifr.ifr_name, "enp0s3", IFNAMSIZ - 1);
        if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
            close(fd);
            return "unknown";
        }
    }
    close(fd);

    std::stringstream ss;
    unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    for (int i = 0; i < 6; ++i) {
        if (i > 0) ss << ":";
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)mac[i];
    }
    return ss.str();
#endif
}

std::string generate() {
    std::string data = get_cpu_id() + "|" +
                       get_disk_serial() + "|" +
                       get_mac_address();
    return utils::sha256(data);
}

} // namespace hwid
