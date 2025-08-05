// GhostHookHunter Pro v4 — by starls
// Win32 Console scanner para Blue Teams (producción, serio y sólido)
// • Modo 1: RWX Memory Scan Only
// • Modo 2: .text SHA256 Verification (solo módulos con sección válida y hash desconocido)
// • Modo 3: Advanced Scan = combinación de Modo 1 + Modo 2
// • No falsos positivos si hashes legítimos están bien definidos
// • Multihilo con barra de progreso real
// • Salida limpia para terminal con mensajes personalizados

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <iomanip>
#include <sstream>
#include <wincrypt.h>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Advapi32.lib")

inline void SetColor(WORD attr) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), attr);
}

struct HookEvent {
    DWORD pid;
    std::wstring moduleName;
    LPVOID address;
    std::string type;
    std::string hash;
};

static std::vector<HookEvent> g_events;
static std::mutex g_mtx;
static std::atomic<int> g_done{ 0 };

std::string Sha256Hash(const BYTE* data, DWORD size) {
    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;
    BYTE hash[32];
    DWORD cbHash = 32;
    char hex[65] = { 0 };
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return "";
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) { CryptReleaseContext(hProv, 0); return ""; }
    CryptHashData(hHash, data, size, 0);
    CryptGetHashParam(hHash, HP_HASHVAL, hash, &cbHash, 0);
    for (DWORD i = 0; i < cbHash; ++i) sprintf_s(hex + i * 2, 3, "%02x", hash[i]);
    CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0);
    return hex;
}

void detectRWX(HANDLE hProc, MODULEENTRY32& me, std::vector<HookEvent>& out) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProc, me.modBaseAddr, &mbi, sizeof(mbi))) {
        if ((mbi.Protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) {
            out.push_back({ GetProcessId(hProc), me.szModule, me.modBaseAddr, "RWX", "" });
        }
    }
}

void verifyTextSectionHash(HANDLE hProc, MODULEENTRY32 me, std::vector<HookEvent>& out) {
    IMAGE_DOS_HEADER dos;
    if (!ReadProcessMemory(hProc, me.modBaseAddr, &dos, sizeof(dos), nullptr)) return;
    IMAGE_NT_HEADERS nt;
    if (!ReadProcessMemory(hProc, (BYTE*)me.modBaseAddr + dos.e_lfanew, &nt, sizeof(nt), nullptr)) return;

    DWORD textRVA = 0, textSize = 0;
    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(&nt);
    for (int i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
        if (memcmp(section[i].Name, ".text", 5) == 0) {
            textRVA = section[i].VirtualAddress;
            textSize = section[i].SizeOfRawData;
            break;
        }
    }
    if (!textRVA || !textSize) return;

    BYTE* textData = new BYTE[textSize]; SIZE_T rd = 0;
    if (ReadProcessMemory(hProc, (BYTE*)me.modBaseAddr + textRVA, textData, textSize, &rd) && rd == textSize) {
        std::string hash = Sha256Hash(textData, textSize);
        static const std::vector<std::string> knownHashes = {
            "HASH_TRUSTED_1",
            "HASH_TRUSTED_2"
        };
        if (std::find(knownHashes.begin(), knownHashes.end(), hash) == knownHashes.end()) {
            out.push_back({ GetProcessId(hProc), me.szModule, (BYTE*)me.modBaseAddr + textRVA, "SHA256", hash });
        }
    }
    delete[] textData;
}

void scanProcess(DWORD pid, int mode) {
    std::vector<HookEvent> local;
    HANDLE hs = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (hs == INVALID_HANDLE_VALUE) { g_done++; return; }
    MODULEENTRY32 me{ sizeof(me) };
    if (Module32First(hs, &me)) {
        HANDLE hp = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        do {
            if (!hp) continue;
            std::wcout << L"  [>] Scanning PID: " << pid << L" | Module: " << me.szModule << std::endl;
            if (mode == 1) detectRWX(hp, me, local);
            if (mode == 2) verifyTextSectionHash(hp, me, local);
            if (mode == 3) {
                detectRWX(hp, me, local);
                verifyTextSectionHash(hp, me, local);
            }
        } while (Module32Next(hs, &me));
        if (hp) CloseHandle(hp);
    }
    CloseHandle(hs);
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_events.insert(g_events.end(), local.begin(), local.end());
    }
    g_done++;
}

void showProgress(int total) {
    const int W = 40;
    while (g_done < total) {
        int d = g_done.load();
        int pct = d * 100 / total;
        int pos = d * W / total;
        std::cout << "\r[" << std::string(pos, '=') << std::string(W - pos, ' ') << "] "
            << pct << "%" << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(60));
    }
    std::cout << "\r[" << std::string(W, '=') << "] 100%\n";
}

void runScanMode(int mode) {
    g_events.clear();
    g_done = 0;
    std::vector<DWORD> pids;
    HANDLE ps = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe{ sizeof(pe) };
    if (Process32First(ps, &pe)) {
        do { if (pe.th32ProcessID) pids.push_back(pe.th32ProcessID); } while (Process32Next(ps, &pe));
    }
    CloseHandle(ps);

    std::cout << "\n[+] Starting scan...\n";
    std::vector<std::thread> threads;
    for (auto pid : pids) threads.emplace_back(scanProcess, pid, mode);

    showProgress((int)pids.size());

    if (g_events.empty()) {
        SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        if (mode == 1) std::cout << "\n[+] RWX Scan complete. No executable memory anomalies found.\n";
        else if (mode == 2) std::cout << "\n[+] SHA256 Verification complete. No suspicious modifications found.\n";
        else if (mode == 3) std::cout << "\n[+] Advanced scan finished. System appears clean.\n";
        SetColor(7);
    }
    else {
        SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        for (auto& e : g_events) {
            std::wcout << L"PID:" << e.pid << L" | Module:" << e.moduleName << L" | Addr:0x" << std::hex << (uintptr_t)e.address << L" | Type:" << e.type.c_str();
            if (!e.hash.empty()) std::wcout << L" | Hash:" << e.hash.c_str();
            std::wcout << std::endl;
        }
        SetColor(7);
        std::cout << "\n[!] Total hooks detected: " << g_events.size() << "\n";
    }
    std::cout << "Press Enter...";
    std::cin.get();
}

int main() {
    SetConsoleTitle(L"GhostHookHunter Pro v4 by starls");
    while (true) {
        SetColor(10);
        std::cout << "\n=== GhostHookHunter Pro v4 ===\n";
        SetColor(7);
        std::cout << "1) RWX Memory Scan\n";
        std::cout << "2) .text SHA256 Verification\n";
        std::cout << "3) Full Advanced Scan\n";
        std::cout << "4) Exit\n";
        std::cout << "Select: ";
        int o;
        if (!(std::cin >> o)) { std::cin.clear(); std::cin.ignore(INT_MAX, '\n'); continue; }
        std::cin.ignore(INT_MAX, '\n');
        if (o == 1) runScanMode(1);
        else if (o == 2) runScanMode(2);
        else if (o == 3) runScanMode(3);
        else if (o == 4) break;
    }
    return 0;
}
