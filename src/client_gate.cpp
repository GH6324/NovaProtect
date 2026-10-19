#include "client_gate.h"
#include "client_trust_key.h"
#include "product_version.h"
#include "vmp_markers.h"
#include <windows.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#include <array>
#include <algorithm>
#include <cstdlib>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <vector>

namespace np {
namespace {
const char* gateStage = "entry";
struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    explicit Handle(HANDLE h = INVALID_HANDLE_VALUE) : value(h) {}
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
std::vector<unsigned char> read(const std::filesystem::path& file, size_t limit) {
    std::ifstream in(file, std::ios::binary | std::ios::ate);
    if (!in) failClosed();
    const auto size = in.tellg();
    if (size <= 0 || static_cast<uint64_t>(size) > limit) failClosed();
    std::vector<unsigned char> data(static_cast<size_t>(size));
    in.seekg(0);
    if (!in.read(reinterpret_cast<char*>(data.data()), size)) failClosed();
    return data;
}
std::array<unsigned char, 32> digest(const unsigned char* bytes, size_t count) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) failClosed();
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD length = 0, got = 0;
    if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&length), sizeof(length), &got, 0) < 0) failClosed();
    std::vector<unsigned char> object(length);
    std::array<unsigned char, 32> out{};
    if (BCryptCreateHash(algorithm, &hash, object.data(), object.size(), nullptr, 0, 0) < 0 ||
        BCryptHashData(hash, const_cast<PUCHAR>(bytes), static_cast<ULONG>(count), 0) < 0) failClosed();
    const NTSTATUS status = BCryptFinishHash(hash, out.data(), out.size(), 0);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0) failClosed();
    return out;
}
std::string fileHash(const std::filesystem::path& path) {
    // No FILE_SHARE_WRITE/DELETE: hold the verified object against replacement
    // for this process lifetime, not just the instant when its path was checked.
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (file == INVALID_HANDLE_VALUE) failClosed();
    static std::vector<HANDLE> heldFiles;
    heldFiles.push_back(file);
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectSize = 0, got = 0;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
        BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize), &got, 0) < 0) failClosed();
    std::vector<unsigned char> object(objectSize), chunk(65536);
    if (BCryptCreateHash(algorithm, &hash, object.data(), object.size(), nullptr, 0, 0) < 0) failClosed();
    do {
        if (!ReadFile(file, chunk.data(), chunk.size(), &got, nullptr)) failClosed();
        if (got && BCryptHashData(hash, chunk.data(), got, 0) < 0) failClosed();
    } while (got);
    std::array<unsigned char, 32> result{};
    if (BCryptFinishHash(hash, result.data(), result.size(), 0) < 0) failClosed();
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    std::string text;
    const char* hex = "0123456789abcdef";
    for (auto b : result) { text += hex[b >> 4]; text += hex[b & 15]; }
    return text;
}
std::map<std::string, std::string> manifest(const std::filesystem::path& root) {
    const auto bytes = read(root / L"client-integrity.manifest", 1024 * 1024);
    auto signature = read(root / L"client-integrity.sig", 4096);
    const auto hash = digest(bytes.data(), bytes.size());
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_RSA_ALGORITHM, nullptr, 0) < 0 ||
        BCryptImportKeyPair(algorithm, nullptr, BCRYPT_RSAPUBLIC_BLOB, &key,
            const_cast<PUCHAR>(kClientTrustKey), sizeof(kClientTrustKey), 0) < 0) failClosed();
    BCRYPT_PKCS1_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM};
    const auto status = BCryptVerifySignature(key, &padding, const_cast<PUCHAR>(hash.data()), hash.size(),
                                              signature.data(), signature.size(), BCRYPT_PAD_PKCS1);
    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0) failClosed();
    std::string text(bytes.begin(), bytes.end());
    const std::string prefix = std::string("NOVAPROTECT-CLIENT-1\n") + NOVAPROTECT_PRODUCT_VERSION + "\n";
    if (text.compare(0, prefix.size(), prefix) != 0) failClosed();
    size_t pos = prefix.size();
    std::map<std::string, std::string> hashes;
    while (pos < text.size()) {
        const auto end = text.find('\n', pos);
        if (end == std::string::npos || end - pos < 67 || text.substr(pos + 64, 2) != "  ") failClosed();
        const auto name = text.substr(pos + 66, end - pos - 66);
        if (name.find("..") != std::string::npos || name.find(':') != std::string::npos || name.front() == '/' ||
            !hashes.emplace(name, text.substr(pos, 64)).second) failClosed();
        pos = end + 1;
    }
    return hashes;
}
std::filesystem::path processPath(HANDLE process) {
    std::wstring path(32768, L'\0');
    DWORD size = static_cast<DWORD>(path.size());
    if (!QueryFullProcessImageNameW(process, 0, path.data(), &size)) failClosed();
    path.resize(size);
    return path;
}
DWORD parentPid() {
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    PROCESSENTRY32W entry{}; entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot.value, &entry)) failClosed();
    do { if (entry.th32ProcessID == GetCurrentProcessId()) return entry.th32ParentProcessID; }
    while (Process32NextW(snapshot.value, &entry));
    failClosed();
}
void pipeTransfer(HANDLE pipe, void* bytes, DWORD count, bool writing) {
    auto* cursor = static_cast<unsigned char*>(bytes);
    DWORD remaining = count;
    while (remaining > 0) {
        Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        OVERLAPPED operation{}; operation.hEvent = event.value;
        DWORD actual = 0;
        const BOOL ok = writing
            ? WriteFile(pipe, cursor, remaining, &actual, &operation)
            : ReadFile(pipe, cursor, remaining, &actual, &operation);
        if (!ok) {
            if (GetLastError() != ERROR_IO_PENDING || WaitForSingleObject(event.value, 8000) != WAIT_OBJECT_0) {
                CancelIoEx(pipe, &operation); failClosed();
            }
            if (!GetOverlappedResult(pipe, &operation, &actual, FALSE)) failClosed();
        }
        if (actual == 0 || actual > remaining) failClosed();
        cursor += actual;
        remaining -= actual;
    }
}
DWORD WINAPI monitorParent(void* value) {
    WaitForSingleObject(static_cast<HANDLE>(value), INFINITE);
    failClosed();
}
}

[[noreturn]] void failClosed() {
    fprintf(stderr, "[gate] rejected at %s (win32=%lu)\n", gateStage, static_cast<unsigned long>(GetLastError()));
    fflush(stderr);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    RaiseFailFastException(nullptr, nullptr, 0);
    TerminateProcess(GetCurrentProcess(), 0xC0000409);
    std::abort();
}

void requireClientInvocation() {
    VMProtectBeginUltra("NovaProtect.ClientInvocation");
    gateStage = "pipe-name";
    wchar_t name[128]{};
    const auto n = GetEnvironmentVariableW(L"NOVAPROTECT_INVOCATION_PIPE", name, 128);
    SetEnvironmentVariableW(L"NOVAPROTECT_INVOCATION_PIPE", nullptr);
    const std::wstring prefix = L"novaprotect-";
    if (n != prefix.size() + 32 || std::wstring(name, prefix.size()) != prefix) failClosed();
    for (DWORD i = static_cast<DWORD>(prefix.size()); i < n; ++i) if (!(name[i] >= '0' && name[i] <= '9') && !(name[i] >= 'a' && name[i] <= 'f')) failClosed();
    const std::wstring pipePath = L"\\\\.\\pipe\\" + std::wstring(name);
    gateStage = "wait-pipe";
    if (!WaitNamedPipeW(pipePath.c_str(), 8000)) failClosed();
    Handle pipe(CreateFileW(pipePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                             FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr));
    if (pipe.value == INVALID_HANDLE_VALUE) failClosed();
    gateStage = "server-pid";
    ULONG server = 0;
    if (!GetNamedPipeServerProcessId(pipe.value, &server) || server != parentPid()) failClosed();
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, server);
    if (!process) failClosed();
    gateStage = "parent-image";
    const auto self = processPath(GetCurrentProcess());
    const auto expected = self.parent_path() / L"NovaProtect.exe";
    if (_wcsicmp(processPath(process).c_str(), expected.c_str()) != 0 || WaitForSingleObject(process, 0) != WAIT_TIMEOUT) failClosed();
    gateStage = "signed-manifest";
    auto hashes = manifest(self.parent_path());
    for (const auto& filename : {"NovaProtect.exe", "NovaProtect.dll", "NovaProtect.Engine.exe", "NovaProtect.ManagedHost.exe"}) {
        gateStage = filename;
        auto found = hashes.find(filename);
        if (found == hashes.end() || fileHash(self.parent_path() / filename) != found->second) failClosed();
    }
    gateStage = "challenge";
    std::array<unsigned char, 40> challenge{};
    const unsigned char magic[8] = {'N','P','G','A','T','E','0','1'};
    std::copy(std::begin(magic), std::end(magic), challenge.begin());
    if (BCryptGenRandom(nullptr, challenge.data() + 8, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) failClosed();
    pipeTransfer(pipe.value, challenge.data(), challenge.size(), true);
    std::array<unsigned char, 40> answer{};
    pipeTransfer(pipe.value, answer.data(), answer.size(), false);
    if (answer != challenge) failClosed();
    Handle thread(CreateThread(nullptr, 0, monitorParent, process, 0, nullptr));
    if (!thread.value) failClosed();
    VMProtectEnd();
}
}
