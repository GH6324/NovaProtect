#include <windows.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include "../include/vmp_markers.h"

#pragma pack(push, 1)
struct ManagedTrailer {
    char magic[8];
    uint32_t version;
    uint32_t flags;
    uint64_t payload_offset;
    uint64_t payload_size;
    uint64_t original_size;
    uint64_t integrity;
    uint64_t nonce;
    uint8_t masked_key[16];
    uint32_t original_name_length;
    char original_name[260];
};
#pragma pack(pop)

static constexpr std::array<uint8_t, 16> kKeyMask = {
    0x4E, 0x6F, 0x76, 0x61, 0x50, 0x72, 0x6F, 0x74,
    0x65, 0x63, 0x74, 0x32, 0x2E, 0x30, 0x21, 0xA7
};

static uint64_t fnv1a64(const uint8_t* data, size_t size) {
    uint64_t hash = 0xCBF29CE484222325ull;
    for (size_t i = 0; i < size; ++i) {
        hash ^= data[i];
        hash *= 0x100000001B3ull;
    }
    return hash;
}

static void xteaBlock(uint32_t& left, uint32_t& right, const uint32_t key[4]) {
    VMProtectBeginUltra("NovaProtect.ManagedPayloadCipher");
    uint32_t sum = 0;
    constexpr uint32_t delta = 0x9E3779B9u;
    for (int round = 0; round < 32; ++round) {
        left += (((right << 4) ^ (right >> 5)) + right) ^ (sum + key[sum & 3]);
        sum += delta;
        right += (((left << 4) ^ (left >> 5)) + left) ^ (sum + key[(sum >> 11) & 3]);
    }
    VMProtectEnd();
}

static void cryptPayload(std::vector<uint8_t>& data, const std::array<uint8_t, 16>& keyBytes, uint64_t nonce) {
    uint32_t key[4]{};
    std::memcpy(key, keyBytes.data(), sizeof(key));
    for (uint64_t offset = 0, counter = 0; offset < data.size(); offset += 8, ++counter) {
        uint32_t left = static_cast<uint32_t>(nonce ^ counter);
        uint32_t right = static_cast<uint32_t>((nonce >> 32) ^ (counter * 0x9E3779B9ull));
        xteaBlock(left, right, key);
        uint8_t stream[8];
        std::memcpy(stream, &left, 4);
        std::memcpy(stream + 4, &right, 4);
        const size_t count = std::min<size_t>(8, data.size() - static_cast<size_t>(offset));
        for (size_t i = 0; i < count; ++i) data[static_cast<size_t>(offset) + i] ^= stream[i];
    }
}

static std::wstring modulePath() {
    std::wstring path(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    path.resize(length);
    return path;
}

static std::wstring utf8ToWide(const char* data, int length) {
    const int required = MultiByteToWideChar(CP_UTF8, 0, data, length, nullptr, 0);
    if (required <= 0) return L"managed-payload.exe";
    std::wstring value(required, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, data, length, value.data(), required);
    const size_t slash = value.find_last_of(L"\\/");
    if (slash != std::wstring::npos) value.erase(0, slash + 1);
    return value.empty() ? L"managed-payload.exe" : value;
}

static const wchar_t* commandLineTail(const wchar_t* line) {
    if (!line) return L"";
    bool quoted = false;
    while (*line) {
        if (*line == L'"') quoted = !quoted;
        else if (!quoted && (*line == L' ' || *line == L'\t')) break;
        ++line;
    }
    while (*line == L' ' || *line == L'\t') ++line;
    return line;
}

int wmain() {
    const std::wstring self = modulePath();
    HANDLE file = CreateFileW(self.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (file == INVALID_HANDLE_VALUE) return 70;

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart < static_cast<LONGLONG>(sizeof(ManagedTrailer))) {
        CloseHandle(file);
        return 71;
    }
    ManagedTrailer trailer{};
    LARGE_INTEGER trailerOffset{};
    trailerOffset.QuadPart = size.QuadPart - sizeof(trailer);
    SetFilePointerEx(file, trailerOffset, nullptr, FILE_BEGIN);
    DWORD read = 0;
    if (!ReadFile(file, &trailer, sizeof(trailer), &read, nullptr) || read != sizeof(trailer) ||
        std::memcmp(trailer.magic, "NVPE2\0\0", 8) != 0 || trailer.version != 2 ||
        trailer.payload_offset + trailer.payload_size > static_cast<uint64_t>(trailerOffset.QuadPart)) {
        CloseHandle(file);
        // The shipped template is not a standalone API/program. An actual
        // protected payload has a validated trailer and remains independent.
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
        RaiseFailFastException(nullptr, nullptr, 0);
        TerminateProcess(GetCurrentProcess(), 0xC0000409);
        return 72;
    }

    std::vector<uint8_t> payload(static_cast<size_t>(trailer.payload_size));
    LARGE_INTEGER payloadOffset{};
    payloadOffset.QuadPart = static_cast<LONGLONG>(trailer.payload_offset);
    SetFilePointerEx(file, payloadOffset, nullptr, FILE_BEGIN);
    if (!ReadFile(file, payload.data(), static_cast<DWORD>(payload.size()), &read, nullptr) || read != payload.size()) {
        CloseHandle(file);
        return 73;
    }
    CloseHandle(file);

    std::array<uint8_t, 16> key{};
    for (size_t i = 0; i < key.size(); ++i) key[i] = trailer.masked_key[i] ^ kKeyMask[i];
    cryptPayload(payload, key, trailer.nonce);
    if (payload.size() != trailer.original_size || fnv1a64(payload.data(), payload.size()) != trailer.integrity) return 74;

    const size_t slash = self.find_last_of(L"\\/");
    const std::wstring directory = slash == std::wstring::npos ? L"." : self.substr(0, slash);
    const std::wstring originalName = utf8ToWide(trailer.original_name,
        static_cast<int>(std::min<uint32_t>(trailer.original_name_length, sizeof(trailer.original_name))));
    wchar_t cacheName[96]{};
    std::swprintf(cacheName, 96, L".novaprotect-%016llX-", static_cast<unsigned long long>(trailer.integrity));
    const std::wstring extracted = directory + L"\\" + cacheName + originalName;

    HANDLE output = CreateFileW(extracted.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (output == INVALID_HANDLE_VALUE) return 75;
    DWORD written = 0;
    const bool wrote = WriteFile(output, payload.data(), static_cast<DWORD>(payload.size()), &written, nullptr) &&
                       written == payload.size();
    FlushFileBuffers(output);
    CloseHandle(output);
    if (!wrote) {
        DeleteFileW(extracted.c_str());
        return 76;
    }

    std::wstring childCommand = L"\"" + extracted + L"\"";
    const wchar_t* tail = commandLineTail(GetCommandLineW());
    if (tail && *tail) childCommand += L" " + std::wstring(tail);
    std::vector<wchar_t> command(childCommand.begin(), childCommand.end());
    command.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    const BOOL started = CreateProcessW(extracted.c_str(), command.data(), nullptr, nullptr, TRUE, 0, nullptr,
                                        directory.c_str(), &startup, &process);
    if (!started) {
        DeleteFileW(extracted.c_str());
        return 77;
    }
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD exitCode = 1;
    GetExitCodeProcess(process.hProcess, &exitCode);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    for (int attempt = 0; attempt < 20 && !DeleteFileW(extracted.c_str()); ++attempt) Sleep(50);
    return static_cast<int>(exitCode);
}
