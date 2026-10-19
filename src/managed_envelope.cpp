#include "managed_envelope.h"

#include <windows.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>
#include <vector>

namespace np {
namespace {

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

constexpr std::array<uint8_t, 16> kKeyMask = {
    0x4E, 0x6F, 0x76, 0x61, 0x50, 0x72, 0x6F, 0x74,
    0x65, 0x63, 0x74, 0x32, 0x2E, 0x30, 0x21, 0xA7
};

uint64_t fnv1a64(const uint8_t* data, size_t size) {
    uint64_t hash = 0xCBF29CE484222325ull;
    for (size_t i = 0; i < size; ++i) {
        hash ^= data[i];
        hash *= 0x100000001B3ull;
    }
    return hash;
}

void xteaBlock(uint32_t& left, uint32_t& right, const uint32_t key[4]) {
    uint32_t sum = 0;
    constexpr uint32_t delta = 0x9E3779B9u;
    for (int round = 0; round < 32; ++round) {
        left += (((right << 4) ^ (right >> 5)) + right) ^ (sum + key[sum & 3]);
        sum += delta;
        right += (((left << 4) ^ (left >> 5)) + left) ^ (sum + key[(sum >> 11) & 3]);
    }
}

void cryptPayload(std::vector<uint8_t>& data, const std::array<uint8_t, 16>& keyBytes, uint64_t nonce) {
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

bool readFile(const std::filesystem::path& path, std::vector<uint8_t>& bytes) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) return false;
    const auto size = input.tellg();
    if (size < 0) return false;
    bytes.resize(static_cast<size_t>(size));
    input.seekg(0);
    return bytes.empty() || static_cast<bool>(input.read(reinterpret_cast<char*>(bytes.data()), size));
}

std::filesystem::path executableDirectory() {
    std::wstring path(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    path.resize(length);
    return std::filesystem::path(path).parent_path();
}

uint16_t readSubsystem(const std::vector<uint8_t>& image) {
    if (image.size() < 0x100 || image[0] != 'M' || image[1] != 'Z') return 2;
    uint32_t peOffset = 0;
    std::memcpy(&peOffset, image.data() + 0x3c, 4);
    if (static_cast<uint64_t>(peOffset) + 24 + 70 > image.size()) return 2;
    uint16_t subsystem = 2;
    std::memcpy(&subsystem, image.data() + peOffset + 24 + 68, 2);
    return subsystem;
}

void patchSubsystem(std::vector<uint8_t>& image, uint16_t subsystem) {
    if (image.size() < 0x100 || image[0] != 'M' || image[1] != 'Z') return;
    uint32_t peOffset = 0;
    std::memcpy(&peOffset, image.data() + 0x3c, 4);
    if (static_cast<uint64_t>(peOffset) + 24 + 70 > image.size()) return;
    std::memcpy(image.data() + peOffset + 24 + 68, &subsystem, 2);
}

}

bool protectManagedExecutable(const std::wstring& input_path,
                              const std::wstring& output_path,
                              std::string& error) {
    std::vector<uint8_t> payload;
    if (!readFile(std::filesystem::path(input_path), payload)) {
        error = "cannot read managed input";
        return false;
    }

    const auto hostPath = executableDirectory() / L"NovaProtect.ManagedHost.exe";
    std::vector<uint8_t> host;
    if (!readFile(hostPath, host)) {
        error = "managed host not found beside NovaProtect.Engine.exe";
        return false;
    }

    patchSubsystem(host, readSubsystem(payload));

    std::array<uint8_t, 16> key{};
    std::random_device rd;
    std::mt19937_64 rng((static_cast<uint64_t>(rd()) << 32) ^ rd() ^
                        static_cast<uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count()));
    for (auto& byte : key) byte = static_cast<uint8_t>(rng());
    const uint64_t nonce = rng();
    const uint64_t integrity = fnv1a64(payload.data(), payload.size());
    cryptPayload(payload, key, nonce);

    ManagedTrailer trailer{};
    std::memcpy(trailer.magic, "NVPE2\0\0", 8);
    trailer.version = 2;
    trailer.flags = 1;
    trailer.payload_offset = host.size();
    trailer.payload_size = payload.size();
    trailer.original_size = payload.size();
    trailer.integrity = integrity;
    trailer.nonce = nonce;
    for (size_t i = 0; i < key.size(); ++i) trailer.masked_key[i] = key[i] ^ kKeyMask[i];

    const auto originalName = std::filesystem::path(input_path).filename().u8string();
    trailer.original_name_length = static_cast<uint32_t>(std::min<size_t>(originalName.size(), sizeof(trailer.original_name) - 1));
    std::memcpy(trailer.original_name, originalName.data(), trailer.original_name_length);

    std::ofstream output(std::filesystem::path(output_path), std::ios::binary | std::ios::trunc);
    if (!output) {
        error = "cannot create managed output";
        return false;
    }
    output.write(reinterpret_cast<const char*>(host.data()), static_cast<std::streamsize>(host.size()));
    output.write(reinterpret_cast<const char*>(payload.data()), static_cast<std::streamsize>(payload.size()));
    output.write(reinterpret_cast<const char*>(&trailer), sizeof(trailer));
    if (!output) {
        error = "failed while writing managed envelope";
        return false;
    }
    return true;
}

}
