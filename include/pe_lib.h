#pragma once
// NovaProtect PE Library - Parse, analyze, modify and rebuild PE files
#include "pe_types.h"
#include <memory>
#include <functional>
#include <unordered_map>

namespace np {

class PELib {
public:
    PELib() = default;
    ~PELib() = default;

    // Load PE from file or memory
    bool load(const std::string& filepath);
    bool load(const std::wstring& filepath);
    bool load(const uint8_t* data, size_t size);

    // Save PE to file
    bool save(const std::string& filepath);
    bool save(const std::wstring& filepath);

    // Basic info
    bool is64() const { return is64_; }
    bool is32() const { return !is64_; }
    uint64_t imageBase() const;
    uint32_t imageSize() const;
    uint32_t entryPoint() const { return ep_; }
    uint32_t sectionAlignment() const { return sectAlign_; }
    uint32_t fileAlignment() const { return fileAlign_; }
    size_t sectionCount() const { return sections_.size(); }
    const SectionHeader& section(size_t idx) const { return sections_[idx]; }
    SectionHeader& section(size_t idx) { return sections_[idx]; }
    const char* sectionName(size_t idx) const { return sections_[idx].Name; }

    // Address conversion
    uint32_t rvaToOffset(uint32_t rva) const;
    uint32_t offsetToRva(uint32_t offset) const;
    uint8_t* rvaToPtr(uint32_t rva);
    const uint8_t* rvaToPtr(uint32_t rva) const;

    // Data directory access
    DataDirectory* dataDirectory(int index);
    const DataDirectory* dataDirectory(int index) const;

    // Section manipulation
    int addSection(const char* name, uint32_t virtualSize, uint32_t characteristics);
    void setSectionData(size_t idx, const std::vector<uint8_t>& data);
    std::vector<uint8_t>& sectionData(size_t idx) { return sectionData_[idx]; }

    // Import table analysis
    struct ImportInfo {
        std::string dll_name;
        std::vector<std::string> functions;
        uint32_t iat_rva;       // FirstThunk
        uint32_t orig_rva;      // OriginalFirstThunk (INT)
        size_t count;
    };
    std::vector<ImportInfo> getImports() const;

    // Export table analysis
    struct ExportInfo {
        std::string name;
        uint32_t ordinal;
        uint32_t rva;
    };
    std::vector<ExportInfo> getExports() const;

    // Relocation analysis
    struct RelocEntry {
        uint32_t rva;
        uint16_t type;
    };
    std::vector<RelocEntry> getRelocations() const;

    // Set entry point
    void setEntryPoint(uint32_t rva) { ep_ = rva; }

    // Raw data access
    const std::vector<uint8_t>& data() const { return data_; }
    std::vector<uint8_t>& data() { return data_; }
    size_t size() const { return data_.size(); }

    // Search for byte pattern in code sections
    std::vector<uint32_t> searchPattern(const uint8_t* pattern, size_t pattern_len, const uint8_t* mask = nullptr);
    
    // Find SDK markers (VMProtectBegin/End style)
    struct SDKMarker {
        uint32_t rva;
        std::string name;  // function name from marker
        int type;           // 0=begin, 1=end
    };
    std::vector<SDKMarker> findMarkers();

    // Get image checksum
    uint32_t computeChecksum() const;

    // Update headers after modifications
    void updateHeaders();

    // Calculate RVA for new section
    uint32_t nextSectionRVA() const;
    uint32_t nextSectionFileOffset() const;

    // Error info
    const std::string& lastError() const { return lastError_; }

    // Get pointer to DOS header
    DOSHeader* dosHeader() { return reinterpret_cast<DOSHeader*>(data_.data()); }
    const DOSHeader* dosHeader() const { return reinterpret_cast<const DOSHeader*>(data_.data()); }
    PEHeader* peHeader() { return reinterpret_cast<PEHeader*>(data_.data() + dosHeader()->e_lfanew); }
    const PEHeader* peHeader() const { return reinterpret_cast<const PEHeader*>(data_.data() + dosHeader()->e_lfanew); }
    
    // Get optional header (returns raw pointer, cast as needed)
    uint8_t* optionalHeader() { return reinterpret_cast<uint8_t*>(peHeader()) + sizeof(PEHeader); }
    const uint8_t* optionalHeader() const { return reinterpret_cast<const uint8_t*>(peHeader()) + sizeof(PEHeader); }

    // Section data from file
    std::vector<uint8_t> getSectionFileData(size_t idx) const;

private:
    void parseHeaders();
    void loadSections();
    bool validatePE();
    
    std::vector<uint8_t> data_;
    bool is64_ = false;
    uint32_t ep_ = 0;
    uint32_t sectAlign_ = 0x1000;
    uint32_t fileAlign_ = 0x200;
    uint64_t imageBase_ = 0x140000000;
    std::vector<SectionHeader> sections_;
    std::vector<std::vector<uint8_t>> sectionData_;
    std::string lastError_;
};

// Utility functions
namespace util {
    uint32_t alignUp(uint32_t value, uint32_t alignment);
    uint32_t alignDown(uint32_t value, uint32_t alignment);
    uint32_t fnv1a_hash(const uint8_t* data, size_t len, uint32_t seed = 0x811C9DC5);
    uint64_t fnv1a_hash64(const uint8_t* data, size_t len, uint64_t seed = 0xCBF29CE484222325);
    void xor_crypt(uint8_t* data, size_t len, const uint8_t* key, size_t key_len);
    std::vector<uint8_t> lz4_compress(const uint8_t* data, size_t len);
    std::vector<uint8_t> lz4_decompress(const uint8_t* data, size_t compressed_len, size_t expected_len);
}

} // namespace np

