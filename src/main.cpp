// NovaProtect CLI
#include "product_version.h"
#include "packer.h"
#include "pe_lib.h"
#include "managed_envelope.h"
#include "client_gate.h"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstdlib>
#include <cctype>
#include <cpuid.h>
#include <algorithm>
#include <sys/stat.h>
#include <filesystem>
#include <windows.h>

using namespace np;

static bool contains_bytes(const std::vector<uint8_t>& data, const std::string& value) {
    if (value.empty() || data.size() < value.size()) return false;
    return std::search(data.begin(), data.end(), value.begin(), value.end()) != data.end();
}

static bool regular_file_exists(const std::string& path) {
    struct stat info{};
    return stat(path.c_str(), &info) == 0 && (info.st_mode & S_IFREG) != 0;
}

static bool is_managed_apphost(const std::string& filepath, const std::vector<uint8_t>& image) {
    const auto slash = filepath.find_last_of("/\\");
    const auto filename = slash == std::string::npos ? filepath : filepath.substr(slash + 1);
    const auto dot = filename.find_last_of('.');
    if (dot == std::string::npos || filename.substr(dot) != ".exe") return false;
    const auto basePath = filepath.substr(0, filepath.size() - 4);
    const auto dll = basePath + ".dll";
    const auto runtimeConfig = basePath + ".runtimeconfig.json";
    if (!regular_file_exists(dll) || !regular_file_exists(runtimeConfig)) return false;
    const auto dllName = filename.substr(0, dot) + ".dll";
    return contains_bytes(image, dllName);
}

static void print_usage(const char* prog) {
    printf("%s v%s - Windows EXE Protector\n", NOVAPROTECT_PRODUCT_NAME, NOVAPROTECT_PRODUCT_VERSION);
    printf("Usage: %s <input.exe> [-o output.exe] [options]\n", prog);
    printf("Inputs: native C/C++, Rust and Golang PE; C#/VB .NET EXE envelope\n");
    printf("Modes:\n");
    printf("  -mode <name>       mutation | virtualization | ultra\n");
    printf("  -mut <0-3>         Mutation strength\n");
    printf("  -vm <0-10>         VM complexity\n");
    printf("  -ad <0-3>          Anti-debug level\n");
    printf("  -avm <0-2>         Anti-VM level\n");
    printf("Protection:\n");
    printf("  -memory            Memory integrity protection\n");
    printf("  -imports           Import protection metadata/checks\n");
    printf("  -resources         Pack and protect resource sections\n");
    printf("  -nopack            Disable packing\n");
    printf("  -keepdebug         Keep debug directory entries\n");
    printf("  -noencrypt         Store packed regions without payload encryption\n");
    printf("  -stripreloc        Remove relocation directory and disable ASLR (EXE only)\n");
    printf("  -stripexport       Remove export directory (EXE only)\n");
    printf("Additional:\n");
    printf("  -watermark <text>  Embed watermark\n");
    printf("  -script <file>     Simple key=value protection script\n");
    printf("  -license <key>     Enable license verification\n");
    printf("  -activation <id>   Bind x64 runtime to 64-bit machine id (hex or auto)\n");
    printf("  -machineid         Print this machine's activation id\n");
    printf("  -region <spec>     SDK region rule: start-end-mode-vm-mut-lock\n");
    printf("  -vf <file>         Embed a virtual file (repeatable)\n");
    printf("  -info              Show PE info\n");
    printf("Inspection:\n");
    printf("  -showwatermark     Print the watermark of a packed image\n");
    printf("  -listvf            List virtual files embedded in a packed image\n");
    printf("  -extractvf <name>  Extract one embedded virtual file\n");
}

static void print_pe_info(const char* filepath) {
    PELib pe;
    if (!pe.load(filepath)) { printf("Error: %s\n", pe.lastError().c_str()); return; }
    const auto* com = pe.dataDirectory(14);
    const bool managed = (com && com->VirtualAddress != 0 && com->Size != 0) ||
                         is_managed_apphost(filepath, pe.data());
    printf("PE: %s\n  Arch: %s  Runtime: %s  Base: 0x%llX  EP: 0x%X  Size: 0x%X  Sections: %zu\n",
        filepath, pe.is64()?"x64":"x86",
        managed ? "CLR (.NET C#/VB)" : "native (C/C++/Rust/Go)",
        (unsigned long long)pe.imageBase(), pe.entryPoint(), pe.imageSize(), pe.sectionCount());
    for (size_t i = 0; i < pe.sectionCount(); i++) {
        auto& s = pe.section(i);
        char name[9] = {}; memcpy(name, s.Name, 8);
        printf("  [%2zu] %-8s VA=0x%08X VS=0x%08X RS=0x%08X %s\n",
            i, name, s.VirtualAddress, s.VirtualSize, s.SizeOfRawData,
            section_flags_str(s.Characteristics).c_str());
    }
    auto imps = pe.getImports();
    printf("  Imports: %zu DLLs\n", imps.size());
    for (auto& im : imps) printf("    %s (%zu fns)\n", im.dll_name.c_str(), im.count);
}

static bool parse_bool(const std::string& value) {
    return value == "1" || value == "true" || value == "yes" || value == "on";
}

static bool parse_range(const std::string& value, int min, int max, uint8_t& out) {
    char* end = nullptr;
    long parsed = std::strtol(value.c_str(), &end, 10);
    if (!end || *end != '\0' || parsed < min || parsed > max) return false;
    out = static_cast<uint8_t>(parsed);
    return true;
}

static bool parse_range_u32(const std::string& value, unsigned long min, unsigned long max, uint32_t& out) {
    char* end = nullptr;
    unsigned long parsed = std::strtoul(value.c_str(), &end, 10);
    if (!end || *end != '\0' || parsed < min || parsed > max) return false;
    out = static_cast<uint32_t>(parsed);
    return true;
}

static uint64_t fnv64_bytes(const void* bytes, size_t size, uint64_t hash = 0xCBF29CE484222325ull) {
    const auto* data = static_cast<const unsigned char*>(bytes);
    for (size_t i = 0; i < size; ++i) { hash ^= data[i]; hash *= 0x100000001B3ull; }
    return hash;
}

static uint64_t machine_guid_hash() {
    // HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid is derived from the
    // machine's hardware identity (motherboard + install identity) and is the
    // most stable single-machine factor available without kernel drivers. In
    // online-analysis sandboxes it is frequently absent, zero, or one of a
    // small set of known template GUIDs.
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ, &key) != ERROR_SUCCESS) return 0;
    wchar_t guid[64] = {};
    DWORD size = sizeof(guid);
    DWORD type = 0;
    LSTATUS rc = RegQueryValueExW(key, L"MachineGuid", nullptr, &type, reinterpret_cast<BYTE*>(guid), &size);
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS || type != REG_SZ) return 0;
    uint64_t h = 0xCBF29CE484222325ull;
    for (wchar_t* p = guid; *p; ++p) {
        unsigned char lo = (unsigned char)(*p & 0xFF);
        unsigned char hi = (unsigned char)((*p >> 8) & 0xFF);
        h = fnv64_bytes(&lo, 1, h);
        h = fnv64_bytes(&hi, 1, h);
    }
    return h;
}

static uint64_t volume_serial() {
    // The system drive volume serial number is a per-machine, per-installation
    // identifier, so it separates two machines that share the same CPU model.
    // On failure the fingerprint degrades to the CPUID component only.
    wchar_t sysroot[MAX_PATH] = {};
    UINT count = GetSystemDirectoryW(sysroot, MAX_PATH);
    if (count == 0 || count >= MAX_PATH) return 0;
    wchar_t root[4] = { sysroot[0], L':', L'\\', L'\0' };
    DWORD serial = 0;
    if (!GetVolumeInformationW(root, nullptr, 0, &serial, nullptr, nullptr, nullptr, 0)) return 0;
    return (uint64_t)serial;
}

static uint64_t current_machine_id() {
    unsigned int a = 0, b = 0, c = 0, d = 0;
    uint64_t h = 0xCBF29CE484222325ull;
    if (__get_cpuid(0, &a, &b, &c, &d)) {
        h = fnv64_bytes(&b, sizeof(b), h);
        h = fnv64_bytes(&d, sizeof(d), h);
        h = fnv64_bytes(&c, sizeof(c), h);
    }
    if (__get_cpuid(1, &a, &b, &c, &d)) {
        h = fnv64_bytes(&a, sizeof(a), h);
        h = fnv64_bytes(&c, sizeof(c), h);
        h = fnv64_bytes(&d, sizeof(d), h);
    }
    if (__get_cpuid_count(7, 0, &a, &b, &c, &d)) {
        h = fnv64_bytes(&b, sizeof(b), h);
        h = fnv64_bytes(&c, sizeof(c), h);
        h = fnv64_bytes(&d, sizeof(d), h);
    }
    // Mix the volume serial and machine GUID in via FNV-1a so the
    // components are bound cryptographically rather than XORed. The
    // GUID is the primary stability anchor; the volume serial is a
    // per-installation discriminator.
    uint64_t vs = volume_serial();
    uint64_t mg = machine_guid_hash();
    h = fnv64_bytes(&vs, sizeof(vs), h);
    h = fnv64_bytes(&mg, sizeof(mg), h);
    return h;
}
static bool parse_region_spec(const std::string& spec, FunctionProtect& out, std::string& error) {
    std::vector<std::string> parts;
    size_t pos = 0;
    while (pos <= spec.size()) {
        size_t next = spec.find('-', pos);
        parts.push_back(spec.substr(pos, next == std::string::npos ? std::string::npos : next - pos));
        if (next == std::string::npos) break;
        pos = next + 1;
    }
    if (parts.size() != 6) { error = "region spec must be start-end-mode-vm-mut-lock"; return false; }
    char* end = nullptr;
    unsigned long start = std::strtoul(parts[0].c_str(), &end, 16);
    if (!end || *end) { error = "invalid region start RVA"; return false; }
    unsigned long finish = std::strtoul(parts[1].c_str(), &end, 16);
    if (!end || *end || finish <= start) { error = "invalid region end RVA"; return false; }
    out.rva_start = (uint32_t)start;
    out.rva_end = (uint32_t)finish;
    if (parts[2] == "inherit") out.level = ProtectLevel::None;
    else if (parts[2] == "skip") out.level = ProtectLevel::None;
    else if (parts[2] == "virtualization") out.level = ProtectLevel::Virtualization;
    else if (parts[2] == "ultra") out.level = ProtectLevel::Ultra;
    else { error = "invalid region mode"; return false; }
    out.name = parts[2] == "skip" ? "skip" : parts[2];
    if (!parse_range(parts[3], 0, 10, out.vm_complexity)) { error = "region VM complexity must be 0..10"; return false; }
    if (!parse_range(parts[4], 0, 3, out.vm_mutation)) { error = "region mutation must be 0..3"; return false; }
    out.vm_lock_to_key = parse_bool(parts[5]);
    return true;
}

static bool apply_option(PackerConfig& config, const std::string& key, const std::string& value, std::string& error) {
    if (key == "mode" || key == "protection") {
        std::string v = value; for (auto& c : v) c = (char)tolower((unsigned char)c);
        if (v != "mutation" && v != "virtualization" && v != "ultra") {
            error = "unsupported mode: " + value;
            return false;
        }
        config.enable_mutation = v == "mutation" || v == "ultra";
        config.enable_vm = v == "virtualization" || v == "ultra";
        config.mutation_strength = config.enable_mutation ? 3 : 0;
        config.vm_default_complexity = config.enable_vm ? 9 : 0;
    } else if (key == "mutation" || key == "mut") {
        if (!parse_range(value, 0, 3, config.mutation_strength)) { error = "mutation strength must be 0..3"; return false; }
        config.enable_mutation = config.mutation_strength > 0;
    } else if (key == "virtualization" || key == "vm") {
        if (!parse_range(value, 0, 10, config.vm_default_complexity)) { error = "VM complexity must be 0..10"; return false; }
        config.enable_vm = config.vm_default_complexity > 0;
    } else if (key == "anti-debug" || key == "ad") {
        if (!parse_range(value, 0, 3, config.anti_debug_level)) { error = "anti-debug level must be 0..3"; return false; }
    } else if (key == "anti-vm" || key == "avm") {
        if (!parse_range(value, 0, 2, config.anti_vm_level)) { error = "anti-VM level must be 0..2"; return false; }
    } else if (key == "memory-protection" || key == "memory") config.memory_protection = parse_bool(value);
    else if (key == "import-protection" || key == "imports") config.import_protection = parse_bool(value);
    else if (key == "resource-protection" || key == "resources") config.resource_protection = parse_bool(value);
    else if (key == "packing" || key == "pack") config.pack_sections = parse_bool(value);
    else if (key == "encryption" || key == "encrypt") config.encrypt_sections = parse_bool(value);
    else if (key == "strip-relocations" || key == "stripreloc") config.strip_relocations = parse_bool(value);
    else if (key == "strip-exports" || key == "stripexport") config.strip_export = parse_bool(value);
    else if (key == "strip-debug" || key == "stripdebug") config.strip_debug_info = parse_bool(value);
    else if (key == "watermark") { config.enable_watermark = !value.empty(); config.watermark = value; }
    else if (key == "license-key" || key == "license") { config.enable_licensing = !value.empty(); config.license_key = value; }
    else if (key == "activation") { config.enable_activation = !value.empty(); config.activation_key = value; }
    else if (key == "sandbox-guard" || key == "sandbox") config.enable_sandbox_guard = parse_bool(value);
    else if (key == "sandbox-threshold" || key == "sbox-thr") { if (!parse_range_u32(value, 0, 100, config.sandbox_score_threshold)) { error = "sandbox threshold must be 0..100"; return false; } }
    else if (key == "anti-dump" || key == "antidump") config.enable_anti_dump = parse_bool(value);
    else if (key == "env-check" || key == "envcheck") config.enable_env_check = parse_bool(value);
    else if (key == "min-cpu" || key == "mincpu") { if (!parse_range_u32(value, 1, 256, config.min_cpu_count)) { error = "min-cpu must be 1..256"; return false; } }
    else if (key == "min-ram-mb" || key == "minram") { if (!parse_range_u32(value, 0, 1048576, config.min_ram_mb)) { error = "min-ram-mb must be 0..1048576"; return false; } }
    else if (key == "min-uptime-ms" || key == "minuptime") { if (!parse_range_u32(value, 0, 4294967295ul, config.min_uptime_ms)) { error = "min-uptime-ms must be 0..4294967295"; return false; } }
    else if (key == "min-screen-w" || key == "minscreenw") { if (!parse_range_u32(value, 0, 32767, config.min_screen_width)) { error = "min-screen-w must be 0..32767"; return false; } }
    else if (key == "min-screen-h" || key == "minscreenh") { if (!parse_range_u32(value, 0, 32767, config.min_screen_height)) { error = "min-screen-h must be 0..32767"; return false; } }
    else if (key == "min-monitor" || key == "minmonitor") { if (!parse_range_u32(value, 0, 64, config.min_monitor_count)) { error = "min-monitor must be 0..64"; return false; } }
    else if (key == "virtual-file" || key == "vf") { config.enable_virtual_files = true; config.virtual_files.push_back(value); }
    else {
        error = "unsupported option in script: " + key;
        return false;
    }
    return true;
}

static bool load_script(const std::string& path, PackerConfig& config, std::string& error) {
    std::ifstream in(path);
    if (!in) { error = "cannot open script: " + path; return false; }
    std::string line;
    int line_no = 0;
    while (std::getline(in, line)) {
        ++line_no;
        size_t hash = line.find_first_of("#;");
        if (hash != std::string::npos) line.resize(hash);
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq), value = line.substr(eq + 1);
        auto trim = [](std::string& s) {
            size_t a = s.find_first_not_of(" \t\r\n"), b = s.find_last_not_of(" \t\r\n");
            s = a == std::string::npos ? "" : s.substr(a, b - a + 1);
        };
        trim(key); trim(value);
        if (!key.empty() && !apply_option(config, key, value, error)) {
            error += " (line " + std::to_string(line_no) + ")";
            return false;
        }
    }
    return true;
}

int wmain(int argc, wchar_t* argv[]) {
    np::requireClientInvocation();
    // A GUI host reads progress through redirected pipes. Disable stdio buffering so
    // every phase is visible immediately instead of arriving only when the process exits.
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
    const auto wide_to_utf8 = [](const std::wstring& value) {
        if (value.empty()) return std::string{};
        const int size = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
        if (size <= 0) return std::string{};
        std::string result(static_cast<size_t>(size), static_cast<char>(0));
        WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), size, nullptr, nullptr);
        return result;
    };
    std::vector<std::string> utf8Args;
    utf8Args.reserve(static_cast<size_t>(argc));
    std::vector<char*> narrowArgv;
    narrowArgv.reserve(static_cast<size_t>(argc));
    for (int i = 0; i < argc; ++i) utf8Args.push_back(wide_to_utf8(argv[i] ? std::wstring(argv[i]) : std::wstring{}));
    for (auto& value : utf8Args) narrowArgv.push_back(value.data());
    if (argc < 2) { print_usage(narrowArgv[0]); return 1; }
    std::string input, output;
    PackerConfig config;
    bool show_info = false;
    bool show_machine_id = false;
    bool show_watermark = false, list_vf = false;
    std::string extract_vf;
    std::string parse_error;

    for (int i = 1; i < argc; i++) {
        std::string arg = narrowArgv[i];
        if (arg[0] != '-') { if (input.empty()) input = arg; continue; }
        if (arg == "-info") show_info = true;
        else if (arg == "-machineid") show_machine_id = true;
        else if (arg == "-showwatermark") show_watermark = true;
        else if (arg == "-listvf") list_vf = true;
        else if (arg == "-extractvf" && i + 1 < argc) extract_vf = narrowArgv[++i];
        else if (arg == "-o" && i + 1 < argc) output = narrowArgv[++i];
        else if (arg == "-mode" && i + 1 < argc) { if (!apply_option(config, "mode", narrowArgv[++i], parse_error)) { printf("Error: %s\n", parse_error.c_str()); return 2; } }
        else if (arg == "-mut" && i + 1 < argc) { if (!apply_option(config, "mut", narrowArgv[++i], parse_error)) { printf("Error: %s\n", parse_error.c_str()); return 2; } }
        else if (arg == "-vm" && i + 1 < argc) { if (!apply_option(config, "vm", narrowArgv[++i], parse_error)) { printf("Error: %s\n", parse_error.c_str()); return 2; } }
        else if (arg == "-ad" && i + 1 < argc) { if (!apply_option(config, "ad", narrowArgv[++i], parse_error)) { printf("Error: %s\n", parse_error.c_str()); return 2; } }
        else if (arg == "-avm" && i + 1 < argc) { if (!apply_option(config, "avm", narrowArgv[++i], parse_error)) { printf("Error: %s\n", parse_error.c_str()); return 2; } }
        else if (arg == "-memory") config.memory_protection = true;
        else if (arg == "-imports") config.import_protection = true;
        else if (arg == "-resources") config.resource_protection = true;
        else if (arg == "-nopack") config.pack_sections = false;
        else if (arg == "-keepdebug") config.strip_debug_info = false;
        else if (arg == "-stripreloc") config.strip_relocations = true;
        else if (arg == "-stripexport") config.strip_export = true;
        else if (arg == "-noencrypt") config.encrypt_sections = false;
        else if (arg == "-vimports") config.import_protection = true;
        else if (arg == "-watermark" && i + 1 < argc) { if (!apply_option(config, "watermark", narrowArgv[++i], parse_error)) { printf("Error: %s\n", parse_error.c_str()); return 2; } }
        else if (arg == "-script" && i + 1 < argc) { config.enable_script = true; config.script_path = narrowArgv[++i]; }
        else if (arg == "-license" && i + 1 < argc) { if (!apply_option(config, "license", narrowArgv[++i], parse_error)) { printf("Error: %s\n", parse_error.c_str()); return 2; } }
        else if (arg == "-activation" && i + 1 < argc) { config.enable_activation = true; config.activation_key = narrowArgv[++i]; }
        else if (arg == "-region" && i + 1 < argc) {
            FunctionProtect region;
            if (!parse_region_spec(narrowArgv[++i], region, parse_error)) { printf("Error: %s\n", parse_error.c_str()); return 2; }
            config.function_regions.push_back(region);
        }
        else if (arg == "-vf" && i + 1 < argc) { if (!apply_option(config, "vf", narrowArgv[++i], parse_error)) { printf("Error: %s\n", parse_error.c_str()); return 2; } }
        else if (arg == "-sandbox-guard" || arg == "-sandbox") { config.enable_sandbox_guard = true; }
        else if (arg == "-anti-dump" || arg == "-antidump") { config.enable_anti_dump = true; }
        else if (arg == "-env-check" || arg == "-envcheck") { config.enable_env_check = true; }
        else if (arg == "-sandbox-threshold" && i + 1 < argc) { if (!apply_option(config, "sandbox-threshold", narrowArgv[++i], parse_error)) { printf("Error: %s\n", parse_error.c_str()); return 2; } }
        else if (arg == "-min-cpu" && i + 1 < argc) { if (!apply_option(config, "min-cpu", narrowArgv[++i], parse_error)) { printf("Error: %s\n", parse_error.c_str()); return 2; } }
        else if (arg == "-min-ram-mb" && i + 1 < argc) { if (!apply_option(config, "min-ram-mb", narrowArgv[++i], parse_error)) { printf("Error: %s\n", parse_error.c_str()); return 2; } }
        else if (arg == "-min-uptime-ms" && i + 1 < argc) { if (!apply_option(config, "min-uptime-ms", narrowArgv[++i], parse_error)) { printf("Error: %s\n", parse_error.c_str()); return 2; } }
        else if (arg == "-min-screen-w" && i + 1 < argc) { if (!apply_option(config, "min-screen-w", narrowArgv[++i], parse_error)) { printf("Error: %s\n", parse_error.c_str()); return 2; } }
        else if (arg == "-min-screen-h" && i + 1 < argc) { if (!apply_option(config, "min-screen-h", narrowArgv[++i], parse_error)) { printf("Error: %s\n", parse_error.c_str()); return 2; } }
        else if (arg == "-min-monitor" && i + 1 < argc) { if (!apply_option(config, "min-monitor", narrowArgv[++i], parse_error)) { printf("Error: %s\n", parse_error.c_str()); return 2; } }
        else { printf("Error: unknown option: %s\n", arg.c_str()); return 2; }
    }

    if (show_machine_id) { printf("%016llX\n", (unsigned long long)current_machine_id()); return 0; }
    if (input.empty()) { print_usage(narrowArgv[0]); return 1; }
    if (config.enable_script && !load_script(config.script_path, config, parse_error)) { printf("Error: %s\n", parse_error.c_str()); return 2; }
    if (show_info) { print_pe_info(input.c_str()); return 0; }
    if (show_watermark) {
        std::string wm, err;
        if (Packer::readWatermark(input, wm, err)) { printf("Watermark: %s\n", wm.c_str()); return 0; }
        printf("Error: %s\n", err.c_str()); return 1;
    }
    if (list_vf) {
        std::vector<std::string> names; std::string err;
        if (Packer::listVirtualFiles(input, names, err)) {
            printf("Virtual files (%zu):\n", names.size());
            for (auto& n : names) printf("  %s\n", n.c_str());
            return 0;
        }
        printf("Error: %s\n", err.c_str()); return 1;
    }
    if (!extract_vf.empty()) {
        std::vector<uint8_t> data; std::string err;
        if (Packer::extractVirtualFile(input, extract_vf, data, err)) {
            std::string outName = extract_vf;
            std::ofstream out(outName, std::ios::binary);
            out.write(reinterpret_cast<const char*>(data.data()), data.size());
            printf("Extracted %zu bytes -> %s\n", data.size(), outName.c_str());
            return 0;
        }
        printf("Error: %s\n", err.c_str()); return 1;
    }
    if (output.empty()) {
        size_t dot = input.rfind('.');
        output = (dot != std::string::npos) ? input.substr(0, dot) + "_packed" + input.substr(dot) : input + "_packed.exe";
    }

    PELib planPe;
    if (!planPe.load(input)) { printf("Error: %s\n", planPe.lastError().c_str()); return 1; }
    const bool requestedVm = config.enable_vm;
    const bool requestedMutation = config.enable_mutation;
    const bool effectiveVm = requestedVm && planPe.is64();
    const bool effectiveMutation = requestedMutation && planPe.is64();
    if (config.enable_licensing && !planPe.is64()) {
        printf("Error: license verification is supported only for x64 targets\n");
        return 2;
    }
    if (config.enable_activation) {
        if (!planPe.is64()) { printf("Error: activation binding is supported only for x64 targets\n"); return 2; }
        if (config.activation_key == "auto") {
            char id[17] = {};
            std::snprintf(id, sizeof(id), "%016llX", (unsigned long long)current_machine_id());
            config.activation_key = id;
        }
        char* end = nullptr;
        (void)std::strtoull(config.activation_key.c_str(), &end, 16);
        if (!end || *end || config.activation_key.empty() || config.activation_key.size() > 16) {
            printf("Error: activation id must be 1..16 hexadecimal digits or auto\n");
            return 2;
        }
    }
    for (const auto& region : config.function_regions) {
        if (region.vm_lock_to_key && !config.enable_activation) {
            printf("Error: activation-locked SDK region requires -activation\n");
            return 2;
        }
    }
    const bool isDll = (planPe.peHeader()->Characteristics & 0x2000u) != 0;
    const bool isManaged = (planPe.dataDirectory(14) && planPe.dataDirectory(14)->VirtualAddress != 0) ||
                           is_managed_apphost(input, planPe.data());
    const uint16_t machine = planPe.peHeader()->Machine;
    if (machine != MACHINE_X86 && machine != MACHINE_X64) {
        printf("Error: current core supports only native x86/x64 PE targets\n");
        return 2;
    }
    if (isManaged) {
        if (isDll) {
            printf("Error: %s %s supports managed EXE input, not managed DLL input\n",
                   NOVAPROTECT_PRODUCT_NAME, NOVAPROTECT_PRODUCT_VERSION);
            return 2;
        }
        if (config.strip_relocations || config.strip_export) {
            printf("Skipped: relocation/export trimming is not applied to CLR envelope payloads\n");
        }
        if (config.import_protection) printf("Skipped: import virtualization is not applied to CLR startup metadata\n");
        if (config.enable_vm || config.enable_mutation) printf("Skipped: SDK marker VM/mutation is native x64 only\n");
        printf("%s v%s\nInput: %s\nOutput: %s\n", NOVAPROTECT_PRODUCT_NAME,
               NOVAPROTECT_PRODUCT_VERSION, input.c_str(), output.c_str());
        printf("Effective: CLR-safe encrypted EXE envelope\n");
        printf("[  0%%] Loading managed executable...\n");
        printf("[ 45%%] Encrypting complete CLR payload...\n");
        std::string error;
        if (!protectManagedExecutable(argv[1], std::filesystem::u8path(output).wstring(), error)) {
            printf("FAILED: %s\n", error.c_str());
            return 1;
        }
        printf("[100%%] Managed executable protected\n");
        printf("\nOK! CLR metadata and IL remain encrypted inside the NovaProtect native envelope\n");
        return 0;
    }
    if (isDll && (config.strip_relocations || config.strip_export)) {
        printf("Error: relocation/export trimming is blocked for DLL targets\n");
        return 2;
    }
    config.enable_vm = effectiveVm;
    config.enable_mutation = effectiveMutation;
    if (!config.enable_vm) config.vm_default_complexity = 0;
    if (!config.enable_mutation) config.mutation_strength = 0;

    printf("%s v%s\nInput: %s\nOutput: %s\n", NOVAPROTECT_PRODUCT_NAME,
           NOVAPROTECT_PRODUCT_VERSION, input.c_str(), output.c_str());
    printf("Requested: VM=%s mutation=%s\n", requestedVm ? "on" : "off", requestedMutation ? "on" : "off");
    printf("Effective: %s VM=%s mutation=%s\n", planPe.is64() ? "x64" : "non-x64", effectiveVm ? "on" : "off", effectiveMutation ? "on" : "off");
    if (requestedVm && !effectiveVm) printf("Skipped: VM virtualization requires x64\n");
    if (requestedMutation && !effectiveMutation) printf("Skipped: mutation pipeline requires x64\n");
    if (config.enable_mutation) printf("Mode: mutation strength=%u\n", config.mutation_strength);
    if (config.enable_vm) printf("Mode: virtualization complexity=%u\n", config.vm_default_complexity);
    if (config.enable_mutation && config.enable_vm) printf("Mode: ultra\n");

    Packer packer;
    packer.setConfig(config);
    packer.setProgressCallback([](int pct, const std::string& msg) { printf("[%3d%%] %s\n", pct, msg.c_str()); });
    auto result = packer.pack(std::filesystem::u8path(input).wstring(), std::filesystem::u8path(output).wstring());
    if (result.success) {
        printf("\nOK! Original: %zu -> Packed: %zu bytes\n", result.original_size, result.packed_size);
        printf("Stub: %u bytes | Debug entries stripped: %u | Virtual files: %u\n",
               result.stub_size, result.debug_entries_stripped, result.virtual_files_embedded);
        return 0;
    }
    printf("\nFAILED: %s\n", result.error_message.c_str());
    return 1;
}

