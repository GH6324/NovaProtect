#pragma once
// NovaProtect Anti-Debug Module
// Multiple detection layers, configurable strength

#include <cstddef>
#include <cstdint>
#include <vector>

namespace np {

// Anti-debug detection methods
enum class AntiDebugMethod : uint8_t {
    // Basic (Level 1)
    IsDebuggerPresent       = 0x01,
    CheckRemoteDebuggerPresent = 0x02,
    NtQueryInformationProcess = 0x03,  // ProcessDebugPort
    // Advanced (Level 2)
    NtQuerySystemInformation = 0x04,   // SystemKernelDebuggerInformation
    CheckWindowClass         = 0x05,   // Known debugger window classes
    CheckProcessName         = 0x06,   // Known debugger process names
    NtSetInformationThread   = 0x07,   // ThreadHideFromDebugger
    CloseHandleInvalid       = 0x08,   // Invalid handle exception
    OutputDebugString        = 0x09,   // OutputDebugString trick
    InterruptTrap            = 0x0A,   // INT 3 / INT 2D detection
    // Paranoid (Level 3)
    NtQueryObject            = 0x0B,   // Debug object check
    PageGuardBreakpoint      = 0x0C,   // PAGE_GUARD detection
    HardwareBreakpointCheck  = 0x0D,   // DR registers check
    TimingCheck              = 0x0E,   // RDTSC timing
    SelfDebugging            = 0x0F,   // Debug self process
    TLS_Callback             = 0x10,   // TLS callback check
    PEB_BeingDebugged        = 0x11,   // Direct PEB access
    NtGlobalFlag             = 0x12,   // NtGlobalFlag check
    HeapFlags                = 0x13,   // Heap force flags
    ProcessDebugFlags        = 0x14,   // ProcessDebugFlags (NoDebugInherit)
    ProcessDebugObjectHandle = 0x15,   // ProcessDebugObjectHandle
    SystemBreakpoint         = 0x16,   // Check for breakpoint on system
    InjectedThread           = 0x17,   // Enumerate threads
    ParentProcess            = 0x18,   // Check parent process
    CRT_SetUnhandled         = 0x19,   // Unhandled exception filter check
    // Anti-VM
    CPUID_Hypervisor         = 0x20,   // CPUID leaf 0x1 ECX bit 31
    Registry_VM              = 0x21,   // Registry VM keys
    FirmwareTable            = 0x22,   // SMBIOS/ACPI VM strings
    MAC_OUI                  = 0x23,   // Known VM MAC prefixes
    Timing_VM                = 0x24,   // Virtualization timing side-channel
    Disk_Vendor              = 0x25,   // Disk model strings
    Count
};

// Anti-debug action when detected
enum class AntiDebugAction : uint8_t {
    Exit             = 0,  // Just exit
    Corrupt          = 1,  // Corrupt internal state
    Crash            = 2,  // Force crash
    Loop             = 3,  // Infinite loop
    Decoy            = 4,  // Execute decoy code
    Silent           = 5,  // Return false results silently
    Count
};

// Anti-VM detection methods
enum class AntiVMMethod : uint8_t {
    CPUID            = 0,  // CPUID hypervisor bit
    Registry         = 1,  // Registry keys
    FirmwareTable    = 2,  // Firmware tables
    MACAddress       = 3,  // MAC OUI
    DiskModel        = 4,  // Disk model strings
    ProcessorName    = 5,  // CPU brand string
    DLLPresence      = 6,  // VM-specific DLLs
    TimingAttack     = 7,  // Timing anomalies
    Count
};

// Anti-debug configuration
struct AntiDebugConfig {
    uint8_t level = 2;               // 0=off, 1=basic, 2=advanced, 3=paranoid
    AntiDebugAction action = AntiDebugAction::Exit;
    uint32_t enabled_methods = 0;     // bitmask of enabled methods
    bool check_at_startup = true;     // check at program start
    bool check_periodic = false;      // periodic checking
    uint32_t check_interval_ms = 5000;
    bool use_tls_callback = false;    // use TLS callback for early check
    bool use_exception_handler = true; // use SEH for detection
    bool anti_vm = true;
    uint32_t anti_vm_methods = 0;

    // Generate default method mask for level
    static uint32_t methodsForLevel(uint8_t level) {
        switch (level) {
        case 0: return 0;
        case 1: return 0x0007;  // Basic: methods 0-2
        case 2: return 0x07FF;  // Advanced: methods 0-10
        case 3: return 0xFFFFFF; // Paranoid: all
        default: return 0x07FF;
        }
    }
};

// Anti-debug module - generates native code for detection
//
// ---------------------------------------------------------------------------
// Emitted code contract
// ---------------------------------------------------------------------------
// Every generator returns a self contained x64 code block with the ABI
//
//      uint32_t fn(void);        // 0 = clean, 1 = detected, 2 = unavailable
//
// * Non volatile registers (rbx, rbp, rsi, rdi, r12-r15) are preserved; only
//   volatile registers (rax, rcx, rdx, r8-r11) are clobbered.
// * No import table entries are used. Modules are located through the PEB
//   loader lists and exports are resolved by walking the PE export directory
//   with a ROR13 name hash, so the blocks can be dropped into a packed image
//   without any fixups or relocation work.
// * Detection methods that need a Windows API return 2 when that API could
//   not be resolved, which lets a caller tell "clean" apart from "broken".
//
// generateCheckRoutine() composes the enabled checks into a single function
// and returns the check id of the first tripped check (ids match the
// constants used by runtime/prot64.c: 1=PEB 2=NtGlobalFlag 3=heap
// 4=NtQueryInfoProcess 5=DR 6=timing 7=CPUID 10=integrity).
// ---------------------------------------------------------------------------
class AntiDebugModule {
public:
    AntiDebugModule() = default;
    explicit AntiDebugModule(const AntiDebugConfig& config) : config_(config) {
        config_.enabled_methods = AntiDebugConfig::methodsForLevel(config_.level);
    }

    // Generate the anti-debug check routine (x64 assembly bytes)
    // Returns the machine code bytes
    std::vector<uint8_t> generateCheckRoutine(bool is64);

    // Generate anti-VM check routine
    std::vector<uint8_t> generateAntiVMRoutine(bool is64);

    // Generate integrity check routine (FNV-1a64 over [rva, rva+size)).
    // The emitted function is uint32_t fn(void* image_base): 0 when the
    // measured hash matches the expected one, 1 when it does not.
    // Set the expected value with setIntegrityHash() first.
    std::vector<uint8_t> generateIntegrityCheck(bool is64, uint32_t target_rva, uint32_t size);

    // Generate TLS callback (void (*)(PVOID DllHandle, DWORD Reason, PVOID Reserved))
    std::vector<uint8_t> generateTLSCallback(bool is64);

    // Set configuration
    void setConfig(const AntiDebugConfig& config) { config_ = config; }
    const AntiDebugConfig& config() const { return config_; }

    // --- integrity helpers -------------------------------------------------
    // Expected FNV-1a64 of the protected region. 0 means "unknown", in which
    // case the check can never match - a packer must always set it.
    void setIntegrityHash(uint64_t expected) { integrity_expected_ = expected; }
    uint64_t integrityHash() const { return integrity_expected_; }

    // FNV-1a64 with the same basis/prime as runtime/prot64.c, exposed so the
    // packer can compute the expected value from the file on disk.
    static uint64_t fnv1a64(const void* data, size_t len);

    static constexpr uint64_t fnv_basis = 0xCBF29CE484222325ULL;
    static constexpr uint64_t fnv_prime = 0x00000100000001B3ULL;

private:
    AntiDebugConfig config_;

    uint32_t integrity_rva_ = 0;
    uint32_t integrity_size_ = 0;
    uint64_t integrity_expected_ = 0;

    // Individual check generators
    std::vector<uint8_t> genIsDebuggerPresent();
    std::vector<uint8_t> genPEBCheck();
    std::vector<uint8_t> genHeapCheck();
    std::vector<uint8_t> genNtQueryInfoProcess();
    std::vector<uint8_t> genHardwareBreakpointCheck();
    std::vector<uint8_t> genTimingCheck();
    std::vector<uint8_t> genCPUIDCheck();
    std::vector<uint8_t> genIntegrityCheck();
};

} // namespace np
