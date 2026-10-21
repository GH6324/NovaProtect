using System.ComponentModel;
using System.Runtime.CompilerServices;
using NovaProtect.UI.Models;
using NovaProtect.UI.Services;

namespace NovaProtect.UI.Models;

// UI-side wrapper around a scanned function. IsSelected drives the list
// checkboxes; ToRule converts a checked row into the packer rule that
// ProtectorService passes as -func.
public sealed class FunctionItem : INotifyPropertyChanged
{
    private bool _isSelected;

    public FunctionItem(ScannedFunction function)
    {
        Function = function;
        _vmComplexity = 6;
        _mutationStrength = 2;
    }

    public ScannedFunction Function { get; }
    public uint Rva => Function.Rva;
    public uint Size => Function.Size;
    public uint EndRva => Function.EndRva;
    public string Name => Function.Name;
    public string Section => Function.Section;
    public bool IsExported => Function.IsExported;
    public bool HasStackFrame => Function.HasStackFrame;
    public string AddressRange => Function.AddressRange;
    public string PrologueHex => Function.PrologueHex;
    public string Feasibility => Function.Feasibility;
    public bool VmFeasible => Function.VmFeasible;

    public bool IsSelected
    {
        get => _isSelected;
        set { if (_isSelected != value) { _isSelected = value; OnPropertyChanged(); } }
    }

    private MarkerProtectionMode _mode = MarkerProtectionMode.Virtualization;
    public MarkerProtectionMode Mode
    {
        get => _mode;
        set { _mode = value; OnPropertyChanged(); }
    }

    private int _vmComplexity;
    public int VmComplexity
    {
        get => _vmComplexity;
        set { _vmComplexity = Math.Clamp(value, 0, 10); OnPropertyChanged(); }
    }

    private int _mutationStrength;
    public int MutationStrength
    {
        get => _mutationStrength;
        set { _mutationStrength = Math.Clamp(value, 0, 3); OnPropertyChanged(); }
    }

    private bool _lockToActivation;
    public bool LockToActivation
    {
        get => _lockToActivation;
        set { _lockToActivation = value; OnPropertyChanged(); }
    }

    public ProtectionObjectRule ToRule() => new()
    {
        Id = $"func-{Rva:X8}",
        Name = Name,
        Source = ProductInfo.FunctionSource,
        DetectorVersion = ProductInfo.FunctionDetectorVersion,
        MarkerRva = Rva,
        StartRva = Rva,
        EndRva = EndRva,
        Mode = Mode,
        VmComplexity = VmComplexity,
        MutationStrength = MutationStrength,
        LockToActivation = LockToActivation
    };

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
