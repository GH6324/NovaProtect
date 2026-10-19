using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using NovaProtect.UI.Services;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace NovaProtect.UI.Pages;

public sealed partial class InspectPage : Page
{
    private readonly ProtectorService _service = new();

    public InspectPage() => InitializeComponent();

    private async void Browse_Click(object sender, RoutedEventArgs e)
    {
        var picker = new FileOpenPicker();
        InitializeWithWindow.Initialize(picker, App.MainWindow?.WindowHandle ?? 0);
        picker.FileTypeFilter.Add(".exe");
        picker.FileTypeFilter.Add(".dll");
        var file = await picker.PickSingleFileAsync();
        if (file is not null) PathBox.Text = file.Path;
    }

    private async void PeInfo_Click(object sender, RoutedEventArgs e) => await RunAsync("-info");
    private async void Watermark_Click(object sender, RoutedEventArgs e) => await RunAsync("-showwatermark");
    private async void VirtualFiles_Click(object sender, RoutedEventArgs e) => await RunAsync("-listvf");

    private async void MachineId_Click(object sender, RoutedEventArgs e)
    {
        ResultBox.Text = "正在读取…";
        var result = await _service.InspectAsync(string.Empty, "-machineid");
        ResultBox.Text = result.Output;
    }

    private async Task RunAsync(params string[] args)
    {
        var path = PathBox.Text.Trim();
        if (!File.Exists(path))
        {
            ResultBox.Text = "请选择有效文件。";
            return;
        }
        ResultBox.Text = "正在检查…";
        var result = await _service.InspectAsync(path, args);
        ResultBox.Text = result.Output;
    }
}

