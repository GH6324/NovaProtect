using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using NovaProtect.UI.Models;
using NovaProtect.UI.Pages;
using WinRT.Interop;

namespace NovaProtect.UI;

public sealed partial class MainWindow : Window
{
    public nint WindowHandle { get; }

    public MainWindow()
    {
        InitializeComponent();
        Title = ProductInfo.Name;
        VersionText.Text = $"v{ProductInfo.Version}";
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);

        WindowHandle = WindowNative.GetWindowHandle(this);
        var windowId = Microsoft.UI.Win32Interop.GetWindowIdFromWindow(WindowHandle);
        AppWindow.GetFromWindowId(windowId).Resize(new Windows.Graphics.SizeInt32(1180, 800));

        NavView.SelectedItem = NavView.SettingsItem;
        ContentFrame.Navigate(typeof(SettingsPage));
    }

    private void NavView_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.IsSettingsSelected)
        {
            Navigate(typeof(SettingsPage));
            return;
        }

        if (args.SelectedItemContainer?.Tag is not string tag) return;
        Navigate(tag switch
        {
            "protect" => typeof(ProtectPage),
            "inspect" => typeof(InspectPage),
            "activity" => typeof(ActivityPage),
            _ => typeof(ProtectPage)
        });
    }

    private void Navigate(Type page)
    {
        if (ContentFrame.CurrentSourcePageType != page)
            ContentFrame.Navigate(page);
    }
}
