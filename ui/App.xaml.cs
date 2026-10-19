using Microsoft.UI.Xaml;

namespace NovaProtect.UI;

public partial class App : Application
{
    public static MainWindow? MainWindow { get; private set; }

    public App()
    {
        Services.ClientIntegrity.EnsureVerified();
        InitializeComponent();
        Services.ClientDiagnosticLog.Initialize();
        UnhandledException += (_, args) =>
        {
            Services.ClientDiagnosticLog.Error("Unhandled UI exception", args.Exception);
            System.Diagnostics.Debug.WriteLine(args.Exception);
        };
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            Services.ClientDiagnosticLog.Error("Unhandled application exception", args.ExceptionObject as Exception);
        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            Services.ClientDiagnosticLog.Error("Unobserved task exception", args.Exception);
            args.SetObserved();
        };
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        MainWindow = new MainWindow();
        MainWindow.Activate();
    }
}

