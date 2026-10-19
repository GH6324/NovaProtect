using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Navigation;
using System.Collections.Specialized;
using NovaProtect.UI.Models;
using NovaProtect.UI.Services;

namespace NovaProtect.UI.Pages;

public sealed partial class ActivityPage : Page
{
    public ActivityPage()
    {
        InitializeComponent();
        ActivityList.ItemsSource = ActivityStore.Items;
        ActivityStore.Items.CollectionChanged += Items_CollectionChanged;
        UpdateEmptyState();
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        ActivityStore.Items.CollectionChanged -= Items_CollectionChanged;
        base.OnNavigatedFrom(e);
    }

    private void Items_CollectionChanged(object? sender, NotifyCollectionChangedEventArgs e) => UpdateEmptyState();

    private void UpdateEmptyState()
    {
        EmptyState.Visibility = ActivityStore.Items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        ClearButton.IsEnabled = ActivityStore.Items.Count > 0;
    }

    private void DeleteItem_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: ActivityItem item }) ActivityStore.Remove(item);
    }

    private async void ClearButton_Click(object sender, RoutedEventArgs e)
    {
        if (ActivityStore.Items.Count == 0) return;

        var dialog = new ContentDialog
        {
            Title = "清空运行记录？",
            Content = "已保存的保护成功、失败和取消记录都会删除。",
            PrimaryButtonText = "清空",
            CloseButtonText = "取消",
            XamlRoot = XamlRoot
        };
        if (await dialog.ShowAsync() == ContentDialogResult.Primary) ActivityStore.Clear();
    }
}

