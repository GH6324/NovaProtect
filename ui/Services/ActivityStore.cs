using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using NovaProtect.UI.Models;

namespace NovaProtect.UI.Services;

public static class ActivityStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private static readonly string StorageDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        ProductInfo.Name);

    private static readonly string StoragePath = Path.Combine(StorageDirectory, "activity.json");

    public static ObservableCollection<ActivityItem> Items { get; } = [];

    static ActivityStore() => Load();

    public static void Add(ActivityItem item)
    {
        Items.Insert(0, item);
        Save();
    }

    public static void Remove(ActivityItem item)
    {
        if (Items.Remove(item)) Save();
    }

    public static void Clear()
    {
        if (Items.Count == 0) return;
        Items.Clear();
        Save();
    }

    private static void Load()
    {
        try
        {
            if (!File.Exists(StoragePath)) return;
            var info = new FileInfo(StoragePath);
            if (info.Length < 1 || info.Length > 32 * 1024 * 1024) return;

            var json = File.ReadAllText(StoragePath, Encoding.UTF8);
            var saved = JsonSerializer.Deserialize<List<ActivityItem>>(json, JsonOptions);
            if (saved is null) return;

            foreach (var item in saved)
            {
                if (item.Time == default || string.IsNullOrWhiteSpace(item.Title)) continue;
                Items.Add(item);
            }
        }
        catch (Exception exception)
        {
            Debug.WriteLine($"NovaProtect activity history could not be loaded: {exception}");
        }
    }

    private static void Save()
    {
        try
        {
            Directory.CreateDirectory(StorageDirectory);
            var temporary = Path.Combine(StorageDirectory, $"activity.{Guid.NewGuid():N}.tmp");
            try
            {
                var json = JsonSerializer.Serialize(Items.ToArray(), JsonOptions);
                File.WriteAllText(temporary, json, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
                File.Move(temporary, StoragePath, overwrite: true);
            }
            finally
            {
                if (File.Exists(temporary)) File.Delete(temporary);
            }
        }
        catch (Exception exception)
        {
            Debug.WriteLine($"NovaProtect activity history could not be saved: {exception}");
        }
    }
}

