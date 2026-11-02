using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Platform.Storage;
using Keyhole.App.Localization;
using Keyhole.App.ViewModels;

namespace Keyhole.App.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();

        // The picker needs a window to parent itself to, which the view model has no
        // business holding, so the view supplies the capability instead.
        DataContextChanged += (_, _) =>
        {
            if (DataContext is MainWindowViewModel viewModel)
            {
                viewModel.PickExecutableAsync = PickExecutableAsync;
            }
        };
    }

    private async Task<string?> PickExecutableAsync()
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            // Deliberately not "...to block": the same picker opens for starting a
            // capture, and a title naming one of the two is wrong half the time.
            Title = Loc.Current["PickerTitle"],
            AllowMultiple = false,
            FileTypeFilter =
            [
                new FilePickerFileType(Loc.Current["PickerPrograms"]) { Patterns = ["*.exe"] },
                FilePickerFileTypes.All,
            ],
        });

        // TryGetLocalPath returns null for virtual locations; the firewall needs a real
        // filesystem path, so anything else cannot be blocked.
        return files.Count > 0 ? files[0].TryGetLocalPath() : null;
    }
}
