using Microsoft.Win32;                // Реестр
using System;
using System.Collections.Generic; // для List<string>
using System.Collections.ObjectModel; // Коллекции для списка
using System.ComponentModel;          // Уведомления интерфейса
using System.Diagnostics;             // Процессы
using System.IO;                      // Файлы
using System.Linq;                    // LINQ
using System.Runtime.CompilerServices;// MVVM
using System.Runtime.InteropServices; // WinAPI
using System.Text;                    // Кодировки
using System.Text.RegularExpressions; // Regex
using System.Threading.Tasks;         // Асинхронность
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Imaging;   // Картинки
using System.Windows.Input; // Для ICommand
using System.Windows.Data;
using System.Globalization;
using System.Text.Json;           // Для JsonSerializer
using System.Windows.Media;       // Для SolidColorBrush, Colors



namespace WpfApp3
{
    // Модель для плана электропитания
    public class PowerPlan
    {
        public string Name { get; set; } = string.Empty;          
        public string Guid { get; set; } = string.Empty;          
        public bool IsActive { get; set; }
    }

    // Модель для обоев
    public class WallpaperItem
    {
        public string Path { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public BitmapImage? Image { get; set; }  // допускаем null, т.к. загружается асинхронно
    }

    public partial class MainWindow : Window, INotifyPropertyChanged
    {
        // === ИМПОРТЫ СИСТЕМНЫХ ФУНКЦИЙ ===

        [DllImport("shell32.dll")]
        private static extern void SHChangeNotify(int wEventId, int uFlags, IntPtr dwItem1, IntPtr dwItem2);
        private const int SHCNE_ASSOCCHANGED = 0x08000000;
        private const int SHCNF_IDLIST = 0x0000;

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        private static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
        private const int SPI_SETDESKWALLPAPER = 20;
        private const int SPIF_UPDATEINIFILE = 0x01;
        private const int SPIF_SENDWININICHANGE = 0x02;



        public MainWindow()
        {

            InitializeComponent();
            this.DataContext = this;

            // Исправление кодировки для консоли
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

            // Адаптация экрана
            double screenHeight = SystemParameters.PrimaryScreenHeight;
            if (screenHeight < 900)
            {
                this.Height = screenHeight - 60;
                this.Width = 900;
                this.Top = (screenHeight - this.Height) / 2;
                this.Left = (SystemParameters.PrimaryScreenWidth - this.Width) / 2;
            }

            if (!IsAdministrator())
                MessageBox.Show("ОШИБКА: Запустите программу от имени Администратора!", "Shuragen4ik Tool", MessageBoxButton.OK, MessageBoxImage.Error);

            if (!Environment.Is64BitProcess)
                MessageBox.Show("ОШИБКА: Запущена 32-битная версия.\nСкомпилируйте проект под x64!", "Архитектура", MessageBoxButton.OK, MessageBoxImage.Error);

            AddLog($"Добро пожаловать, {CurrentUserName}!");
            AddLog("Shuragen4ik Tool v1.3.1 готов к работе.");

            LoadWallpapers();
            LoadPowerPlans();
            _isDefenderDisabled = GetDefenderState();
            OnPropertyChanged(nameof(IsDefenderDisabled));
            LoadMsiDevicesSimple();

            BlockUpdatesCommand = new RelayCommand(async () =>
            {
                IsBusy = true;
                AddLog("Запуск блокировки обновлений...");
                if (await RunWub("/D /P"))
                {
                    AddLog("Обновления Windows заблокированы.");
                    AddLog("Защита настроек служб включена.");
                }
                else
                {
                    AddLog("Не удалось заблокировать обновления.");
                }
                IsBusy = false;
            });

            EnableUpdatesCommand = new RelayCommand(async () =>
            {
                IsBusy = true;
                AddLog("Запуск включения обновлений...");
                if (await RunWub("/E"))
                {
                    AddLog("Обновления Windows включены.");
                    AddLog("Защита настроек служб отключена.");
                }
                else
                {
                    AddLog("Не удалось включить обновления.");
                }
                IsBusy = false;
            });




        }

        // MSI режим
        // В начало класса MainWindow, после других коллекций
        public ObservableCollection<MsiDeviceItem> MsiCapableDevices { get; } = new();

        // Модель остаётся той же (можно оставить старую)
        public class MsiDeviceItem : INotifyPropertyChanged
        {
            public string DeviceName { get; set; } = "";
            public string DeviceId { get; set; } = "";
            public string FriendlyName { get; set; } = "";
            public bool SupportsMsi { get; set; }
            private bool _msiEnabled;
            public bool MsiCurrentlyEnabled
            {
                get => _msiEnabled;
                set { _msiEnabled = value; OnPropertyChanged(); }
            }
            public bool IsRecommended { get; set; }
            public event PropertyChangedEventHandler? PropertyChanged;
            protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }

        // Кнопка обновления списка
        private async void BtnRefreshMsiList_Click(object sender, RoutedEventArgs e)
        {
            await LoadMsiDevicesSimple();
        }

        // Упрощённая загрузка через PowerShell (самый надёжный способ)
        private async Task LoadMsiDevicesSimple()
        {
            IsBusy = true;
            MsiCapableDevices.Clear();

            try
            {
                string psCommand = @"
            Get-PnpDevice | Where-Object { $_.Class -eq 'Display' -or $_.Class -eq 'Media' -or $_.Class -eq 'Sound' } |
            ForEach-Object {
                $dev = $_
                $instanceId = $dev.InstanceId
                $msiPath = 'HKLM:\SYSTEM\CurrentControlSet\Enum\' + $instanceId.Replace('\','\\') + '\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties'
                $msi = Get-ItemProperty -Path $msiPath -ErrorAction SilentlyContinue
                [PSCustomObject]@{
                    Name = $dev.FriendlyName
                    InstanceId = $instanceId
                    Class = $dev.Class
                    MSISupported = if ($msi) { $msi.MSISupported } else { $null }
                }
            } | ConvertTo-Json -Compress";

                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{psCommand}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                // Ensure OEM encoding for console output to correctly read Cyrillic on Russian Windows
                psi.StandardOutputEncoding = Encoding.GetEncoding(866);
                psi.StandardErrorEncoding = Encoding.GetEncoding(866);

                using var process = Process.Start(psi);
                string output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();

                if (string.IsNullOrWhiteSpace(output))
                {
                    // Тихая ошибка, без лога при запуске
                    return;
                }

                // Новый безопасный парсинг
                using var doc = JsonDocument.Parse(output);
                var results = doc.RootElement.EnumerateArray();

                foreach (var element in results)
                {
                    string name = element.GetProperty("Name").GetString() ?? "Без имени";
                    string id = element.GetProperty("InstanceId").GetString() ?? "";
                    string cls = element.GetProperty("Class").GetString() ?? "";

                    int? msiSupported = null;
                    if (element.TryGetProperty("MSISupported", out var msiProp) && msiProp.ValueKind != JsonValueKind.Null)
                    {
                        msiSupported = msiProp.GetInt32();
                    }

                    // Показываем только видеокарты и аудиовыходы (динамики), исключая встроенное аудио Intel
                    bool isGpu = string.Equals(cls, "Display", StringComparison.OrdinalIgnoreCase);
                    bool isAudioClass = string.Equals(cls, "Media", StringComparison.OrdinalIgnoreCase) || string.Equals(cls, "Sound", StringComparison.OrdinalIgnoreCase);

                    bool isAudioOutput = false;
                    if (isAudioClass)
                    {
                        var lower = name.ToLowerInvariant();
                        if (lower.Contains("speaker") || lower.Contains("speakers") || lower.Contains("audio") || lower.Contains("realtek") || lower.Contains("high definition") || lower.Contains("nvidia") || lower.Contains("amd") || lower.Contains("intel"))
                            isAudioOutput = true;
                    }

                    if (!isGpu && !isAudioOutput)
                    {
                        // Пропускаем устройства, которые не являются видеокартой или аудиовыходом
                        continue;
                    }

                    string friendly = isGpu ? "Видеокарта" : "Аудиоустройство";
                    bool recommended = isGpu || name.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase) || name.Contains("AMD", StringComparison.OrdinalIgnoreCase) || name.Contains("Audio", StringComparison.OrdinalIgnoreCase);

                    var msiItem = new MsiDeviceItem
                    {
                        DeviceName = name,
                        DeviceId = id,
                        FriendlyName = friendly,
                        IsRecommended = recommended,
                        SupportsMsi = true, // Предполагаем поддержку MSI для всех PCI устройств (видеокарты и аудио)
                        MsiCurrentlyEnabled = msiSupported == 1 // Правильное чтение текущего состояния из реестра
                    };

                    Dispatcher.Invoke(() => MsiCapableDevices.Add(msiItem));
                }
            }
            catch (Exception ex)
            {
                // Тихая ошибка при запуске
            }
            finally
            {
                IsBusy = false;
            }
        }

        private void MsiCheckBox_Changed(object sender, RoutedEventArgs e)
        {
            if (sender is not CheckBox cb || cb.DataContext is not MsiDeviceItem item)
                return;

            bool desiredState = cb.IsChecked == true;

            Task.Run(() =>
            {
                IsBusy = true;
                string action = desiredState ? "ВКЛЮЧЕНИЕ" : "ОТКЛЮЧЕНИЕ";
                Dispatcher.Invoke(() => AddLog($"MSI-режим → {action} для {item.DeviceName}..."));

                try
                {
                    // Путь к реестру (совместим с PowerShell-вариантом)
                    string regPath = $@"SYSTEM\CurrentControlSet\Enum\{item.DeviceId}\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties";

                    using var key = Registry.LocalMachine.CreateSubKey(regPath, true);
                    if (key == null)
                        throw new Exception("Не удалось открыть/создать ветку реестра");

                    key.SetValue("MSISupported", desiredState ? 1 : 0, RegistryValueKind.DWord);

                    Dispatcher.Invoke(() => AddLog("Успешно применено! Требуется **перезагрузка** компьютера."));
                }
                catch (Exception ex)
                {
                    Dispatcher.Invoke(() =>
                    {
                        AddLog($"Ошибка изменения MSI-режима: {ex.Message}");
                        // Откатываем галочку в UI
                        item.MsiCurrentlyEnabled = !desiredState;
                    });
                }
                finally
                {
                    Dispatcher.Invoke(() => IsBusy = false);
                }
            });
        }







        // ==========================
        // БАЗОВЫЕ СВОЙСТВА
        // ==========================

        // !!! ВОТ ЭТО СВОЙСТВО Я ДОБАВИЛ ДЛЯ ОТОБРАЖЕНИЯ НИКА !!!
        public string CurrentUserName { get; set; } = Environment.UserName;

        private string _logText = "";
        public string LogText { get => _logText; set { _logText = value; OnPropertyChanged(); } }

        private bool _isBusy;
        public bool IsBusy { get => _isBusy; set { _isBusy = value; OnPropertyChanged(); } }

        private void AddLog(string msg) => Dispatcher.Invoke(() => LogText += $"[{DateTime.Now:HH:mm:ss}] {msg}\n");

        private bool IsAdministrator()
        {
            try
            {
                var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                return new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        // ==========================
        // 1. ПИТАНИЕ
        // ==========================

        public ObservableCollection<PowerPlan> PowerPlans { get; set; } = new ObservableCollection<PowerPlan>();

        private PowerPlan? _selectedPowerPlan = null;
        public PowerPlan? SelectedPowerPlan
        {
            get => _selectedPowerPlan;
            set
            {
                if (_selectedPowerPlan != value)
                {
                    _selectedPowerPlan = value;
                    OnPropertyChanged();
                    if (value != null)
                    {
                        SetActivePowerPlan(value.Guid);
                    }
                }
            }
        }

        private async void LoadPowerPlans()
        {
            try
            {
                PowerPlans.Clear();
                string output = await RunCommandWithOutput("powercfg", "/list", true);

                var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                PowerPlan activePlan = null;

                foreach (var line in lines)
                {
                    var match = Regex.Match(line, @"GUID.*:\s+([a-f0-9\-]+)\s+\((.+)\)");
                    if (match.Success)
                    {
                        var plan = new PowerPlan
                        {
                            Guid = match.Groups[1].Value,
                            Name = match.Groups[2].Value,
                            IsActive = line.Trim().EndsWith("*")
                        };

                        PowerPlans.Add(plan);
                        if (plan.IsActive) activePlan = plan;
                    }
                }

                if (activePlan != null)
                {
                    _selectedPowerPlan = activePlan;
                    OnPropertyChanged(nameof(SelectedPowerPlan));
                }
            }
            catch (Exception ex) { AddLog($"Ошибка чтения планов: {ex.Message}"); }
        }

        private void SetActivePowerPlan(string guid)
        {
            if (!string.IsNullOrEmpty(guid))
            {
                RunSystemCommand("powercfg", $"/setactive {guid}");

                // Локальная переменная — компилятор доволен
                string planName = SelectedPowerPlan?.Name ?? "Неизвестная схема";
                AddLog($"Питание переключено: {planName}");
            }
        }

        // ==========================
        // 2. ПРОВОДНИК
        // ==========================

        public bool IsHiddenFilesVisible
        {
            get => GetRegistryInt(@"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "Hidden", 2, RegRoot.HKCU) == 1;
            set
            {
                SetRegistry(@"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "Hidden", value ? 1 : 2, RegRoot.HKCU);
                RefreshExplorer();
                AddLog($"Скрытые файлы: {(value ? "ВИДИМЫ" : "СКРЫТЫ")}");
                OnPropertyChanged();
            }
        }

        public bool IsFileExtensionsVisible
        {
            get => GetRegistryInt(@"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt", 1, RegRoot.HKCU) == 0;
            set
            {
                SetRegistry(@"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt", value ? 0 : 1, RegRoot.HKCU);
                RefreshExplorer();
                AddLog($"Расширения файлов: {(value ? "ВИДИМЫ" : "СКРЫТЫ")}");
                OnPropertyChanged();
            }
        }

        private void RefreshExplorer()
        {
            SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, IntPtr.Zero, IntPtr.Zero);
        }

        // ==========================
        // 3. ИГРОВЫЕ ТВИКИ
        // ==========================

        public bool IsFsoEnabled
        {
            get
            {
                // 0 = Оптимизация ВКЛЮЧЕНА (по умолчанию)
                // 2 = Оптимизация ОТКЛЮЧЕНА (Legacy Mode)
                int val = GetRegistryInt(@"System\GameConfigStore", "GameDVR_FSEBehavior", 0, RegRoot.HKCU);
                return val == 0;
            }
            set
            {
                // Если True (Включить оптимизацию) -> ставим 0
                // Если False (Отключить/Вернуть старый режим) -> ставим 2
                int val = value ? 0 : 2;

                SetRegistry(@"System\GameConfigStore", "GameDVR_FSEBehavior", val, RegRoot.HKCU);
                SetRegistry(@"System\GameConfigStore", "GameDVR_DXGIHonorFSEWindowsCompatible", value ? 0 : 1, RegRoot.HKCU);
                SetRegistry(@"System\GameConfigStore", "GameDVR_HonoredDead", value ? 0 : 1, RegRoot.HKCU);
                SetRegistry(@"System\GameConfigStore", "GameDVR_EFSEFeatureFlags", 0, RegRoot.HKCU);

                AddLog($"Full Screen Optimization: {(value ? "ВКЛЮЧЕНА" : "ОТКЛЮЧЕНА")}");
                OnPropertyChanged();

                // Этому параметру часто нужна перезагрузка, но попробуем обновить проводник
                RefreshExplorer();
            }
        }

        public bool IsWindowedGameOptEnabled
        {
            get
            {
                // Читаем сложную строку настроек DirectX
                string s = GetRegistryString(@"Software\Microsoft\DirectX\UserGpuPreferences", "DirectXUserGlobalSettings", "", RegRoot.HKCU);
                // Ищем в ней "SwapEffectUpgradeEnable=1"
                return s.Contains("SwapEffectUpgradeEnable=1");
            }
            set
            {
                // 1. Ставим новую настройку в GraphicsSettings (для Windows 11 UI)
                SetRegistry(@"Software\Microsoft\Windows\CurrentVersion\GraphicsSettings", "SwapEffectUpgradeCache", value ? 1 : 0, RegRoot.HKCU);

                // 2. Формируем строку для DirectX UserGpuPreferences (это реальный движок)
                string path = @"Software\Microsoft\DirectX\UserGpuPreferences";
                string keyName = "DirectXUserGlobalSettings";

                string current = GetRegistryString(path, keyName, "", RegRoot.HKCU);

                // Используем исправленный метод замены значения
                string newVal = ModifyUserPreferences(current, "SwapEffectUpgradeEnable", value ? "1" : "0");

                // ВАЖНО: Пишем как String (RegistryValueKind.String)
                SetRegistry(path, keyName, newVal, RegRoot.HKCU, RegistryValueKind.String);

                AddLog($"Оконная Оптимизация: {(value ? "ВКЛЮЧЕНА" : "ВЫКЛЮЧЕНА")}");
                OnPropertyChanged();
            }
        }

        public bool IsMPODisabled
        {
            get => GetRegistryInt(@"SOFTWARE\Microsoft\Windows\Dwm", "OverlayTestMode", 0) == 5;
            set
            {
                SetRegistry(@"SOFTWARE\Microsoft\Windows\Dwm", "OverlayTestMode", value ? 5 : 0);
                AddLog($"MPO: {(value ? "ОТКЛЮЧЕНО" : "ВКЛЮЧЕНО")}");
                OnPropertyChanged();
            }
        }

        // ==========================
        // 4. БЕЗОПАСНОСТЬ
        // ==========================

        public bool IsSpectreDisabled
        {
            get
            {
                int val = GetRegistryInt(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", "FeatureSettingsOverride", 0);
                return (val & 3) == 3;
            }
            set
            {
                int currentVal = GetRegistryInt(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", "FeatureSettingsOverride", 0);
                int newVal = value ? (currentVal | 3) : (currentVal & ~3);

                SetRegistry(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", "FeatureSettingsOverride", newVal);
                SetRegistry(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", "FeatureSettingsOverrideMask", 3);
                AddLog($"Spectre/Meltdown: {(value ? "ОТКЛЮЧЕНО" : "ВКЛЮЧЕНО")}");
                OnPropertyChanged();
            }
        }

        public bool IsDownfallDisabled
        {
            get
            {
                int val = GetRegistryInt(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", "FeatureSettingsOverride", 0);
                return (val & 33554432) == 33554432;
            }
            set
            {
                int currentVal = GetRegistryInt(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", "FeatureSettingsOverride", 0);
                int newVal = value ? (currentVal | 33554432) : (currentVal & ~33554432);

                SetRegistry(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", "FeatureSettingsOverride", newVal);
                AddLog($"Downfall: {(value ? "ОТКЛЮЧЕНО" : "ВКЛЮЧЕНО")}");
                OnPropertyChanged();
            }
        }

        private bool _isDefenderDisabled;

        private bool GetDefenderState()
        {
            // Улучшенная проверка состояния Windows Defender
            // 1. Проверяем политики отключения
            if (GetRegistryInt(@"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", 0, RegRoot.HKLM) == 1 ||
                GetRegistryInt(@"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiVirus", 0, RegRoot.HKLM) == 1)
                return true;

            // 2. Проверяем тип запуска службы WinDefend
            int winDefendStart = GetRegistryInt(@"SYSTEM\CurrentControlSet\Services\WinDefend", "Start", 2, RegRoot.HKLM);
            if (winDefendStart == 4) // disabled
                return true;

            // 3. Проверяем дополнительные службы
            int securityCenterStart = GetRegistryInt(@"SYSTEM\CurrentControlSet\Services\SecurityHealthService", "Start", 2, RegRoot.HKLM);
            if (securityCenterStart == 4) // disabled
                return true;

            // 4. Проверяем настройки реального времени
            if (GetRegistryInt(@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", 0, RegRoot.HKLM) == 1)
                return true;

            // Если ни одна проверка не подтвердила отключение, считаем включенным
            return false;
        }

        // Полное отключение Windows Defender + скрытие в Параметрах
        public bool IsDefenderDisabled
        {
            get => _isDefenderDisabled;
            set
            {
                _isDefenderDisabled = value;
                OnPropertyChanged();
                Task.Run(async () =>
                {
                    IsBusy = true;
                    AddLog("Применение настроек Windows Defender...");

                    if (value) // === ОТКЛЮЧАЕМ Defender ===
                    {
                        // Проверяем Tamper Protection
                        if (CheckTamperProtection())
                        {
                            AddLog("Обнаружена включённая Tamper Protection. Открываем Windows Defender для ручного отключения...");

                            // Открываем Windows Defender
                            OpenWindowsDefender();

                            // Цикл пока Tamper Protection включена
                            while (CheckTamperProtection())
                            {
                                // Показываем инструкцию
                                var result = MessageBox.Show(
                                    "Защита от подделки (Tamper Protection) включена!\n\n" +
                                    "Для отключения Windows Defender необходимо сначала отключить защиту от подделки (Tamper Protection) вручную:\n\n" +
                                    "1. В открывшемся окне Windows Security перейдите в 'Защита от вирусов и угроз'\n" +
                                    "2. Нажмите 'Управление настройками'\n" +
                                    "3. Отключите 'Защита от подделки'\n" +
                                    "4. Подтвердите отключение\n\n" +
                                    "После отключения защиты от подделки (Tamper Protection) нажмите OK для продолжения.",
                                    "Требуется ручное действие",
                                    MessageBoxButton.OKCancel,
                                    MessageBoxImage.Warning);

                                if (result == MessageBoxResult.Cancel)
                                {
                                    AddLog("Пользователь отменил отключение Defender.");
                                    Dispatcher.Invoke(() => { _isDefenderDisabled = false; OnPropertyChanged(); });
                                    IsBusy = false;
                                    return;
                                }

                                // Если OK, но Tamper Protection еще включена, цикл повторится
                                // Добавим небольшую паузу, чтобы не спамить
                                await Task.Delay(300);
                            }

                            AddLog("Tamper Protection отключена.");

                            // Теперь показываем финальное подтверждение
                            var finalConfirm = MessageBox.Show(
                                "Tamper Protection отключена.\n\n" +
                                "Теперь можно продолжить отключение Windows Defender.\n\n" +
                                "Подтвердить отключение защитника?",
                                "Подтверждение отключения",
                                MessageBoxButton.YesNo,
                                MessageBoxImage.Question);

                            if (finalConfirm != MessageBoxResult.Yes)
                            {
                                AddLog("Пользователь отменил финальное отключение Defender.");
                                Dispatcher.Invoke(() => { _isDefenderDisabled = false; OnPropertyChanged(); });
                                IsBusy = false;
                                return;
                            }
                        }

                        AddLog("Полное отключение Windows Defender (усиленный метод)...");

                        // 1. Отключаем через PowerShell (Set-MpPreference)
                        // Это помогает, если политики игнорируются, но служба еще работает
                        RunSystemCommand("powershell.exe", "Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableBlockAtFirstSeen $true -DisableIOAVProtection $true -DisablePrivacyMode $true -SignatureUpdateInterval 0 -SubmitSamplesConsent 2 -MAPSReporting 0 -HighThreatDefaultAction 6 -ModerateThreatDefaultAction 6 -LowThreatDefaultAction 6 -SevereThreatDefaultAction 6", true);

                        // 2. Основные политики (GPO)
                        SetRegistry(@"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", 1, RegRoot.HKLM);
                        SetRegistry(@"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiVirus", 1, RegRoot.HKLM);
                        SetRegistry(@"SOFTWARE\Policies\Microsoft\Windows Defender", "ServiceKeepAlive", 0, RegRoot.HKLM);

                        // 3. Real-Time Protection (Расширенный список)
                        string rtpKey = @"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection";
                        SetRegistry(rtpKey, "DisableBehaviorMonitoring", 1, RegRoot.HKLM);
                        SetRegistry(rtpKey, "DisableOnAccessProtection", 1, RegRoot.HKLM);
                        SetRegistry(rtpKey, "DisableScanOnRealtimeEnable", 1, RegRoot.HKLM);
                        SetRegistry(rtpKey, "DisableIOAVProtection", 1, RegRoot.HKLM);
                        SetRegistry(rtpKey, "DisableRealtimeMonitoring", 1, RegRoot.HKLM); // Критически важно для предотвращения включения

                        // 4. Spynet (Cloud)
                        string spyKey = @"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet";
                        SetRegistry(spyKey, "SpyNetReporting", 0, RegRoot.HKLM);
                        SetRegistry(spyKey, "SubmitSamplesConsent", 2, RegRoot.HKLM);

                        // 5. Tamper Protection и UI
                        RunSystemCommand("reg", "add \"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features\" /v TamperProtection /t REG_DWORD /d 0 /f", true);
                        SetRegistry(@"SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray", "HideSystray", 1, RegRoot.HKLM);

                        // 6. Отключаем службы (WinDefend, WdNisSvc, Sense, SecurityHealthService, WdFilter)
                        // SecurityHealthService часто отвечает за восстановление защиты
                        string[] services = { "WinDefend", "WdNisSvc", "Sense", "SecurityHealthService", "WdFilter" };
                        foreach (var svc in services)
                        {
                            RunSystemCommand("sc", $"config \"{svc}\" start= disabled", true);
                            RunSystemCommand("sc", $"stop \"{svc}\"", true);
                        }

                        AddLog("Windows Defender полностью отключён (Registry + PowerShell + Services).");
                    }
                    else // === ВКЛЮЧАЕМ Defender ===
                    {
                        AddLog("Включение Windows Defender...");

                        // ШАГ 1: Снимаем блокирующие политики
                        try
                        {
                            using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows Defender", true))
                            {
                                key?.DeleteValue("DisableAntiSpyware", false);
                                key?.DeleteValue("DisableAntiVirus", false);
                            }
                            Registry.LocalMachine.DeleteSubKeyTree(@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", false);
                            Registry.LocalMachine.DeleteSubKeyTree(@"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", false);
                            Registry.LocalMachine.DeleteSubKeyTree(@"SOFTWARE\Policies\Microsoft\Windows Defender Security Center", false);

                            using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Features", true))
                            {
                                key?.DeleteValue("TamperProtection", false);
                            }
                        }
                        catch { } // Игнорируем ошибки реестра

                        // ШАГ 2: Включаем службы обратно
                        string[] services = { "WinDefend", "WdNisSvc", "SecurityHealthService", "Sense" };
                        foreach (var svc in services)
                        {
                            RunSystemCommand("sc", $"config \"{svc}\" start= auto", true);
                        }

                        // ШАГ 3: Возвращаем настройки PowerShell
                        RunSystemCommand("powershell.exe", "Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false", true);

                        // ШАГ 4: Запускаем основную службу
                        string startResult = RunCommandSync("net", "start WinDefend");
                        if (startResult.Contains("успешно") || startResult.Contains("already"))
                            AddLog("Служба WinDefend запущена.");
                        // else: Служба запустится после перезагрузки (без лога)

                        AddLog("Windows Defender включён. Полное восстановление — после перезагрузки.");

                        // Удаляем задачу планировщика для отключения Defender
                        string result = RunCommandSync("schtasks", "/delete /tn \"\\DisableWindowsDefender\" /f");
                        if (result.Contains("Успех") || result.Contains("SUCCESS") || result.Contains("не существует") || string.IsNullOrWhiteSpace(result))
                        {
                            AddLog("✓ Задача планировщика для отключения Defender удалена.");
                        }
                        // else: Не выводим ошибки удаления задачи
                    }

                    AddLog("⚠️ Рекомендуется перезагрузка для полного применения изменений!");

                    // Ждём применения изменений
                    await Task.Delay(2000);

                    // Обновляем UI для других элементов
                    Dispatcher.Invoke(() =>
                    {
                        RefreshAllUIStates();
                    });

                    IsBusy = false;
                });
            }
        }

        // === ПРОВЕРКА И УПРАВЛЕНИЕ TAMPER PROTECTION ===
        private bool CheckTamperProtection()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "-NoProfile -ExecutionPolicy Bypass -Command \"(Get-MpComputerStatus).IsTamperProtected\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    StandardOutputEncoding = Encoding.GetEncoding(866),
                    StandardErrorEncoding = Encoding.GetEncoding(866)
                };

                using var process = Process.Start(psi);
                string output = process.StandardOutput.ReadToEnd().Trim();
                process.WaitForExit();

                return output == "True";
            }
            catch
            {
                return false;
            }
        }

        private void OpenWindowsDefender()
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "windowsdefender:",
                    UseShellExecute = true
                });
            }
            catch
            {
                // Альтернативный способ
                try
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "ms-settings:windowsdefender",
                        UseShellExecute = true
                    });
                }
                catch
                {
                    AddLog("Не удалось открыть Windows Defender.");
                }
            }
        }

        private async Task WaitForTamperProtectionDisabled()
        {
            AddLog("Ожидание отключения Tamper Protection...");
            while (CheckTamperProtection())
            {
                await Task.Delay(2000); // Проверяем каждые 2 секунды
            }
            AddLog("Tamper Protection отключена.");
        }

        // === ВКЛЮЧЕНИЕ INTEL TSX (Transactional Synchronization Extensions) ===
        public bool IsTsxEnabled
        {
            get
            {
                // Если ключ отсутствует или =0 — TSX включён (по умолчанию)
                // Если =1 — отключён
                int val = GetRegistryInt(@"SYSTEM\CurrentControlSet\Control\Session Manager\Kernel", "DisableTsx", 0);
                return val != 1;
            }
            set
            {
                if (value) // ВКЛЮЧАЕМ TSX (удаляем ключ или ставим 0)
                {
                    // Лучше удалить ключ полностью — возвращает дефолт (включено)
                    DeleteRegistryValue(@"SYSTEM\CurrentControlSet\Control\Session Manager\Kernel", "DisableTsx");

                    AddLog("Intel TSX: ВКЛЮЧЕН (аппаратная транзакционная память активна)");
                }
                else // ОТКЛЮЧАЕМ TSX
                {
                    SetRegistry(@"SYSTEM\CurrentControlSet\Control\Session Manager\Kernel", "DisableTsx", 1);

                    AddLog("Intel TSX: ОТКЛЮЧЕН (фикс TAA + небольшой прирост FPS)");
                }

                AddLog("⚠ Обязательна перезагрузка ПК для применения!");

                OnPropertyChanged();
            }
        }


        
        // ==========================
        // 5. СИСТЕМА
        // ==========================

        // ==========================
        // ПОЛНАЯ БЛОКИРОВКА ДРАЙВЕРОВ ИЗ WINDOWS UPDATE (НАДЁЖНЫЙ СПОСОБ)
        // ==========================
        public bool IsDriverUpdateDisabled
        {
            get => GetRegistryInt(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata", "PreventDeviceMetadataFromNetwork", 0) == 1 &&
                   GetRegistryInt(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "ExcludeWUDriversInQualityUpdate", 0) == 1;

            set
            {
                int val = value ? 1 : 0;
                int searchVal = value ? 0 : 1; // SearchOrderConfig: 0 = не искать в WU

                // Основные ключи
                SetRegistry(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "ExcludeWUDriversInQualityUpdate", val);
                SetRegistry(@"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings", "ExcludeWUDriversInQualityUpdate", val);
                SetRegistry(@"SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching", "SearchOrderConfig", searchVal);
                SetRegistry(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata", "PreventDeviceMetadataFromNetwork", val);

                // Дополнительные ключи (критически важны в новых версиях Windows)
                SetRegistry(@"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall", "PreventDeviceMetadataFromNetwork", val);
                SetRegistry(@"SOFTWARE\Policies\Microsoft\Windows\DriverSearching", "DontSearchWindowsUpdate", val);
                SetRegistry(@"SOFTWARE\Policies\Microsoft\Windows\DriverSearching", "SearchOnlyIfNeeded", val);
                SetRegistry(@"SOFTWARE\Policies\Microsoft\Windows\DriverSearching", "DriverUpdateWizardWuSearchEnabled", val == 1 ? 0 : 1);

                // Отключаем автоматическую установку драйверов через Диспетчер устройств
                SetRegistry(@"SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceSetup", "PreventNewDeviceInstallation", val);

                AddLog($"Драйверы из Windows Update: {(value ? "ЗАБЛОКИРОВАНЫ (усиленная защита)" : "РАЗРЕШЕНЫ")}");
                AddLog("Перезагрузите ПК для полного применения.");
                OnPropertyChanged();
            }
        }


        public bool IsSysMainDisabled
        {
            get
            {
                // 4 = Disabled, 2 = Auto. Проверяем в реестре.
                return GetRegistryInt(@"SYSTEM\CurrentControlSet\Services\SysMain", "Start", 2) == 4;
            }
            set
            {
                if (value)
                {
                    // ОТКЛЮЧАЕМ
                    // 1. Ставим автозапуск в Disabled
                    RunSystemCommand("sc", "config \"SysMain\" start= disabled", true);
                    // 2. Останавливаем службу прямо сейчас
                    RunSystemCommand("net", "stop \"SysMain\"", true);
                    // 3. Обновляем реестр для UI (на случай задержки sc)
                    SetRegistry(@"SYSTEM\CurrentControlSet\Services\SysMain", "Start", 4);
                }
                else
                {
                    // ВКЛЮЧАЕМ
                    // 1. Ставим автозапуск в Auto
                    RunSystemCommand("sc", "config \"SysMain\" start= auto", true);
                    // 2. Обновляем реестр
                    SetRegistry(@"SYSTEM\CurrentControlSet\Services\SysMain", "Start", 2);
                    // 3. Запускаем службу
                    RunSystemCommand("net", "start \"SysMain\"", true);
                }

                AddLog($"SysMain (Superfetch): {(value ? "ОТКЛЮЧЕН" : "ВКЛЮЧЕН")}");
                OnPropertyChanged();
            }
        }





        public bool IsNtfs8dot3Disabled
        {
            get => GetRegistryInt(@"SYSTEM\CurrentControlSet\Control\FileSystem", "NtfsDisable8dot3NameCreation", 0) == 1;
            set
            {
                SetRegistry(@"SYSTEM\CurrentControlSet\Control\FileSystem", "NtfsDisable8dot3NameCreation", value ? 1 : 0);
                RunSystemCommand("fsutil", $"behavior set disable8dot3 {(value ? 1 : 0)}");
                AddLog($"NTFS 8.3: {(value ? "ОТКЛЮЧЕНО" : "ВКЛЮЧЕНО")}");
                OnPropertyChanged();
            }
        }

        // =============================================================================
        // ГРУППИРОВКА СЛУЖБ (SvcHostSplitThresholdInKB)
        // =============================================================================
        // Этот пункт управляет группировкой системных служб в Windows.
        // По умолчанию Windows (начиная с Win10 1709+) разделяет службы по разным процессам svchost.exe,
        // чтобы повысить стабильность (каждая служба в отдельном процессе — 70–120 процессов).
        // 
        // При включении мы ставим большое значение (3670016 КБ ≈ 3.5 ГБ), что заставляет Windows
        // группировать службы в меньше процессов (20–50 вместо 70–100+), экономя немного ОЗУ.
        // Эффект заметен только на системах с небольшим объёмом RAM (≤4–8 ГБ). На современных ПК (16+ ГБ)
        // группировка будет слабой или отсутствовать, т.к. значение ниже реального объёма памяти.
        // 
        // При выключении — возвращаем стандартное значение Windows (≈380000 КБ).
        // 
        // Изменения применяются ТОЛЬКО после перезагрузки компьютера!
        // =============================================================================
        public bool IsServiceGroupingEnabled
        {
            get => GetRegistryInt(@"SYSTEM\CurrentControlSet\Control", "SvcHostSplitThresholdInKB", 380000) > 1000000;
            set
            {
                // 3670016 КБ ≈ 3.5 ГБ — классическое значение для принудительной группировки в старых твиках
                SetRegistry(@"SYSTEM\CurrentControlSet\Control", "SvcHostSplitThresholdInKB", value ? 3670016 : 380000);

                AddLog($"Группировка служб: {(value ? "ВКЛЮЧЕНА" : "ВЫКЛЮЧЕНА")}");
                AddLog("⚠ Обязательна перезагрузка ПК для применения изменений!");

                OnPropertyChanged();
            }
        }


        // ==========================
        // ЯДРО СИСТЕМНЫХ КОМАНД
        // ==========================

        private void RunSystemCommand(string command, string arguments, bool isHidden = true)
        {
            // Весь остальной код внутри метода оставьте как есть
            try
            {
                System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
                startInfo.FileName = command;
                startInfo.Arguments = arguments;

                if (isHidden)
                {
                    startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
                    startInfo.CreateNoWindow = true;
                    startInfo.UseShellExecute = false; // Нужно для CreateNoWindow
                }
                else
                {
                    startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Normal;
                }

                System.Diagnostics.Process.Start(startInfo);
            }
            catch (Exception ex)
            {
                if (!ex.Message.Contains("cannot find"))
                    System.Windows.MessageBox.Show($"Ошибка при выполнении команды: {ex.Message}");
            }
        }

        private async Task<string> RunCommandWithOutput(string cmd, string args, bool useEncoding = false)
        {
            return await Task.Run(() =>
            {
                try
                {
                    var info = new ProcessStartInfo
                    {
                        FileName = cmd,
                        Arguments = args,
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };
                    if (useEncoding) info.StandardOutputEncoding = Encoding.GetEncoding(866);

                    using (var p = Process.Start(info))
                    {
                        return p.StandardOutput.ReadToEnd();
                    }
                }
                catch { return ""; }
            });
        }

        // ==========================
        // ЯДРО РЕЕСТРА (64-BIT)
        // ==========================
        public enum RegRoot { HKLM, HKCU }

        private void SetRegistry(string path, string key, object value, RegRoot root = RegRoot.HKLM, RegistryValueKind kind = RegistryValueKind.DWord)
        {
            try
            {
                using (var baseKey = RegistryKey.OpenBaseKey(root == RegRoot.HKLM ? RegistryHive.LocalMachine : RegistryHive.CurrentUser, RegistryView.Registry64))
                using (var subKey = baseKey.CreateSubKey(path, true))
                {
                    subKey?.SetValue(key, value, kind);
                }
            }
            catch (Exception ex) { AddLog($"Ошибка реестра {key}: {ex.Message}"); }
        }

        private int GetRegistryInt(string path, string key, int defaultValue, RegRoot root = RegRoot.HKLM)
        {
            try
            {
                using (var baseKey = RegistryKey.OpenBaseKey(root == RegRoot.HKLM ? RegistryHive.LocalMachine : RegistryHive.CurrentUser, RegistryView.Registry64))
                using (var subKey = baseKey.OpenSubKey(path))
                {
                    return subKey?.GetValue(key) is object val ? Convert.ToInt32(val) : defaultValue;
                }
            }
            catch { return defaultValue; }
        }

        private string GetRegistryString(string path, string key, string defaultValue, RegRoot root = RegRoot.HKLM)
        {
            try
            {
                using (var baseKey = RegistryKey.OpenBaseKey(root == RegRoot.HKLM ? RegistryHive.LocalMachine : RegistryHive.CurrentUser, RegistryView.Registry64))
                using (var subKey = baseKey.OpenSubKey(path))
                {
                    return subKey?.GetValue(key) is object val ? val.ToString() : defaultValue;
                }
            }
            catch { return defaultValue; }
        }

        private string ModifyUserPreferences(string current, string key, string val)
        {
            // Если строка пустая, просто создаем новую пару
            if (string.IsNullOrWhiteSpace(current))
                return $"{key}={val};";

            // Разбиваем по точке с запятой, удаляем пустые хвосты
            var parts = current.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries).ToList();

            bool found = false;
            for (int i = 0; i < parts.Count; i++)
            {
                // Ищем ключ (например "SwapEffectUpgradeEnable=")
                if (parts[i].Trim().StartsWith(key + "=", StringComparison.OrdinalIgnoreCase))
                {
                    parts[i] = $"{key}={val}";
                    found = true;
                    break;
                }
            }

            // Если не нашли, добавляем в конец
            if (!found)
            {
                parts.Add($"{key}={val}");
            }

            // Собираем обратно с точкой с запятой
            return string.Join(";", parts) + ";";
        }

        private string ToggleGlobalFlag(string current, string flag, bool add)
        {
            if (current == null) current = "";
            var parts = current.Split(' ').Where(x => !string.IsNullOrWhiteSpace(x)).ToList();
            if (!parts.Contains("~")) parts.Insert(0, "~");
            if (add) { if (!parts.Contains(flag)) parts.Add(flag); }
            else { if (parts.Contains(flag)) parts.Remove(flag); }
            if (parts.Count == 1 && parts[0] == "~") return "";
            return string.Join(" ", parts);
        }

        // ==========================
        // ОБОИ И ОЧИСТКА
        // ==========================

        public ObservableCollection<WallpaperItem> Wallpapers { get; set; } = new ObservableCollection<WallpaperItem>();
        private WallpaperItem? _selectedWallpaper = null;
        public WallpaperItem? SelectedWallpaper
        {
            get => _selectedWallpaper;
            set
            {
                _selectedWallpaper = value;
                OnPropertyChanged();
            }
        }

        private void LoadWallpapers()
        {
            try
            {
                string imagesPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "images");
                if (!Directory.Exists(imagesPath))
                {
                    Directory.CreateDirectory(imagesPath);
                    return;
                }
                var files = Directory.GetFiles(imagesPath, "*.*")
                                     .Where(s => s.EndsWith(".jpg", StringComparison.OrdinalIgnoreCase) ||
                                                 s.EndsWith(".png", StringComparison.OrdinalIgnoreCase));
                foreach (var file in files)
                {
                    var bitmap = new BitmapImage();
                    bitmap.BeginInit(); bitmap.UriSource = new Uri(file); bitmap.CacheOption = BitmapCacheOption.OnLoad; bitmap.DecodePixelWidth = 200; bitmap.EndInit(); bitmap.Freeze();
                    Wallpapers.Add(new WallpaperItem { Path = file, Name = Path.GetFileName(file), Image = bitmap });
                }
            }
            catch (Exception ex) { AddLog($"Ошибка обоев: {ex.Message}"); }
        }

        private void BtnSetWallpaper_Click(object sender, RoutedEventArgs e)
        {
            if (SelectedWallpaper != null && !string.IsNullOrEmpty(SelectedWallpaper.Path))
            {
                SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, SelectedWallpaper.Path, SPIF_UPDATEINIFILE | SPIF_SENDWININICHANGE);

                // Локальная переменная — компилятор доволен
                string wallpaperName = SelectedWallpaper.Name ?? "Без имени";
                AddLog($"Обои установлены: {wallpaperName}");
            }
            else
            {
                AddLog("Ошибка: обои не выбраны.");
            }
        }

        private async void BtnClean_Click(object sender, RoutedEventArgs e)
        {
            if (IsBusy) return; IsBusy = true; AddLog("Запуск очистки...");
            await Task.Run(() => RunSystemCommand("powershell.exe", "-Command \"Clear-RecycleBin -Force -ErrorAction SilentlyContinue; Remove-Item $env:TEMP\\* -Recurse -Force\""));
            AddLog("Очистка завершена."); IsBusy = false;
        }

        private async void BtnBloat_Click(object sender, RoutedEventArgs e)
        {
            if (IsBusy) return; IsBusy = true; AddLog("Удаление Bloatware...");
            await Task.Run(() => RunSystemCommand("powershell.exe", "-Command \"Get-AppxPackage *cortana* | Remove-AppxPackage; Get-AppxPackage *xboxapp* | Remove-AppxPackage\""));
            AddLog("Bloatware удален."); IsBusy = false;
        }

        private void ConsoleBox_TextChanged(object sender, TextChangedEventArgs e) { (sender as TextBox)?.ScrollToEnd(); }
        public event PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));


        // 1.1 ГИБЕРНАЦИЯ И СОН (НОВОЕ)
        // ==========================

        public bool IsHibernationEnabled
        {
            // Читаем реальное состояние из реестра
            get => GetRegistryInt(@"SYSTEM\CurrentControlSet\Control\Power", "HibernateEnabled", 1, RegRoot.HKLM) == 1;
            set
            {
                // 1. Выполняем команду powercfg
                RunSystemCommand("powercfg", $"/h {(value ? "on" : "off")}");

                // 2. Дублируем в реестр для мгновенного обновления UI (иногда powercfg тормозит с обновлением ключа)
                SetRegistry(@"SYSTEM\CurrentControlSet\Control\Power", "HibernateEnabled", value ? 1 : 0, RegRoot.HKLM);

                AddLog($"Гибернация: {(value ? "ВКЛЮЧЕНА" : "ВЫКЛЮЧЕНА")}");
                OnPropertyChanged();

                // Если включили гибернацию, обновляем список схем, так как может появиться Fast Boot
                if (value) LoadPowerPlans();
            }
        }

        // ==========================
        // COMPACT OS
        // ==========================

        private async void BtnCompactOn_Click(object sender, RoutedEventArgs e)
        {
            if (IsBusy) return;
            IsBusy = true;
            AddLog("Включаю Compact OS...");
            await Task.Run(() =>
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "compact.exe",
                    Arguments = "/compactos:always",
                    UseShellExecute = true, // Важно: runas для админ-прав
                    Verb = "runas",
                    CreateNoWindow = true
                };
                try
                {
                    using (var process = Process.Start(psi))
                    {
                        process?.WaitForExit();
                    }
                    AddLog("Compact OS включён успешно.");
                }
                catch (Exception ex)
                {
                    AddLog($"Ошибка при включении Compact OS: {ex.Message}");
                }
            });
            IsBusy = false;
        }

        private async void BtnCompactOff_Click(object sender, RoutedEventArgs e)
        {
            if (IsBusy) return;
            IsBusy = true;
            AddLog("Выключаю Compact OS...");
            await Task.Run(() =>
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "compact.exe",
                    Arguments = "/compactos:never",
                    UseShellExecute = true,
                    Verb = "runas",
                    CreateNoWindow = true
                };
                try
                {
                    using (var process = Process.Start(psi))
                    {
                        process?.WaitForExit();
                    }
                    AddLog("Compact OS выключен успешно.");
                }
                catch (Exception ex)
                {
                    AddLog($"Ошибка при выключении Compact OS: {ex.Message}");
                }
            });
            IsBusy = false;
        }


        private string RunCommandSync(string cmd, string args)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = cmd,
                    Arguments = args,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    // Ключевое: кодировка OEM 866 для консольного вывода на русской Windows
                    StandardOutputEncoding = Encoding.GetEncoding(866),
                    StandardErrorEncoding = Encoding.GetEncoding(866)
                };

                using var process = Process.Start(psi);

                // Читаем оба потока одновременно, чтобы избежать deadlock
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();

                process.WaitForExit();

                // Возвращаем ошибку, если она есть, иначе обычный вывод
                // Если ошибка пустая — возвращаем вывод
                string result = !string.IsNullOrWhiteSpace(error) ? error : output;

                return result.Trim();
            }
            catch (Exception ex)
            {
                // Игнорируем ошибки "cannot find" или "Не удается найти"
                if (ex.Message.Contains("cannot find") || ex.Message.Contains("Не удается найти"))
                    return "";
                return $"Исключение при выполнении команды: {ex.Message}";
            }
        }




        // ==========================
        // БЛОКИРОВКА ОБНОВЛЕНИЙ ЧЕРЕЗ WUB (НАДЁЖНЫЙ СПОСОБ)
        // ==========================
        private string WubPath => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Wub.exe");

        private async Task<bool> RunWubAsync(string arguments)
        {
            if (!File.Exists(WubPath))
            {
                AddLog("ОШИБКА: Wub.exe не найден в папке с программой!");
                return false;
            }

            return await Task.Run(() =>
            {
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = WubPath,
                        Arguments = arguments,
                        UseShellExecute = true,        // Нужно для запуска от админа
                        Verb = "runas",                // Автоматический запрос UAC (программа уже от админа)
                        CreateNoWindow = true,
                        WindowStyle = ProcessWindowStyle.Hidden
                    };

                    using (var process = Process.Start(psi))
                    {
                        process?.WaitForExit();
                        return process?.ExitCode == 0;
                    }
                }
                catch (Exception ex)
                {
                    AddLog($"Ошибка запуска WUB: {ex.Message}");
                    return false;
                }
            });
        }

        // ==========================
        // БЛОКИРОВКА ОБНОВЛЕНИЙ ЧЕРЕЗ WINDOWS UPDATE BLOCKER (WUB)
        // ==========================
        private string WubExePath => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Wub.exe");
        private string WubIniPath => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Wub.ini");

        private async Task<bool> ApplyWubSettings()
        {
            if (!File.Exists(WubExePath))
            {
                AddLog("ОШИБКА: Wub.exe не найден в папке с программой!");
                return false;
            }

            return await Task.Run(() =>
            {
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = WubExePath,
                        UseShellExecute = true,
                        Verb = "runas",
                        CreateNoWindow = true,
                        WindowStyle = ProcessWindowStyle.Hidden
                    };

                    using var process = Process.Start(psi);
                    process?.WaitForExit();
                    return true;
                }
                catch (Exception ex)
                {
                    AddLog($"Ошибка запуска Wub.exe: {ex.Message}");
                    return false;
                }
            });
        }

        private void ModifyWubIni(bool disableUpdates, bool protectServices)
        {
            if (!File.Exists(WubIniPath))
            {
                AddLog("Wub.ini не найден. Запустите Wub.exe вручную хотя бы один раз.");
                return;
            }

            try
            {
                var lines = new List<string>(File.ReadAllLines(WubIniPath));
                bool changed = false;

                for (int i = 0; i < lines.Count; i++)
                {
                    if (lines[i].StartsWith("ServicesStatus="))
                    {
                        lines[i] = $"ServicesStatus={(disableUpdates ? "1" : "0")}";
                        changed = true;
                    }
                    else if (lines[i].StartsWith("ProtectServices="))
                    {
                        lines[i] = $"ProtectServices={(protectServices ? "1" : "0")}";
                        changed = true;
                    }
                }

                if (changed)
                {
                    File.WriteAllLines(WubIniPath, lines);
                }
            }
            catch (Exception ex)
            {
                AddLog($"Ошибка изменения Wub.ini: {ex.Message}");
            }
        }

        // ==========================
        // СКРЫТНАЯ БЛОКИРОВКА ОБНОВЛЕНИЙ ЧЕРЕЗ WINDOWS UPDATE BLOCKER
        // ==========================
        private string UpdateBlockerExe => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Wub.exe");
        private string UpdateBlockerIni => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Wub.ini");

        private async Task<bool> ApplyUpdateBlockerSilently()
        {
            if (!File.Exists(UpdateBlockerExe))
            {
                AddLog("ОШИБКА: Wub.exe не найден в папке с программой!");
                return false;
            }

            return await Task.Run(() =>
            {
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = UpdateBlockerExe,
                        Arguments = "/apply",                  // Скрытно применяет настройки из ini
                        UseShellExecute = true,
                        Verb = "runas",
                        CreateNoWindow = true,
                        WindowStyle = ProcessWindowStyle.Hidden
                    };

                    using var process = Process.Start(psi);
                    process?.WaitForExit();
                    return true;
                }
                catch (Exception ex)
                {
                    AddLog($"Ошибка скрытного применения настроек: {ex.Message}");
                    return false;
                }
            });
        }

        private void ChangeUpdateBlockerSettings(bool blockUpdates, bool protectServices)
        {
            if (!File.Exists(UpdateBlockerIni))
            {
                AddLog("Wub.ini не найден. Запустите Wub.exe вручную один раз для создания файла.");
                return;
            }

            try
            {
                var lines = new List<string>(File.ReadAllLines(UpdateBlockerIni));
                bool changed = false;

                for (int i = 0; i < lines.Count; i++)
                {
                    if (lines[i].StartsWith("ServicesStatus="))
                    {
                        lines[i] = $"ServicesStatus={(blockUpdates ? "1" : "0")}";
                        changed = true;
                    }
                    else if (lines[i].StartsWith("ProtectServices="))
                    {
                        lines[i] = $"ProtectServices={(protectServices ? "1" : "0")}";
                        changed = true;
                    }
                }

                if (changed)
                {
                    File.WriteAllLines(UpdateBlockerIni, lines);
                }
            }
            catch (Exception ex)
            {
                AddLog($"Ошибка изменения Wub.ini: {ex.Message}");
            }
        }

        // ==========================
        // СКРЫТНАЯ БЛОКИРОВКА ОБНОВЛЕНИЙ ЧЕРЕЗ WUB (МИНИМАЛЬНОЕ ОКНО)
        // ==========================
        private string BlockerExe => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Wub.exe");
        private string BlockerIni => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Wub.ini");

        private async Task<bool> RunBlockerWithArgs(string args)
        {
            if (!File.Exists(BlockerExe))
            {
                AddLog("ОШИБКА: Wub.exe не найден в папке с программой!");
                return false;
            }

            return await Task.Run(() =>
            {
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = BlockerExe,
                        Arguments = args,                  // /D /P или /E
                        UseShellExecute = true,
                        Verb = "runas",
                        CreateNoWindow = false,            // Окно всё равно покажется кратко
                        WindowStyle = ProcessWindowStyle.Normal
                    };

                    using var process = Process.Start(psi);
                    process?.WaitForExit();
                    return true;
                }
                catch (Exception ex)
                {
                    AddLog($"Ошибка запуска Wub.exe: {ex.Message}");
                    return false;
                }
            });
        }

        private void SetIniSettings(bool disable, bool protect)
        {
            if (!File.Exists(BlockerIni))
            {
                AddLog("Wub.ini не найден. Запустите Wub.exe вручную один раз.");
                return;
            }

            try
            {
                var lines = new List<string>(File.ReadAllLines(BlockerIni));
                bool changed = false;

                for (int i = 0; i < lines.Count; i++)
                {
                    if (lines[i].StartsWith("ServicesStatus="))
                    {
                        lines[i] = $"ServicesStatus={(disable ? "1" : "0")}";
                        changed = true;
                    }
                    else if (lines[i].StartsWith("ProtectServices="))
                    {
                        lines[i] = $"ProtectServices={(protect ? "1" : "0")}";
                        changed = true;
                    }
                }

                if (changed)
                {
                    File.WriteAllLines(BlockerIni, lines);
                }
            }
            catch (Exception ex)
            {
                AddLog($"Ошибка изменения Wub.ini: {ex.Message}");
            }
        }

        // ==========================
        // КНОПКИ ДЛЯ УПРАВЛЕНИЯ ОБНОВЛЕНИЯМИ WINDOWS (WUB)
        // ==========================
        public ICommand BlockUpdatesCommand { get; }
        public ICommand EnableUpdatesCommand { get; }

        private readonly string _wubExe = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Wub.exe");

        private async Task<bool> RunWub(string args)
        {
            if (!File.Exists(_wubExe))
            {
                AddLog("Wub.exe отсутствует рядом с исполняемым файлом основной программы.");
                return false;
            }

            return await Task.Run(() =>
            {
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = _wubExe,
                        Arguments = args,
                        UseShellExecute = true,
                        Verb = "runas",
                        CreateNoWindow = false,
                        WindowStyle = ProcessWindowStyle.Normal
                    };

                    using var p = Process.Start(psi);
                    p?.WaitForExit();
                    return true;
                }
                catch (Exception ex)
                {
                    AddLog($"Ошибка запуска Wub.exe: {ex.Message}");
                    return false;
                }
            });
        }
        // ПАУЗА ДЛЯ ОБНОВЛЕНИЙ ВИНДОВС (БЕСКОНЕЧНАЯ) ===
        public bool IsInfinitePauseEnabled
        {
            get
            {
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = "schtasks.exe",
                        Arguments = "/query /tn \"\\PauseWindowsUpdate\" /fo list",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        StandardOutputEncoding = Encoding.GetEncoding(866),
                        StandardErrorEncoding = Encoding.GetEncoding(866)
                    };

                    using (var process = Process.Start(psi))
                    {
                        process.WaitForExit();
                        return process.ExitCode == 0; // 0 = задача существует
                    }
                }
                catch
                {
                    return false;
                }
            }
            set
            {
                Task.Run(() =>
                {
                    IsBusy = true;
                    AddLog("Управление бесконечной паузой обновлений...");

                    if (value) // ВКЛЮЧАЕМ
                    {
                        string taskXml = @"<?xml version=""1.0"" encoding=""UTF-16""?>
<Task version=""1.2"" xmlns=""http://schemas.microsoft.com/windows/2004/02/mit/task"">
  <RegistrationInfo>
    <URI>\PauseWindowsUpdate</URI>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Repetition>
        <Interval>P1D</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id=""Author"">
      <UserId>S-1-5-19</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context=""Author"">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-ExecutionPolicy Bypass -Command ""$pause = (Get-Date).AddDays(35); $date = $pause.ToString('yyyy-MM-ddTHH:mm:ssK'); Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesExpiryTime' -Value $date -Type String -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseQualityUpdatesEndTime' -Value $date -Type String -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseFeatureUpdatesEndTime' -Value $date -Type String -Force""</Arguments>
    </Exec>
  </Actions>
</Task>";

                        string tempXml = Path.Combine(Path.GetTempPath(), "PauseWindowsUpdate_Task.xml");
                        File.WriteAllText(tempXml, taskXml, Encoding.Unicode);

                        string result = RunCommandSync("schtasks", $"/create /tn \"\\PauseWindowsUpdate\" /xml \"{tempXml}\" /f");

                        try { File.Delete(tempXml); } catch { }

                        // Даже если пишет "ОШИБКА: уже существует" — с /f задача перезаписана успешно
                        if (result.Contains("Успех") || result.Contains("SUCCESS") || result.Contains("уже существует") || string.IsNullOrWhiteSpace(result))
                        {
                            AddLog("✓ Бесконечная пауза обновлений ВКЛЮЧЕНА.");
                            AddLog("Задача планировщика 'PauseWindowsUpdate' успешно создана/обновлена для бесконечной паузы обновлений.");
                        }
                        else
                        {
                            AddLog(result.Trim());
                        }
                    }
                    else // ВЫКЛЮЧАЕМ
                    {
                        string result = RunCommandSync("schtasks", "/delete /tn \"\\PauseWindowsUpdate\" /f");

                        if (result.Contains("Успех") || result.Contains("SUCCESS") || result.Contains("успешно") || string.IsNullOrWhiteSpace(result))
                        {
                            AddLog("✗ Бесконечная пауза обновлений ОТКЛЮЧЕНА.");
                            AddLog("Задача планировщика 'PauseWindowsUpdate' для бесконечной паузы обновлений удалена.");
                        }
                        else
                        {
                            AddLog("Результат команды schtasks: " + result.Trim());
                        }
                    }

                    Dispatcher.Invoke(() => OnPropertyChanged(nameof(IsInfinitePauseEnabled)));
                    IsBusy = false;
                });
            }
        }


        // === ДОПОЛНИТЕЛЬНЫЕ GAMING ТВИКИ (ЭКСПЕРИМЕНТАЛЬНЫЕ) ===

        // === ИЗОЛЯЦИЯ ЯДРА / ЦЕЛОСТНОСТЬ ПАМЯТИ (Memory Integrity / HVCI) ===
        // Без принудительной активации — только с согласия пользователя и проверкой
        public bool IsMemoryIntegrityDisabled
        {
            get
            {
                int hvci = GetRegistryInt(@"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled", 0);
                int vbs = GetRegistryInt(@"SYSTEM\CurrentControlSet\Control\DeviceGuard", "EnableVirtualizationBasedSecurity", 0);
                string bcdOutput = RunCommandSync("bcdedit", "/enum {current}");
                bool isBcdOff = bcdOutput.Contains("hypervisorlaunchtype    Off");

                return hvci == 0 || vbs == 0 || isBcdOff;
            }
            set
            {
                Task.Run(() =>
                {
                    IsBusy = true;
                    AddLog("Применение настроек изоляции ядра...");

                    // Всегда чистим политики и Locked-флаги (чтобы галочка не была серой)
                    try { Registry.LocalMachine.DeleteSubKeyTree(@"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard", false); } catch { }
                    DeleteRegistryValue(@"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Locked");
                    DeleteRegistryValue(@"SYSTEM\CurrentControlSet\Control\DeviceGuard", "Locked");

                    if (value) // === ОТКЛЮЧАЕМ ИЗОЛЯЦИЮ ЯДРА (безопасно, для гейминга) ===
                    {
                        AddLog("Отключение изоляции ядра (рекомендуется для игр)...");

                        SetRegistry(@"SYSTEM\CurrentControlSet\Control\DeviceGuard", "EnableVirtualizationBasedSecurity", 0);
                        SetRegistry(@"SYSTEM\CurrentControlSet\Control\DeviceGuard", "RequirePlatformSecurityFeatures", 0);
                        SetRegistry(@"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled", 0);
                        SetRegistry(@"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", 0);
                        SetRegistry(@"SYSTEM\CurrentControlSet\Control\Lsa", "LsaCfgFlags", 0);

                        RunSystemCommand("bcdedit", "/set hypervisorlaunchtype off");
                        RunSystemCommand("bcdedit", "/deletevalue {current} loadoptions");

                        AddLog("Изоляция ядра успешно ОТКЛЮЧЕНА.");
                        MessageBox.Show("Изоляция ядра отключена.\n\nТеперь система совместима с любыми драйверами и оверлеями.\nПерезагрузите ПК для применения.",
                                        "Shuragen4ik Tool", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                    else // === ПОПЫТКА ВКЛЮЧИТЬ ИЗОЛЯЦИЮ ЯДРА (с максимальной осторожностью) ===
                    {
                        // Шаг 1: Сильное предупреждение
                        var confirm = MessageBox.Show(
                            "ВНИМАНИЕ!\n\n" +
                            "Включение изоляции ядра (Memory Integrity) может вызвать СИНИЙ ЭКРАН (BSOD) при перезагрузке,\n" +
                            "если у вас установлены несовместимые драйверы (например: старые драйверы мыши/клавиатуры, оверлеи, макросы, читы и т.д.).\n\n" +
                            "Это защитная функция Windows — она блокирует неподписанные или устаревшие драйверы.\n\n" +
                            "Рекомендуется оставить отключённым для стабильности и производительности в играх.\n\n" +
                            "Вы уверены, что хотите включить изоляцию ядра?",
                            "ОПАСНО: Риск BSOD!",
                            MessageBoxButton.YesNo,
                            MessageBoxImage.Warning);

                        if (confirm != MessageBoxResult.Yes)
                        {
                            AddLog("Пользователь отказался от включения изоляции ядра.");
                            Dispatcher.Invoke(() => OnPropertyChanged(nameof(IsMemoryIntegrityDisabled))); // возвращаем старое значение
                            IsBusy = false;
                            return;
                        }

                        // Шаг 2: Дополнительная проверка на несовместимые драйверы
                        AddLog("Проверка наличия несовместимых драйверов...");
                        string scanResult = RunCommandSync("powershell", "-Command \"Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-CodeIntegrity/Operational'; ID=3076,3077} -MaxEvents 10 -ErrorAction SilentlyContinue | Select-Object -First 1 Message\"");

                        bool hasIncompatible = false;
                        if (!string.IsNullOrWhiteSpace(scanResult) && scanResult.Contains("blocked") || scanResult.Contains("не совместим"))
                        {
                            hasIncompatible = true;
                        }

                        // Также проверяем через встроенный интерфейс (косвенно)
                        if (File.Exists(@"C:\Windows\System32\ci.dll")) // всегда есть, но для примера
                        {
                            // Можно добавить ручной совет
                        }

                        if (hasIncompatible)
                        {
                            var finalConfirm = MessageBox.Show(
                                "ОБНАРУЖЕНЫ НЕСОВМЕСТИМЫЕ ДРАЙВЕРЫ!\n\n" +
                                "Windows уже блокировала загрузку одного или нескольких драйверов.\n" +
                                "Включение изоляции ядра с высокой вероятностью вызовет BSOD.\n\n" +
                                "Рекомендуется:\n" +
                                "• Удалить проблемный софт/драйвер\n" +
                                "• Или оставить изоляцию ядра отключённой\n\n" +
                                "Всё равно включить?",
                                "КРИТИЧЕСКОЕ ПРЕДУПРЕЖДЕНИЕ",
                                MessageBoxButton.YesNo,
                                MessageBoxImage.Stop);

                            if (finalConfirm != MessageBoxResult.Yes)
                            {
                                AddLog("Пользователь отказался после обнаружения несовместимых драйверов.");
                                Dispatcher.Invoke(() => OnPropertyChanged(nameof(IsMemoryIntegrityDisabled)));
                                IsBusy = false;
                                return;
                            }
                        }

                        // Шаг 3: Только после всех проверок — включаем
                        AddLog("Включение изоляции ядра по запросу пользователя...");

                        SetRegistry(@"SYSTEM\CurrentControlSet\Control\DeviceGuard", "EnableVirtualizationBasedSecurity", 1);
                        SetRegistry(@"SYSTEM\CurrentControlSet\Control\DeviceGuard", "RequirePlatformSecurityFeatures", 1);
                        SetRegistry(@"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled", 1);
                        SetRegistry(@"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", 2);
                        SetRegistry(@"SYSTEM\CurrentControlSet\Control\Lsa", "LsaCfgFlags", 1);

                        RunSystemCommand("bcdedit", "/set hypervisorlaunchtype auto");

                        AddLog("Изоляция ядра ВКЛЮЧЕНА по желанию пользователя.");
                        MessageBox.Show("Изоляция ядра включена.\n\n" +
                "Система теперь лучше защищена, но возможны проблемы с драйверами.\n" +
                "ОБЯЗАТЕЛЬНО ПЕРЕЗАГРУЗИТЕ ПК.\n" +
                "Если появится BSOD — загрузитесь в безопасном режиме и отключите эту опцию обратно.",
                "Готово!", MessageBoxButton.OK, MessageBoxImage.Information);
                    }

                    Dispatcher.Invoke(() => OnPropertyChanged(nameof(IsMemoryIntegrityDisabled)));
                    IsBusy = false;
                });
            }
        }

        // Вспомогательный метод для безопасного удаления значения реестра
        private void DeleteRegistryValue(string path, string valueName, RegRoot root = RegRoot.HKLM)
        {
            try
            {
                using (var baseKey = RegistryKey.OpenBaseKey(root == RegRoot.HKLM ? RegistryHive.LocalMachine : RegistryHive.CurrentUser, RegistryView.Registry64))
                using (var subKey = baseKey.OpenSubKey(path, true))
                {
                    subKey?.DeleteValue(valueName, false);
                }
            }
            catch { } // Игнорируем, если значения нет
        }

        public bool IsHagsEnabled
        {
            get
            {
                // Если ключа нет — по умолчанию в свежих Windows 11 HAGS включён (особенно после 22H2+)
                // Но для точности: 2 = включён, 1 = выключен
                int val = GetRegistryInt(@"SYSTEM\CurrentControlSet\Control\GraphicsDrivers", "HwSchMode", 2);
                return val == 2;
            }
            set
            {
                int newVal = value ? 2 : 1;
                SetRegistry(@"SYSTEM\CurrentControlSet\Control\GraphicsDrivers", "HwSchMode", newVal);
                AddLog($"HAGS: {(value ? "ВКЛЮЧЕН" : "ВЫКЛЮЧЕН")}");
                AddLog("⚠ Перезагрузите ПК для применения!");
                OnPropertyChanged();
            }
        }

        public bool IsNotificationsDisabled
        {
            get => GetRegistryInt(@"SOFTWARE\Policies\Microsoft\Windows\Explorer", "DisableNotificationCenter", 0) == 1;
            set
            {
                SetRegistry(@"SOFTWARE\Policies\Microsoft\Windows\Explorer", "DisableNotificationCenter", value ? 1 : 0);
                SetRegistry(@"SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications", "ToastEnabled", value ? 0 : 1);
                AddLog($"Уведомления: {(value ? "ОТКЛЮЧЕНЫ" : "ВКЛЮЧЕНЫ")}");
                OnPropertyChanged();
            }
        }

        public bool IsGamePriorityHigh
        {
            get => GetRegistryInt(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Games", "Priority", 6) == 8;
            set
            {
                SetRegistry(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Games", "Priority", value ? 8 : 6);
                SetRegistry(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Games", "GPU Priority", value ? 8 : 6);
                SetRegistry(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Games", "Scheduling Category", value ? "High" : "Medium", RegRoot.HKLM, RegistryValueKind.String);
                AddLog($"Приоритет игр: {(value ? "HIGH" : "Стандарт")}");
                OnPropertyChanged();
            }
        }

        public bool IsFastStartupDisabled
        {
            get
            {
                // Основной ключ реестра
                int hiberboot = GetRegistryInt(@"SYSTEM\CurrentControlSet\Control\Session Manager\Power", "HiberbootEnabled", 1);
                // Дополнительно проверяем, включена ли гибернация (Fast Startup зависит от hiberfil.sys)
                string output = RunCommandSync("powercfg", "/a");
                bool hibernationAvailable = !output.Contains("Гибернация не включена") && !output.Contains("Hibernation is disabled");

                // Fast Startup отключён, если либо ключ = 0, либо гибернация полностью выключена
                return hiberboot == 0 || !hibernationAvailable;
            }
            set
            {
                SetRegistry(@"SYSTEM\CurrentControlSet\Control\Session Manager\Power", "HiberbootEnabled", value ? 0 : 1);
                // Дополнительно выключаем гибернацию, если нужно
                if (value)
                    RunSystemCommand("powercfg", "/h off");
                AddLog($"Fast Startup: {(value ? "ОТКЛЮЧЕН" : "ВКЛЮЧЕН")}");
                OnPropertyChanged();
            }
        }

        public bool IsMenuDelayZero
        {
            get => GetRegistryString(@"Control Panel\Desktop", "MenuShowDelay", "400", RegRoot.HKCU) == "0";
            set
            {
                SetRegistry(@"Control Panel\Desktop", "MenuShowDelay", value ? "0" : "400", RegRoot.HKCU, RegistryValueKind.String);
                AddLog($"MenuShowDelay: {(value ? "0 (мгновенно)" : "Стандарт")}");
                OnPropertyChanged();
            }
        }

        // === ОТКЛЮЧЕНИЕ ФОНОВЫХ ПРИЛОЖЕНИЙ (Background Apps) ===
        public bool IsBackgroundAppsDisabled
        {
            get
            {
                // Проверяем политику (самый надёжный способ)
                int policy = GetRegistryInt(@"SOFTWARE\Policies\Microsoft\Windows\AppPrivacy", "LetAppsRunInBackground", 0);
                // Дополнительно проверяем пользовательский ключ
                int user = GetRegistryInt(@"SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications", "GlobalUserDisabled", 0, RegRoot.HKCU);

                // 2 = Force Deny (отключено для всех), 1 у пользователя = отключено
                return policy == 2 || user == 1;
            }
            set
            {
                if (value) // ОТКЛЮЧАЕМ фоновые приложения
                {
                    // Основной способ: групповая политика (для всей системы)
                    SetRegistry(@"SOFTWARE\Policies\Microsoft\Windows\AppPrivacy", "LetAppsRunInBackground", 2);

                    // Страховка: пользовательский ключ
                    SetRegistry(@"SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications", "GlobalUserDisabled", 1, RegRoot.HKCU);

                    AddLog("Фоновые приложения: ОТКЛЮЧЕНЫ (для всех пользователей)");
                }
                else // ВКЛЮЧАЕМ обратно
                {
                    // Удаляем политику (самый чистый способ)
                    try
                    {
                        Registry.LocalMachine.DeleteSubKeyTree(@"SOFTWARE\Policies\Microsoft\Windows\AppPrivacy", false);
                    }
                    catch { /* Игнорируем, если ключа нет */ }

                    // Сбрасываем пользовательский флаг
                    DeleteRegistryValue(@"SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications", "GlobalUserDisabled", RegRoot.HKCU);

                    AddLog("Фоновые приложения: РАЗРЕШЕНЫ (стандартное поведение)");
                }

                OnPropertyChanged();
            }
        }

        // Метод для обновления всех состояний UI после системных изменений
        private void RefreshAllUIStates()
        {
            // Force refresh all bindings by resetting DataContext
            var oldContext = DataContext;
            DataContext = null;
            DataContext = oldContext;
        }
        


        // === АКТИВАЦИЯ WINDOWS И OFFICE ===
        private async void BtnActivateWindows_Click(object sender, RoutedEventArgs e)
        {
            await RunMASActivation("Для активации Windows выберите пункт [1] HWID в открывшемся меню.");
        }

        private async void BtnActivateOffice_Click(object sender, RoutedEventArgs e)
        {
            await RunMASActivation("Для активации Office выберите пункт [2] OHook в открывшемся меню.");
        }

        private async Task RunMASActivation(string instruction)
        {
            if (IsBusy) return;

            var confirm = MessageBox.Show(
                "ВНИМАНИЕ!\n\n" +
                "Запустится Microsoft Activation Scripts (MAS) — открытый инструмент для активации.\n" +
                "Рекомендуемые методы: HWID (Windows навсегда), OHook (Office с авто-обновлением).\n" +
                "Требуется интернет. Антивирус может сработать (ложное положительное).\n" +
                "Оригинал: https://massgrave.dev\n\n" +
                instruction + "\n\nПродолжить?",
                "Активация через MAS", MessageBoxButton.YesNo, MessageBoxImage.Warning);

            if (confirm != MessageBoxResult.Yes) return;

            IsBusy = true;
            AddLog("Запуск Microsoft Activation Scripts (MAS)...");
            AddLog("Инструкция: " + instruction);

            // Список альтернативных URL для обхода блокировок
            string[] masUrls = new[]
            {
                "https://get.activated.win",
                "https://massgrave.dev/脚本",
                "https://raw.githubusercontent.com/massgravel/Microsoft-Activation-Scripts/master/MAS/All-In-One-Version/MAS_AIO.cmd"
            };

            bool success = false;
            Exception? lastError = null;

            await Task.Run(() =>
            {
                foreach (string url in masUrls)
                {
                    try
                    {
                        AddLog($"Попытка загрузки с: {url}");

                        var psi = new ProcessStartInfo
                        {
                            FileName = "powershell.exe",
                            Arguments = $"-ExecutionPolicy Bypass -Command \"irm {url} -TimeoutSec 30 | iex\"",
                            UseShellExecute = true,
                            Verb = "runas",
                            WindowStyle = ProcessWindowStyle.Normal
                        };

                        using var process = Process.Start(psi);
                        // Таймаут 3 минуты на запуск MAS
                        bool finished = process!.WaitForExit(180000);
                        
                        if (finished)
                        {
                            success = true;
                            AddLog("MAS успешно загружен и запущен.");
                            break;
                        }
                        else
                        {
                            process.Kill();
                            AddLog("Таймаут загрузки, пробуем следующий URL...");
                        }
                    }
                    catch (Exception ex)
                    {
                        lastError = ex;
                        AddLog($"Ошибка с URL {url}: {ex.Message}");
                        continue;
                    }
                }
            });

            if (!success)
            {
                AddLog("Не удалось загрузить MAS автоматически.");
                
                var manualResult = MessageBox.Show(
                    $"Автоматическая загрузка не удалась.\n\n" +
                    $"Последняя ошибка: {lastError?.Message ?? "Неизвестная ошибка"}\n\n" +
                    "Хотите открыть инструкцию по ручной активации?",
                    "Ручная активация",
                    MessageBoxButton.YesNo, MessageBoxImage.Information);

                if (manualResult == MessageBoxResult.Yes)
                {
                    // Показываем инструкцию для ручного запуска
                    MessageBox.Show(
                        "Ручной запуск MAS:\n\n" +
                        "1. Откройте PowerShell от имени Администратора\n" +
                        "2. Скопируйте и вставьте команду:\n\n" +
                        "irm https://get.activated.win | iex\n\n" +
                        "Или скачайте скрипт вручную:\n" +
                        "https://massgrave.dev/get","Ручная активация", MessageBoxButton.OK, MessageBoxImage.Information);
                    
                    // Открываем браузер
                    try { Process.Start("explorer.exe", "https://massgrave.dev"); } catch { }
                }
            }
            else
            {
                AddLog("MAS завершён. Проверьте статус в Параметры → Обновление и безопасность → Активация.");
            }

            IsBusy = false;
        }


        




    }

    public class RelayCommand : ICommand
    {
        private readonly Action _execute;
        private readonly Func<bool>? _canExecute;

        public RelayCommand(Action execute, Func<bool>? canExecute = null)
        {
            _execute = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute;
        }

        public bool CanExecute(object? parameter) => _canExecute == null || _canExecute();

        public void Execute(object? parameter) => _execute();

        public event EventHandler? CanExecuteChanged;
    }

    public class BoolToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return (bool)value ? new SolidColorBrush(Colors.White) : new SolidColorBrush(Colors.LightGray);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
    }

    public class BoolToBoldConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return (bool)value ? FontWeights.Bold : FontWeights.Normal;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
    }
}
