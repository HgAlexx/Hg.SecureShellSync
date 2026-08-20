using KeePass.Forms;
using KeePass.Plugins;
using KeePass.Resources;
using KeePassLib;
using KeePassLib.Interfaces;
using KeePassLib.Resources;
using KeePassLib.Security;
using KeePassLib.Serialization;
using Renci.SshNet;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace HgSecureShellSync
{
    public enum SyncResultCode
    {
        Success,
        UnknownError,
        InvalidParameters,
        InvalidProtocol,
        InvalidHost,
        InvalidPort,
        InvalidCredentials,
        InvalidPath,
        ConnectFailed,
        DownloadFailed,
        UploadFailed,
        MergeFailed
    }


    public class HgSecureShellSyncData
    {
        #region Fields & Properties

        public string Host;
        public string Path;
        public int Port;
        public string Protocol;

        #endregion

        #region Members

        public override string ToString()
        {
            return Protocol + "|" + Host + " | " + Port.ToString(CultureInfo.InvariantCulture) + " | " + Path;
        }

        #endregion
    }

    public sealed class HgSecureShellSyncExt : Plugin
    {
        #region Fields & Properties

        private const int BYTES_TO_READ = sizeof(long);
        private const string FieldOptionSyncOnOpen = "OptionSyncOnOpen";
        private const string FieldOptionSyncOnSave = "OptionSyncOnSave";
        private const string FieldOptionTimerTimeSpanValue = "OptionTimerTimeSpanValue";
        private const string FieldOverrideUrl = "OverrideUrl";
        private const string PluginName = "Hg.SecureShellSync";

        private IPluginHost _host;
        private bool _isAutoSync;
        private bool _isSynchronizing;
        private PwEntry _optionsEntry;
        private PwUuid _optionsUuid;

        private readonly Dictionary<string, string> _overrideUrl = new Dictionary<string, string>();
        private bool _optionSyncOnOpen;
        private bool _optionSyncOnSave;
        private int _optionTimerTimeSpanValue;
        private Timer _timer;

        private int _timerLastHours = -1;
        private int _timerLastMinutes = -1;

        private DateTime _timerNextSync;
        private ToolStripMenuItem _tsmiOptions;
        private ToolStripMenuItem _tsmiOptionsTimer;
        private ToolStripMenuItem _tsmiOverride;
        private ToolStripMenuItem _tsmiDiagnostics;
        private ToolStripMenuItem _tsmiPopup;
        private ToolStripMenuItem _tsmiSync;

        private ToolStripSeparator _tsSeparator;

        private string _machineName;
        private ToolStripMenuItem _tsmiUrlAdd;
        private ToolStripMenuItem _tsmiUrlEdit;
        private ToolStripMenuItem _tsmiUrlDelete;

        #endregion

        #region Members

        public override bool Initialize(IPluginHost host)
        {
            // Must run before any dependency is touched: a PLGX has no app.config, so the
            // binding redirects our NuGet dependencies expect have to be applied at runtime.
            HgAssemblyResolver.Install();

            // Logging never persists between sessions: it starts disabled and any file left
            // behind by a previous run (for example after a crash) is discarded.
            HgLog.Enabled = false;
            HgLog.Delete();
            _host = host;
            _timer = new Timer();

            _machineName = Environment.MachineName.Trim();

            if (_timer != null)
            {
                _optionTimerTimeSpanValue = 0;
                _timerNextSync = DateTime.UtcNow;
                _timer.Enabled = false;
                _timer.Interval = 998;
                _timer.Tick += TimerOnTick;
            }

            _optionsUuid = new PwUuid(Encoding.Unicode.GetBytes(PluginName + ".Options").Take(16).ToArray());

            // Get a reference to the 'Tools' menu item container
            ToolStripItemCollection tsMenu = _host.MainWindow.ToolsMenu.DropDownItems;
            _tsSeparator = new ToolStripSeparator();
            tsMenu.Add(_tsSeparator);

            _tsmiPopup = new ToolStripMenuItem();
            _tsmiPopup.Text = PluginName;
            tsMenu.Add(_tsmiPopup);

            _host.MainWindow.FileClosed += OnFileClosed;
            _host.MainWindow.FileSaved += OnFileSaved;
            _host.MainWindow.FileOpened += OnFileOpened;
            _host.MainWindow.FileCreated += OnFileCreated;

            return true;
        }

        public override void Terminate()
        {
            if (_timer != null)
            {
                _timer.Stop();
                _timer = null;
            }

            // Remove all of our menu items
            ToolStripItemCollection tsMenu = _host.MainWindow.ToolsMenu.DropDownItems;
            tsMenu.Remove(_tsSeparator);
            tsMenu.Remove(_tsmiPopup);

            // Best effort: the log is a transient debugging aid, it must not survive the session.
            HgLog.Enabled = false;
            HgLog.Delete();

            HgAssemblyResolver.Uninstall();
        }

        private void AddTimeSpanValue(double hours, ToolStripMenuItem tsmiOptionsTimer)
        {
            ToolStripMenuItem tsmiOptionsTimerValue = new ToolStripMenuItem();
            if (hours > 1)
            {
                tsmiOptionsTimerValue.Text = hours + "h";
            }
            else if (Math.Abs(hours - 1) < 0.01)
            {
                tsmiOptionsTimerValue.Text = "1h";
            }
            else if (Math.Abs(hours - 0) < 0.01)
            {
                tsmiOptionsTimerValue.Text = KPRes.Off;
            }
            else
            {
                int minutes = (int) Math.Round(hours * 60.0);
                tsmiOptionsTimerValue.Text = minutes + "m";
            }

            tsmiOptionsTimerValue.Tag = hours;
            if (Math.Abs(hours * 60 - _optionTimerTimeSpanValue) < 0.01)
            {
                tsmiOptionsTimerValue.CheckState = CheckState.Checked;
            }

            tsmiOptionsTimerValue.Click += OnMenuOptionsTimerValue;
            tsmiOptionsTimer.DropDownItems.Add(tsmiOptionsTimerValue);
        }

        private static bool AreFilesEqual(FileInfo first, FileInfo second)
        {
            if (first.Length != second.Length)
            {
                return false;
            }

            int iterations = (int) Math.Ceiling((double) first.Length / BYTES_TO_READ);

            using (FileStream fs1 = first.OpenRead())
            using (FileStream fs2 = second.OpenRead())
            {
                byte[] one = new byte[BYTES_TO_READ];
                byte[] two = new byte[BYTES_TO_READ];

                for (int i = 0; i < iterations; i++)
                {
                    fs1.Read(one, 0, BYTES_TO_READ);
                    fs2.Read(two, 0, BYTES_TO_READ);

                    if (BitConverter.ToInt64(one, 0) != BitConverter.ToInt64(two, 0))
                    {
                        return false;
                    }
                }
            }

            return true;
        }

        private SyncResultCode DoSynchronize()
        {
            //DebugMsg("DoSynchronize");

            if (_optionTimerTimeSpanValue > 0)
            {
                _timerNextSync = DateTime.UtcNow.AddMinutes(_optionTimerTimeSpanValue);
            }

            SyncResult result;
            _isSynchronizing = true;
            try
            {
                result = Synchronize();
            }
            catch (Exception ex)
            {
                // Nothing above is allowed to escape: an unhandled exception here would surface
                // as a bare KeePass crash dialog with no indication that this plugin caused it.
                result = SyncResult.Fail(SyncResultCode.UnknownError, "Synchronize", ex);
            }
            finally
            {
                _isSynchronizing = false;
            }

            if (result.Succeeded)
            {
                HgLog.Info("Synchronization succeeded.");
                _host.MainWindow.SetStatusEx(PluginName + ": " + KPRes.SyncSuccess);
                return result.Code;
            }

            // Always logged, including during auto-sync where no dialog is shown at all.
            HgLog.Error("Synchronization failed. " + result.GetLogDetail());

            _host.MainWindow.SetStatusEx(PluginName + ": " + KPRes.SyncFailed + " (" + result.Code + ")");

            if (!_isAutoSync)
            {
                MessageBox.Show(
                    BuildFailureMessage(result),
                    PluginName + ": " + KPRes.SyncFailed,
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }

            return result.Code;
        }

        /// <summary>
        /// Builds the text shown when a synchronization fails: the summary that matches the
        /// result code, then the underlying reason, then where to find the full log.
        /// </summary>
        private static string BuildFailureMessage(SyncResult result)
        {
            string summary;

            switch (result.Code)
            {
                case SyncResultCode.InvalidParameters:
                case SyncResultCode.InvalidProtocol:
                case SyncResultCode.InvalidHost:
                case SyncResultCode.InvalidPort:
                    summary = KPRes.InvalidUrl;
                    break;
                case SyncResultCode.InvalidCredentials:
                    summary = KPRes.Invalid + " (" + KPRes.UserName + " / " + KPRes.Password + ")!";
                    break;
                case SyncResultCode.InvalidPath:
                    summary = KPRes.FileNotFoundError;
                    break;
                case SyncResultCode.ConnectFailed:
                    summary = "Unable to connect to the server.";
                    break;
                case SyncResultCode.DownloadFailed:
                    summary = "Unable to download the remote database.";
                    break;
                case SyncResultCode.UploadFailed:
                    summary = "Unable to upload the local database.";
                    break;
                case SyncResultCode.MergeFailed:
                    summary = "Unable to merge the remote database.";
                    break;
                default:
                    summary = KLRes.UnknownError;
                    break;
            }

            StringBuilder message = new StringBuilder();
            message.Append(summary);

            string detail = result.GetDetail();
            if (!string.IsNullOrEmpty(detail))
            {
                message.AppendLine();
                message.AppendLine();
                message.Append(detail);
            }

            message.AppendLine();
            message.AppendLine();
            if (HgLog.Enabled)
            {
                message.Append("Details were written to:");
                message.AppendLine();
                message.Append(HgLog.LogFilePath);
            }
            else
            {
                message.Append("For more details, enable logging from the plugin Diagnostics menu and retry.");
            }

            return message.ToString();
        }

        private string EntryRetrieve(string key)
        {
            ProtectedString str = null;
            if (_optionsEntry.Strings.Exists(key))
            {
                str = _optionsEntry.Strings.Get(key);
            }

            return str == null ? "" : str.ReadString();
        }

        private void EntryStore(string key, string value)
        {
            _optionsEntry.Strings.Set(key, new ProtectedString(false, value));
        }

        private void GenerateSubMenus()
        {
            if (_tsmiOptions != null)
            {
                _tsmiPopup.DropDownItems.Remove(_tsmiOptions);
            }

            if (_tsmiSync != null)
            {
                _tsmiPopup.DropDownItems.Remove(_tsmiSync);
            }

            if (_tsmiOverride != null)
            {
                _tsmiPopup.DropDownItems.Remove(_tsmiOverride);
            }

            if (_tsmiDiagnostics != null)
            {
                _tsmiPopup.DropDownItems.Remove(_tsmiDiagnostics);
            }


            _tsmiSync = new ToolStripMenuItem();
            _tsmiSync.Text = KPRes.Synchronize;
            _tsmiSync.Click += OnMenuSync;
            _tsmiPopup.DropDownItems.Insert(0, _tsmiSync);

            _tsmiOptions = new ToolStripMenuItem();
            _tsmiOptions.Text = KPRes.Options;
            _tsmiPopup.DropDownItems.Insert(1, _tsmiOptions);

            ToolStripMenuItem tsmiOptionsEntry = new ToolStripMenuItem();
            tsmiOptionsEntry.Text = KPRes.Entry;
            tsmiOptionsEntry.Click += OnMenuOptionsEntry;
            _tsmiOptions.DropDownItems.Add(tsmiOptionsEntry);

            ToolStripMenuItem tsmiOptionsSyncOnOpen = new ToolStripMenuItem();
            tsmiOptionsSyncOnOpen.Text = KPRes.Synchronize + " " +
                                         KPRes.AfterDatabaseOpen.ToLower();
            tsmiOptionsSyncOnOpen.CheckState = _optionSyncOnOpen ? CheckState.Checked : CheckState.Unchecked;
            tsmiOptionsSyncOnOpen.Click += OnMenuOptionsSyncOnOpen;
            _tsmiOptions.DropDownItems.Add(tsmiOptionsSyncOnOpen);

            ToolStripMenuItem tsmiOptionsSyncOnSave = new ToolStripMenuItem();
            tsmiOptionsSyncOnSave.Text = KPRes.Synchronize + " " + KPRes.SavingPost;
            tsmiOptionsSyncOnSave.CheckState = _optionSyncOnSave ? CheckState.Checked : CheckState.Unchecked;
            tsmiOptionsSyncOnSave.Click += OnMenuOptionsSyncOnSave;
            _tsmiOptions.DropDownItems.Add(tsmiOptionsSyncOnSave);

            _tsmiOptionsTimer = new ToolStripMenuItem();
            _tsmiOptionsTimer.Text = KPRes.ExpiryTime + " " + KPRes.OfLower + " " +
                                     KPRes.Auto + "-" + KPRes.Synchronize;
            _tsmiOptions.DropDownItems.Add(_tsmiOptionsTimer);

            AddTimeSpanValue(0, _tsmiOptionsTimer);
            AddTimeSpanValue(0.5, _tsmiOptionsTimer);
            AddTimeSpanValue(1, _tsmiOptionsTimer);
            AddTimeSpanValue(2, _tsmiOptionsTimer);
            AddTimeSpanValue(4, _tsmiOptionsTimer);
            AddTimeSpanValue(6, _tsmiOptionsTimer);
            AddTimeSpanValue(12, _tsmiOptionsTimer);
            AddTimeSpanValue(24, _tsmiOptionsTimer);


            _tsmiOverride = new ToolStripMenuItem();
            _tsmiOverride.Text = KPRes.Overwrite;
            _tsmiPopup.DropDownItems.Insert(2, _tsmiOverride);


            ToolStripMenuItem tsmiOverrideUrl = new ToolStripMenuItem();
            tsmiOverrideUrl.Text = KPRes.Url;
            _tsmiOverride.DropDownItems.Add(tsmiOverrideUrl);

            _tsmiUrlAdd = new ToolStripMenuItem();
            _tsmiUrlAdd.Text = "Add for " + _machineName;
            _tsmiUrlAdd.Enabled = !_overrideUrl.ContainsKey(_machineName);
            _tsmiUrlAdd.Click += OnMenuOverrideUrlAdd;
            tsmiOverrideUrl.DropDownItems.Add(_tsmiUrlAdd);

            _tsmiUrlEdit = new ToolStripMenuItem();
            _tsmiUrlEdit.Text = "Edit for " + _machineName;
            _tsmiUrlEdit.Enabled = _overrideUrl.ContainsKey(_machineName);
            _tsmiUrlEdit.Click += OnMenuOverrideUrlEdit;
            tsmiOverrideUrl.DropDownItems.Add(_tsmiUrlEdit);

            _tsmiUrlDelete = new ToolStripMenuItem();
            _tsmiUrlDelete.Text = "Delete for " + _machineName;
            _tsmiUrlDelete.Enabled = _overrideUrl.ContainsKey(_machineName);
            _tsmiUrlDelete.Click += OnMenuOverrideUrlDelete;
            tsmiOverrideUrl.DropDownItems.Add(_tsmiUrlDelete);

            _tsmiDiagnostics = new ToolStripMenuItem();
            _tsmiDiagnostics.Text = "Diagnostics";
            _tsmiPopup.DropDownItems.Insert(3, _tsmiDiagnostics);

            ToolStripMenuItem tsmiDiagnosticsEnabled = new ToolStripMenuItem();
            tsmiDiagnosticsEnabled.Text = "Enable logging (this session only)";
            tsmiDiagnosticsEnabled.CheckState = HgLog.Enabled ? CheckState.Checked : CheckState.Unchecked;
            tsmiDiagnosticsEnabled.Click += OnMenuDiagnosticsEnabled;
            _tsmiDiagnostics.DropDownItems.Add(tsmiDiagnosticsEnabled);

            ToolStripMenuItem tsmiDiagnosticsView = new ToolStripMenuItem();
            tsmiDiagnosticsView.Text = "View log";
            tsmiDiagnosticsView.Click += OnMenuDiagnosticsViewLog;
            _tsmiDiagnostics.DropDownItems.Add(tsmiDiagnosticsView);

            ToolStripMenuItem tsmiDiagnosticsFolder = new ToolStripMenuItem();
            tsmiDiagnosticsFolder.Text = "Open log folder";
            tsmiDiagnosticsFolder.Click += OnMenuDiagnosticsOpenLogFolder;
            _tsmiDiagnostics.DropDownItems.Add(tsmiDiagnosticsFolder);

            ToolStripMenuItem tsmiDiagnosticsClear = new ToolStripMenuItem();
            tsmiDiagnosticsClear.Text = "Clear log";
            tsmiDiagnosticsClear.Click += OnMenuDiagnosticsClearLog;
            _tsmiDiagnostics.DropDownItems.Add(tsmiDiagnosticsClear);

        }

        private void OnMenuDiagnosticsEnabled(object sender, EventArgs e)
        {
            ToolStripMenuItem item = sender as ToolStripMenuItem;
            if (item == null)
            {
                return;
            }

            if (HgLog.Enabled)
            {
                HgLog.Enabled = false;
                // Leaving logging off must not leave the collected data on disk.
                HgLog.Delete();
            }
            else
            {
                HgLog.Enabled = true;
                HgLog.Info("Logging enabled. This log is deleted when KeePass exits.");
            }

            item.CheckState = HgLog.Enabled ? CheckState.Checked : CheckState.Unchecked;
            _host.MainWindow.SetStatusEx(PluginName + ": logging " + (HgLog.Enabled ? "enabled" : "disabled"));
        }

        private void OnMenuDiagnosticsViewLog(object sender, EventArgs e)
        {
            if (!File.Exists(HgLog.LogFilePath))
            {
                string reason = HgLog.Enabled
                    ? "The log is empty: " + HgLog.LogFilePath
                    : "Logging is disabled. Enable it from this menu, then reproduce the issue.";

                MessageBox.Show(reason, PluginName, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            OpenWithShell(HgLog.LogFilePath);
        }

        private void OnMenuDiagnosticsOpenLogFolder(object sender, EventArgs e)
        {
            string folder = Path.GetDirectoryName(HgLog.LogFilePath);
            if (string.IsNullOrEmpty(folder))
            {
                return;
            }

            try
            {
                Directory.CreateDirectory(folder);
            }
            catch (Exception ex)
            {
                HgLog.Warn("Unable to create the log folder. " + HgLog.Describe(ex, true));
            }

            OpenWithShell(folder);
        }

        private void OnMenuDiagnosticsClearLog(object sender, EventArgs e)
        {
            HgLog.Clear();
            _host.MainWindow.SetStatusEx(PluginName + ": log cleared");
        }

        private void OpenWithShell(string path)
        {
            try
            {
                Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                HgLog.Warn("Unable to open " + path + ". " + HgLog.Describe(ex, true));
                MessageBox.Show(path, PluginName, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private void OnMenuOverrideUrlAdd(object sender, EventArgs e)
        {
            ToolStripMenuItem item = sender as ToolStripMenuItem;
            if (item == null)
            {
                return;
            }

            HgUrl hgUrl = new HgUrl();
            hgUrl.Text = @"Add Url for " + _machineName;
            hgUrl.SetUrl("");

            if (hgUrl.ShowDialog() == DialogResult.OK)
            {
                if (_overrideUrl.ContainsKey(_machineName))
                    _overrideUrl.Remove(_machineName);
                _overrideUrl.Add(_machineName, hgUrl.GetUrl());
                _tsmiUrlAdd.Enabled = false;
                _tsmiUrlEdit.Enabled = true;
                _tsmiUrlDelete.Enabled = true;
                _optionsEntry.Strings.Set(FieldOverrideUrl, new ProtectedString(false, SerializeOverrideUrl()));
                _optionsEntry.Touch(true);
                _host.MainWindow.UpdateUI(false, null, true, null, true, null, true);
            }
        }

        private void OnMenuOverrideUrlDelete(object sender, EventArgs e)
        {
            ToolStripMenuItem item = sender as ToolStripMenuItem;
            if (item == null)
            {
                return;
            }

            if (_overrideUrl.ContainsKey(_machineName))
            {
                _overrideUrl.Remove(_machineName);
                _tsmiUrlAdd.Enabled = true;
                _tsmiUrlEdit.Enabled = false;
                _tsmiUrlDelete.Enabled = false;
                _optionsEntry.Strings.Set(FieldOverrideUrl, new ProtectedString(false, SerializeOverrideUrl()));
                _optionsEntry.Touch(true);
                _host.MainWindow.UpdateUI(false, null, true, null, true, null, true);
            }
        }

        private void OnMenuOverrideUrlEdit(object sender, EventArgs e)
        {
            ToolStripMenuItem item = sender as ToolStripMenuItem;
            if (item == null)
            {
                return;
            }

            if (!_overrideUrl.ContainsKey(_machineName))
                return;

            HgUrl hgUrl = new HgUrl();
            hgUrl.Text = @"Edit Url for " + _machineName;
            hgUrl.SetUrl(_overrideUrl[_machineName]);

            if (hgUrl.ShowDialog() == DialogResult.OK)
            {
                _overrideUrl[_machineName] = hgUrl.GetUrl();
                _optionsEntry.Strings.Set(FieldOverrideUrl, new ProtectedString(false, SerializeOverrideUrl()));
                _optionsEntry.Touch(true);
                _host.MainWindow.UpdateUI(false, null, true, null, true, null, true);
            }
        }

        private HgSecureShellSyncData GetHgSecureShellSyncData()
        {
            HgSecureShellSyncData hgSecureShellSyncData = new HgSecureShellSyncData();

            string url;

            // check for overridden Url first
            if (_overrideUrl.ContainsKey(_machineName))
            {
                url = _overrideUrl[_machineName];
            }
            else
            {
                url = EntryRetrieve(PwDefs.UrlField);
            }

            if (!url.StartsWith("sftp://"))
            {
                return null;
            }

            UriBuilder uriBuilder = new UriBuilder(url);
            if (uriBuilder.Scheme != "sftp" ||
                uriBuilder.Host == "" ||
                uriBuilder.Port <= 0 ||
                uriBuilder.Path == "")
            {
                return null;
            }

            hgSecureShellSyncData.Protocol = uriBuilder.Scheme;
            hgSecureShellSyncData.Host = uriBuilder.Host;
            hgSecureShellSyncData.Port = uriBuilder.Port;
            hgSecureShellSyncData.Path = uriBuilder.Path;

            return hgSecureShellSyncData;
        }

        private void OnFileClosed(object sender, EventArgs e)
        {
            _optionTimerTimeSpanValue = 0;
            if (_timer != null)
            {
                _timer.Stop();
            }

            if (_tsmiOptions != null)
            {
                _tsmiPopup.DropDownItems.Remove(_tsmiOptions);
            }

            if (_tsmiSync != null)
            {
                _tsmiPopup.DropDownItems.Remove(_tsmiSync);
            }

            if (_tsmiOverride != null)
            {
                _tsmiPopup.DropDownItems.Remove(_tsmiOverride);
            }

            //DebugMsg("OnFileClosed");
        }

        private void OnFileCreated(object sender, EventArgs e)
        {
            //DebugMsg("OnFileCreated");

            OnFileOpened(sender, e);
        }

        private void OnFileOpened(object sender, EventArgs e)
        {
            //DebugMsg("OnFileOpened");

            if (_host.MainWindow.ActiveDatabase == null || !_host.MainWindow.ActiveDatabase.IsOpen)
            {
                return;
            }

            if (!OptionsEntryLoad())
            {
                OptionsEntryCreate();
                GenerateSubMenus();
            }
            else
            {
                GenerateSubMenus();
                if (_timer != null && _optionTimerTimeSpanValue > 0)
                {
                    _timerNextSync = DateTime.UtcNow.AddMinutes(_optionTimerTimeSpanValue);
                    _timer.Start();
                }

                if (_optionSyncOnOpen)
                {
                    if (_host.MainWindow.IsAtLeastOneFileOpen() && _host.MainWindow.ActiveDatabase.IsOpen)
                    {
                        DoSynchronize();
                    }
                }
            }
        }

        private void OnFileSaved(object sender, FileSavedEventArgs e)
        {
            //DebugMsg("OnFileSaved: " + sender);

            if (_optionSyncOnSave && !_isSynchronizing)
            {
                if (_host.MainWindow.IsAtLeastOneFileOpen() && _host.MainWindow.ActiveDatabase.IsOpen)
                {
                    _isAutoSync = _host.MainWindow.IsTrayed() || _host.MainWindow.UIIsInteractionBlocked() ||
                                  !_host.MainWindow.Enabled || !_host.MainWindow.Visible;
                    DoSynchronize();
                    _isAutoSync = false;
                }
            }
        }

        private void OnMenuOpen(object sender, EventArgs e)
        {
            // TODO
        }

        private void OnMenuOptionsEntry(object sender, EventArgs e)
        {
            PwEntryForm form = new PwEntryForm();
            form.InitEx(_optionsEntry, PwEditMode.EditExistingEntry, _host.Database, _host.MainWindow.ClientIcons, false,
                false);
            DialogResult res = form.ShowDialog();

            if (res == DialogResult.OK)
            {
                _host.MainWindow.UpdateUI(false, null, true, null, true, null, true);
            }
        }

        private void OnMenuOptionsSyncOnOpen(object sender, EventArgs eventArgs)
        {
            ToolStripMenuItem item = sender as ToolStripMenuItem;
            if (item == null)
            {
                return;
            }

            _optionSyncOnOpen = !_optionSyncOnOpen;
            item.CheckState = _optionSyncOnOpen ? CheckState.Checked : CheckState.Unchecked;
            _optionsEntry.Strings.Set(FieldOptionSyncOnOpen, new ProtectedString(false, _optionSyncOnOpen.ToString()));
            _optionsEntry.Touch(true);
            _host.MainWindow.UpdateUI(false, null, true, null, true, null, true);
        }

        private void OnMenuOptionsSyncOnSave(object sender, EventArgs e)
        {
            ToolStripMenuItem item = sender as ToolStripMenuItem;
            if (item == null)
            {
                return;
            }

            _optionSyncOnSave = !_optionSyncOnSave;
            item.CheckState = _optionSyncOnSave ? CheckState.Checked : CheckState.Unchecked;
            _optionsEntry.Strings.Set(FieldOptionSyncOnSave, new ProtectedString(false, _optionSyncOnSave.ToString()));
            _optionsEntry.Touch(true);
            _host.MainWindow.UpdateUI(false, null, true, null, true, null, true);
        }

        private void OnMenuOptionsTimerValue(object sender, EventArgs e)
        {
            ToolStripMenuItem item = sender as ToolStripMenuItem;
            if (item == null)
            {
                return;
            }

            _timer.Stop();
            if (item.CheckState == CheckState.Checked)
            {
                if (_optionTimerTimeSpanValue > 0)
                {
                    _timerNextSync = DateTime.UtcNow.AddMinutes(_optionTimerTimeSpanValue);
                    _timer.Start();
                }

                return;
            }

            foreach (ToolStripMenuItem toolStripMenuItem in _tsmiOptionsTimer.DropDownItems)
            {
                toolStripMenuItem.CheckState = CheckState.Unchecked;
            }

            _optionTimerTimeSpanValue = (int) ((double) item.Tag * 60);
            if (_optionTimerTimeSpanValue > 0)
            {
                _timerNextSync = DateTime.UtcNow.AddMinutes(_optionTimerTimeSpanValue);
            }

            if (_optionTimerTimeSpanValue == 0)
            {
                _host.MainWindow.SetStatusEx(PluginName + ": " + KPRes.Auto + "-" + KPRes.Synchronize +
                                             " " + KPRes.Disabled);
            }
            else
            {
                _timer.Start();
            }

            _optionsEntry.Strings.Set(FieldOptionTimerTimeSpanValue,
                new ProtectedString(false,
                    _optionTimerTimeSpanValue.ToString(
                        CultureInfo.InvariantCulture)));
            _optionsEntry.Touch(true);

            item.CheckState = CheckState.Checked;

            _host.MainWindow.UpdateUI(false, null, true, null, true, null, true);
        }

        private void OnMenuSync(object sender, EventArgs e)
        {
            //DebugMsg("OnMenuSync");

            DoSynchronize();
        }

        private bool OptionsEntryCreate()
        {
            // Try load from old version  "Hg.SftpSync"
            if (OptionsEntryLoad(new PwUuid(Encoding.Unicode.GetBytes("Hg.SftpSync" + ".Options").Take(16).ToArray())))
            {
                return true;
            }

            _optionsEntry = new PwEntry(false, false);
            _optionsEntry.SetUuid(_optionsUuid, false);
            _optionsEntry.Strings.Set(PwDefs.TitleField, new ProtectedString(false, PluginName));
            _optionsEntry.Strings.Set(PwDefs.UserNameField, new ProtectedString(false, "sshUsername"));
            _optionsEntry.Strings.Set(PwDefs.UrlField, new ProtectedString(false, "sftp://host:port/path/to/directory/"));
            _optionsEntry.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, "sshPassword"));
            _optionsEntry.Strings.Set(PwDefs.NotesField,
                new ProtectedString(false,
                    "You can do what ever you want with this entry as long as you don't change the Uuid :)" +
                    Environment.NewLine + Environment.NewLine +
                    "Support only SFTP protocol."
                ));

            _optionsEntry.Strings.Set(FieldOptionTimerTimeSpanValue,
                new ProtectedString(false,
                    _optionTimerTimeSpanValue.ToString(
                        CultureInfo.InvariantCulture)));
            _optionsEntry.Strings.Set(FieldOptionSyncOnOpen,
                new ProtectedString(false,
                    _optionSyncOnOpen.ToString(CultureInfo.InvariantCulture)));
            _optionsEntry.Strings.Set(FieldOptionSyncOnSave,
                new ProtectedString(false,
                    _optionSyncOnSave.ToString(CultureInfo.InvariantCulture)));
            _optionsEntry.Strings.Set(FieldOverrideUrl,
                new ProtectedString(false, ""));

            _host.MainWindow.ActiveDatabase.RootGroup.AddEntry(_optionsEntry, true, true);
            _host.MainWindow.UpdateUI(false, null, true, null, true, null, true);
            return _optionsEntry != null;
        }

        private bool OptionsEntryLoad(PwUuid pwUuid = null)
        {
            if (pwUuid == null)
            {
                pwUuid = _optionsUuid;
            }

            _optionsEntry = _host.MainWindow.ActiveDatabase.RootGroup.FindEntry(pwUuid, true);
            if (_optionsEntry != null && _optionsEntry.ParentGroup == null)
            {
                _host.MainWindow.ActiveDatabase.RootGroup.AddEntry(_optionsEntry, true);
                _host.MainWindow.UpdateUI(false, null, true, null, true, null, true);
            }

            if (_optionsEntry != null)
            {
                // Update from previous version
                if (pwUuid != _optionsUuid)
                {
                    _optionsEntry.CreateBackup(_host.MainWindow.ActiveDatabase);
                    _optionsEntry.SetUuid(_optionsUuid, true);
                    _optionsEntry.Strings.Set(PwDefs.TitleField, new ProtectedString(false, PluginName));
                    _optionsEntry.Touch(true);
                }

                if (!_optionsEntry.Strings.Exists(FieldOptionTimerTimeSpanValue))
                {
                    EntryStore(FieldOptionTimerTimeSpanValue,
                        _optionTimerTimeSpanValue.ToString(CultureInfo.InvariantCulture));
                }

                if (!_optionsEntry.Strings.Exists(FieldOptionSyncOnOpen))
                {
                    EntryStore(FieldOptionSyncOnOpen, _optionSyncOnOpen.ToString());
                }

                if (!_optionsEntry.Strings.Exists(FieldOptionSyncOnSave))
                {
                    EntryStore(FieldOptionSyncOnSave, _optionSyncOnSave.ToString());
                }

                if (!_optionsEntry.Strings.Exists(FieldOverrideUrl))
                {
                    EntryStore(FieldOptionSyncOnSave, "");
                }

                int.TryParse(EntryRetrieve(FieldOptionTimerTimeSpanValue), out _optionTimerTimeSpanValue);
                bool.TryParse(EntryRetrieve(FieldOptionSyncOnOpen), out _optionSyncOnOpen);
                bool.TryParse(EntryRetrieve(FieldOptionSyncOnSave), out _optionSyncOnSave);
                DeserializeOverrideUrl(EntryRetrieve(FieldOverrideUrl));

                if (_optionTimerTimeSpanValue < 0)
                {
                    _optionTimerTimeSpanValue = 0;
                }
            }

            return _optionsEntry != null;
        }

        private void DeserializeOverrideUrl(string overrideUrl)
        {
            _overrideUrl.Clear();

            if (string.IsNullOrEmpty(overrideUrl))
                return;

            string[] lines = overrideUrl.Split(new[] { '#' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var line in lines)
            {
                string[] data = line.Split(new[] { '=' }, StringSplitOptions.None);
                if (data.Length == 2)
                    _overrideUrl.Add(data[0], data[1]);
            }
        }

        private string SerializeOverrideUrl()
        {
            var lines = _overrideUrl.Select(pair => pair.Key + "=" + pair.Value).AsEnumerable();
            return string.Join("#", lines);
        }

        private void SaveActiveDatabase()
        {
            // MainWindow.SaveDatabase raises the FileSaving/FileSaved events,
            // which is what KeePass triggers ("Saving database", "Saved database") listen to.
            _host.MainWindow.SaveDatabase(_host.Database, null);
        }

        private SyncResult Synchronize()
        {
            if (_timer != null)
            {
                _timer.Stop();
            }

            HgSecureShellSyncData hgSecureShellSyncData = GetHgSecureShellSyncData();
            if (hgSecureShellSyncData == null)
            {
                return SyncResult.Fail(SyncResultCode.InvalidParameters,
                    "The synchronization URL is missing or could not be parsed");
            }

            PasswordConnectionInfo passwordConnectionInfo = new PasswordConnectionInfo(hgSecureShellSyncData.Host,
                hgSecureShellSyncData.Port,
                EntryRetrieve(PwDefs.UserNameField),
                EntryRetrieve(PwDefs.PasswordField));

            _host.MainWindow.SetStatusEx(PluginName + ": " + "Synchronizing...");

            switch (hgSecureShellSyncData.Protocol)
            {
                case "sftp":
                    SftpClient sftpClient = new SftpClient(passwordConnectionInfo);
                    return SynchronizeSftp(sftpClient, hgSecureShellSyncData);
            }

            return SyncResult.Fail(SyncResultCode.InvalidProtocol,
                "Unsupported protocol '" + hgSecureShellSyncData.Protocol + "', only sftp is supported");
        }

        private SyncResult SynchronizeSftp(SftpClient sftpClient, HgSecureShellSyncData hgSecureShellSyncData)
        {
            try
            {
                HgLog.Info(string.Format("Connecting to host: {0}, port: {1}, remotePath: {2}",
                    hgSecureShellSyncData.Host,
                    hgSecureShellSyncData.Port,
                    hgSecureShellSyncData.Path));
                sftpClient.Connect();
            }
            catch (Exception ex)
            {
                if ((ex.Message != null ? ex.Message.IndexOf("username", StringComparison.OrdinalIgnoreCase) : -1) >= 0 ||
                    (ex.Message != null ? ex.Message.IndexOf("password", StringComparison.OrdinalIgnoreCase) : -1) >= 0)
                {
                    return SyncResult.Fail(SyncResultCode.InvalidCredentials, "Authentication", ex);
                }

                return SyncResult.Fail(SyncResultCode.ConnectFailed, "Connect", ex);
            }

            // sync here
            string localTempDbFile = _host.TempFilesPool.GetTempFileName(false);
            if (File.Exists(localTempDbFile))
            {
                File.Delete(localTempDbFile);
            }

            string remoteDbPath = hgSecureShellSyncData.Path + Path.GetFileName(_host.MainWindow.ActiveDatabase.IOConnectionInfo.Path);

            bool fileCorrupted = false;

            FileStream fileStream = null;

            // If exists: get remote and Sync into local
            if (sftpClient.Exists(remoteDbPath))
            {
                try
                {
                    fileStream = new FileStream(localTempDbFile, FileMode.Create, FileAccess.Write);
                    sftpClient.DownloadFile(remoteDbPath, fileStream);
                    fileStream.Close();
                }
                catch (Exception ex)
                {
                    if (fileStream != null)
                    {
                        fileStream.Close();
                    }

                    if (File.Exists(localTempDbFile))
                    {
                        File.Delete(localTempDbFile);
                    }

                    return SyncResult.Fail(SyncResultCode.DownloadFailed, "Download of " + remoteDbPath, ex);
                }

                IOConnectionInfo ioConnectionInfo = new IOConnectionInfo();
                ioConnectionInfo.Path = localTempDbFile;
                IStatusLogger logger = new StatusLog();
                PwDatabase localTempDb = new PwDatabase();
                try
                {
                    // load remote (temp) db
                    localTempDb.Open(ioConnectionInfo, _host.Database.MasterKey, logger);
                    // save local (active) db to be sure to have up-to-date data
                    // (silent save: the events are raised by the post-merge save only)
                    _host.Database.Save(logger);
                    // merge remote into local
                    _host.Database.MergeIn(localTempDb, PwMergeMethod.Synchronize);
                    // Refresh UI
                    _host.MainWindow.UpdateUI(false, null, true, null, true, null, true);
                    localTempDb.Close();
                }
                catch (CryptographicException ex)
                {
                    // remote file is corrupted, or the master key no longer matches
                    HgLog.Warn("Unable to open the remote database, it may be corrupted or the " +
                               "master key may differ. " + HgLog.Describe(ex, false));
                    fileCorrupted = true;
                }
                catch (Exception ex)
                {
                    return SyncResult.Fail(SyncResultCode.MergeFailed, "Merge", ex);
                }
                finally
                {
                    localTempDb = null;
                    logger = null;
                    ioConnectionInfo = null;
                    fileStream = null;
                    if (File.Exists(localTempDbFile))
                    {
                        File.Delete(localTempDbFile);
                    }
                }
            }

            if (fileCorrupted)
            {
                if (_isAutoSync || MessageBox.Show(
                    "The remote database file may be corrupted." + Environment.NewLine +
                        "Do you want to override it with the LOCAL database file ?" + Environment.NewLine +
                        "WARNING:" + Environment.NewLine +
                        "- If you have changed the masterkey of the LOCAL database since the last sync, click yes." + Environment.NewLine +
                        "- If you jave changed the masterkey on ANOTHER device since last sync, click no, THEN update the masterkey of the LOCAL database and THEN resync.",
                    "Unable to open remote file", MessageBoxButtons.YesNo, MessageBoxIcon.Stop) == DialogResult.No)
                {
                    return SyncResult.Fail(SyncResultCode.MergeFailed,
                        "Merge: the remote database could not be opened and overwriting was declined");
                }

                // delete corrupted file (keep last backup)
                if (sftpClient.Exists(remoteDbPath))
                {
                    sftpClient.DeleteFile(remoteDbPath);
                }
            }

            // Once sync (if needed) SaveAs tempFile before upload
            string localTempDbFile2 = _host.TempFilesPool.GetTempFileName(false);
            FileStream fileStream2 = null;
            IOConnectionInfo ioConnectionInfo2 = new IOConnectionInfo();
            ioConnectionInfo2.Path = localTempDbFile2;
            IStatusLogger logger2 = new StatusLog();
            try
            {
                // save local (active) db to be sure to have up-to-date data
                // (also persists the data merged in from the remote db and raises the save events)
                SaveActiveDatabase();

                // SaveAs local (active) db into tempFile
                _host.Database.SaveAs(ioConnectionInfo2, false, logger2);

                if (sftpClient.Exists(remoteDbPath))
                {
                    if (sftpClient.Exists(remoteDbPath + ".bak"))
                    {
                        sftpClient.DeleteFile(remoteDbPath + ".bak");
                    }

                    sftpClient.RenameFile(remoteDbPath, remoteDbPath + ".bak");
                }

                fileStream2 = new FileStream(localTempDbFile2, FileMode.Open, FileAccess.Read);
                // Upload to server
                sftpClient.UploadFile(fileStream2, remoteDbPath);
                fileStream2.Close();
            }
            catch (Exception ex)
            {
                if (fileStream2 != null)
                {
                    fileStream2.Close();
                }

                if (File.Exists(localTempDbFile2))
                {
                    File.Delete(localTempDbFile2);
                }

                return SyncResult.Fail(SyncResultCode.UploadFailed, "Upload of " + remoteDbPath, ex);
            }
            finally
            {
                // Refresh UI
                _host.MainWindow.UpdateUI(false, null, true, null, true, null, false);
            }

            // control upload
            try
            {
                if (sftpClient.Exists(remoteDbPath))
                {
                    try
                    {
                        fileStream = new FileStream(localTempDbFile, FileMode.Create, FileAccess.Write);
                        // Get freshly uploaded remote copy
                        sftpClient.DownloadFile(remoteDbPath, fileStream);
                    }
                    catch (Exception ex)
                    {
                        // Non fatal: this is only the post-upload verification copy.
                        HgLog.Warn("Unable to download the uploaded database for verification. " + HgLog.Describe(ex, true));
                    }
                    finally
                    {
                        if (fileStream != null)
                            fileStream.Close();
                    }
                }
                else
                {
                    return SyncResult.Fail(SyncResultCode.UploadFailed,
                        "Upload verification: " + remoteDbPath + " is missing from the server after upload");
                }

                if (!AreFilesEqual(new FileInfo(localTempDbFile), new FileInfo(localTempDbFile2)))
                {
                    // delete corrupted file (keep last backup)
                    if (sftpClient.Exists(remoteDbPath))
                    {
                        sftpClient.DeleteFile(remoteDbPath);
                    }

                    return SyncResult.Fail(SyncResultCode.UploadFailed,
                        "Upload verification: the uploaded file does not match the local database");
                }
            }
            finally
            {
                if (File.Exists(localTempDbFile))
                {
                    File.Delete(localTempDbFile);
                }

                if (File.Exists(localTempDbFile2))
                {
                    File.Delete(localTempDbFile2);
                }
            }

            if (sftpClient.IsConnected)
            {
                sftpClient.Disconnect();
                OptionsEntryLoad();
                GenerateSubMenus();
                if (_timer != null && _optionTimerTimeSpanValue > 0)
                {
                    _timer.Start();
                }

                return SyncResult.Ok();
            }

            return SyncResult.Fail(SyncResultCode.UnknownError,
                "The connection was lost before the synchronization could be confirmed");
        }


        private void TimerOnTick(object sender, EventArgs eventArgs)
        {
            _timer.Stop();
            if (_optionTimerTimeSpanValue == 0)
            {
                return;
            }

            TimeSpan timeSpan = _timerNextSync.Subtract(DateTime.UtcNow);
            if (timeSpan.TotalSeconds > 0)
            {
                int minutes = (int) timeSpan.TotalMinutes;
                int hours = (int) timeSpan.TotalHours;
                if (hours > 0)
                {
                    minutes = timeSpan.Minutes;
                }

                if (hours > 0)
                {
                    if (_timerLastHours != hours || _timerLastMinutes != minutes)
                    {
                        _host.MainWindow.SetStatusEx(
                            PluginName + ": " +
                            string.Format(
                                KPRes.Auto + "-" + KPRes.Synchronize + ": {0}h{1}",
                                hours, minutes.ToString("00")));
                        _timerLastHours = hours;
                        _timerLastMinutes = minutes;
                    }
                }
                else if (minutes > 0)
                {
                    if (_timerLastMinutes != minutes)
                    {
                        _host.MainWindow.SetStatusEx(
                            PluginName + ": " +
                            string.Format(
                                KPRes.Auto + "-" + KPRes.Synchronize + ": {0}h{1}",
                                hours, minutes.ToString("00")));
                        _timerLastHours = hours;
                        _timerLastMinutes = minutes;
                    }
                }
                else if (minutes == 0)
                {
                    _host.MainWindow.SetStatusEx(
                        PluginName + ": " +
                        string.Format(
                            KPRes.Auto + "-" + KPRes.Synchronize + ": {0}s",
                            (int) timeSpan.TotalSeconds));
                }

                _timer.Start();
            }
            else
            {
                if (_host.MainWindow.IsAtLeastOneFileOpen() && _host.MainWindow.ActiveDatabase.IsOpen)
                {
                    _isAutoSync = true;
                    DoSynchronize();
                    _isAutoSync = false;
                }
            }
        }

        #endregion
    }

    public class StatusLog : IStatusLogger
    {
        #region Members

        public bool ContinueWork()
        {
            return true;
        }

        public void EndLogging()
        {
        }

        public bool SetProgress(uint uPercent)
        {
            return true;
        }

        public bool SetText(string strNewText, LogStatusType lsType)
        {
            return true;
        }

        public void StartLogging(string strOperation, bool bWriteOperationToLog)
        {
            throw new NotImplementedException();
        }

        #endregion
    }
}