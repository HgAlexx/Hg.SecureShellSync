using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
using KeePass.Forms;
using KeePass.Plugins;
using KeePass.Resources;
using KeePassLib;
using KeePassLib.Interfaces;
using KeePassLib.Resources;
using KeePassLib.Security;
using KeePassLib.Serialization;
using Renci.SshNet;

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
        private const string PluginName = "Hg.SecureShellSync";

        private IPluginHost _host;
        private bool _isAutoSync;
        private PwEntry _optionsEntry;
        private PwUuid _optionsUuid;

        private bool _optionSyncOnOpen;
        private bool _optionSyncOnSave;
        private int _optionTimerTimeSpanValue;
        private Timer _timer;

        private int _timerLastHours = -1;
        private int _timerLastMinutes = -1;

        private DateTime _timerNextSync;
        private ToolStripMenuItem _tsmiOptions;
        private ToolStripMenuItem _tsmiOptionsTimer;
        private ToolStripMenuItem _tsmiPopup;
        private ToolStripMenuItem _tsmiSync;

        private ToolStripSeparator _tsSeparator;

        #endregion

        #region Members

        public override bool Initialize(IPluginHost host)
        {
            _host = host;
            _timer = new Timer();

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

            ToolStripMenuItem tsmiOpen = new ToolStripMenuItem();
            tsmiOpen.Text = KPRes.UrlOpenTitle;
            tsmiOpen.Click += OnMenuOpen;
            tsmiOpen.Enabled = false;
            _tsmiPopup.DropDownItems.Add(tsmiOpen);

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

        private void DebugMsg(string text)
        {
#if (DEBUG)
            //MessageBox.Show(text, "Debug message", MessageBoxButtons.OK, MessageBoxIcon.Information);
#endif
        }

        private void DebugMsg(Exception ex)
        {
            DebugMsg(ex.Message + Environment.NewLine + ex.StackTrace);
        }

        private SyncResultCode DoSynchronize()
        {
            //DebugMsg("DoSynchronize");

            if (_optionTimerTimeSpanValue > 0)
            {
                _timerNextSync = DateTime.UtcNow.AddMinutes(_optionTimerTimeSpanValue);
            }

            SyncResultCode result = Synchronize();

            switch (result)
            {
                case SyncResultCode.Success:
                    _host.MainWindow.SetStatusEx(PluginName + ": " + KPRes.SyncSuccess);
                    break;
                case SyncResultCode.InvalidParameters:
                    _host.MainWindow.SetStatusEx(PluginName + ": " + KPRes.SyncFailed);
                    if (!_isAutoSync)
                    {
                        MessageBox.Show(KPRes.InvalidUrl, PluginName + ": " + KPRes.SyncFailed, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }

                    break;
                case SyncResultCode.InvalidProtocol:
                    _host.MainWindow.SetStatusEx(PluginName + ": " + KPRes.SyncFailed);
                    if (!_isAutoSync)
                    {
                        MessageBox.Show(KPRes.InvalidUrl, PluginName + ": " + KPRes.SyncFailed, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }

                    break;
                case SyncResultCode.InvalidHost:
                    _host.MainWindow.SetStatusEx(PluginName + ": " + KPRes.SyncFailed);
                    if (!_isAutoSync)
                    {
                        MessageBox.Show(KPRes.InvalidUrl, PluginName + ": " + KPRes.SyncFailed, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }

                    break;
                case SyncResultCode.InvalidPort:
                    _host.MainWindow.SetStatusEx(PluginName + ": " + KPRes.SyncFailed);
                    if (!_isAutoSync)
                    {
                        MessageBox.Show(KPRes.InvalidUrl, PluginName + ": " + KPRes.SyncFailed, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }

                    break;
                case SyncResultCode.InvalidCredentials:
                    _host.MainWindow.SetStatusEx(PluginName + ": " + KPRes.SyncFailed);
                    if (!_isAutoSync)
                    {
                        MessageBox.Show(KPRes.InvalidUserPassword, PluginName + ": " + KPRes.SyncFailed, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }

                    break;
                case SyncResultCode.InvalidPath:
                    _host.MainWindow.SetStatusEx(PluginName + ": " + KPRes.SyncFailed);
                    if (!_isAutoSync)
                    {
                        MessageBox.Show(KPRes.FileNotFoundError, PluginName + ": " + KPRes.SyncFailed, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }

                    break;
                case SyncResultCode.ConnectFailed:
                    _host.MainWindow.SetStatusEx(PluginName + ": " + KPRes.SyncFailed);
                    if (!_isAutoSync)
                    {
                        MessageBox.Show(KLRes.UnknownError, PluginName + ": " + KPRes.SyncFailed, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }

                    break;
                case SyncResultCode.DownloadFailed:
                    _host.MainWindow.SetStatusEx(PluginName + ": " + KPRes.SyncFailed);
                    if (!_isAutoSync)
                    {
                        MessageBox.Show(KLRes.UnknownError, PluginName + ": " + KPRes.SyncFailed, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }

                    break;
                case SyncResultCode.UploadFailed:
                    _host.MainWindow.SetStatusEx(PluginName + ": " + KPRes.SyncFailed);
                    if (!_isAutoSync)
                    {
                        MessageBox.Show(KLRes.UnknownError, PluginName + ": " + KPRes.SyncFailed, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }

                    break;
                case SyncResultCode.MergeFailed:
                    _host.MainWindow.SetStatusEx(PluginName + ": " + KPRes.SyncFailed);
                    if (!_isAutoSync)
                    {
                        MessageBox.Show(KLRes.UnknownError, PluginName + ": " + KPRes.SyncFailed, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }

                    break;
                default:
                    _host.MainWindow.SetStatusEx(PluginName + ": " + KPRes.SyncFailed);
                    if (!_isAutoSync)
                    {
                        MessageBox.Show(KLRes.UnknownError, PluginName + ": " + KPRes.SyncFailed, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }

                    break;
            }

            return result;
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
        }

        private HgSecureShellSyncData GetHgKeePassSftpSyncData()
        {
            HgSecureShellSyncData hgSecureShellSyncData = new HgSecureShellSyncData();
            string url = EntryRetrieve(PwDefs.UrlField);

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

            if (_optionSyncOnSave)
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

                int.TryParse(EntryRetrieve(FieldOptionTimerTimeSpanValue), out _optionTimerTimeSpanValue);
                bool.TryParse(EntryRetrieve(FieldOptionSyncOnOpen), out _optionSyncOnOpen);
                bool.TryParse(EntryRetrieve(FieldOptionSyncOnSave), out _optionSyncOnSave);

                if (_optionTimerTimeSpanValue < 0)
                {
                    _optionTimerTimeSpanValue = 0;
                }
            }

            return _optionsEntry != null;
        }

        private SyncResultCode Synchronize()
        {
            if (_timer != null)
            {
                _timer.Stop();
            }

            HgSecureShellSyncData hgSecureShellSyncData = GetHgKeePassSftpSyncData();
            if (hgSecureShellSyncData == null)
            {
                return SyncResultCode.InvalidParameters;
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

            return SyncResultCode.InvalidProtocol;
        }

        private SyncResultCode SynchronizeSftp(SftpClient sftpClient, HgSecureShellSyncData hgSecureShellSyncData)
        {
            try
            {
                sftpClient.Connect();
            }
            catch (Exception ex)
            {
                if (ex.Message.Contains("username") || ex.Message.Contains("password"))
                {
                    return SyncResultCode.InvalidCredentials;
                }

                return SyncResultCode.ConnectFailed;
            }

            // sync here
            string localTempDbFile = _host.TempFilesPool.GetTempFileName(false);
            if (File.Exists(localTempDbFile))
            {
                File.Delete(localTempDbFile);
            }

            string remoteDbPath = hgSecureShellSyncData.Path + Path.GetFileName(_host.MainWindow.ActiveDatabase.IOConnectionInfo.Path);

            bool fileCorrupted = false;
            bool localSaved = false;

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

                    return SyncResultCode.DownloadFailed;
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
                    _host.Database.Save(logger);
                    localSaved = true;
                    // merge remote into local
                    _host.Database.MergeIn(localTempDb, PwMergeMethod.Synchronize);
                    // Refresh UI
                    _host.MainWindow.UpdateUI(false, null, true, null, true, null, true);
                    localTempDb.Close();
                }
                catch (CryptographicException ex)
                {
                    // remote file is corrupted
                    fileCorrupted = true;
                }
                catch (Exception ex)
                {
                    return SyncResultCode.MergeFailed;
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
                    return SyncResultCode.MergeFailed;
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
                if (!localSaved)
                    _host.Database.Save(logger2);

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

                return SyncResultCode.UploadFailed;
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
                        DebugMsg(ex);
                    }
                    finally
                    {
                        if (fileStream != null)
                            fileStream.Close();
                    }
                }
                else
                {
                    return SyncResultCode.UploadFailed;
                }

                if (!AreFilesEqual(new FileInfo(localTempDbFile), new FileInfo(localTempDbFile2)))
                {
                    // delete corrupted file (keep last backup)
                    if (sftpClient.Exists(remoteDbPath))
                    {
                        sftpClient.DeleteFile(remoteDbPath);
                    }

                    return SyncResultCode.UploadFailed;
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

                return SyncResultCode.Success;
            }

            return SyncResultCode.UnknownError;
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