using System;
using System.Globalization;
using System.IO;
using System.Text;

namespace HgSecureShellSync
{
    /// <summary>
    /// Minimal file logger for the plugin.
    ///
    /// A PLGX is always compiled in Release by KeePass, so conditional or debugger based
    /// diagnostics are unavailable on a user machine. Auto-sync also suppresses every dialog,
    /// which means a scheduled failure would otherwise leave no trace at all. This writes a
    /// plain text log that a user can read or attach to a bug report.
    ///
    /// Never pass credentials or database content to these methods. Host, port and remote path
    /// are fine, the user name and password are not.
    /// </summary>
    public static class HgLog
    {
        private const long MaxLogBytes = 512 * 1024;

        private static readonly object SyncRoot = new object();
        private static string _logFilePath;

        /// <summary>
        /// Logging is opt-in and deliberately session scoped: it is never persisted anywhere,
        /// so it always starts disabled and the log file is removed when KeePass exits.
        /// </summary>
        public static bool Enabled { get; set; }

        /// <summary>
        /// Full path of the log file, kept beside the other per-user application data so it
        /// stays writable regardless of where KeePass itself is installed.
        /// </summary>
        public static string LogFilePath
        {
            get
            {
                if (_logFilePath == null)
                {
                    string folder = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        "Hg.SecureShellSync");

                    _logFilePath = Path.Combine(folder, "Hg.SecureShellSync.log");
                }

                return _logFilePath;
            }
        }

        public static void Info(string message)
        {
            Write("INFO ", message);
        }

        public static void Warn(string message)
        {
            Write("WARN ", message);
        }

        public static void Error(string message)
        {
            Write("ERROR", message);
        }

        /// <summary>
        /// Logs a failure together with the full exception chain, which is the detail that was
        /// previously discarded by the catch blocks.
        /// </summary>
        public static void Error(string message, Exception ex)
        {
            Write("ERROR", message + Environment.NewLine + Describe(ex, true));
        }

        /// <summary>
        /// Produces a human readable description of an exception and every inner exception.
        /// </summary>
        /// <param name="includeStackTrace">
        /// Stack traces are useful in the log file but only add noise in a message box.
        /// </param>
        public static string Describe(Exception ex, bool includeStackTrace)
        {
            if (ex == null)
            {
                return string.Empty;
            }

            StringBuilder builder = new StringBuilder();
            Exception current = ex;
            int depth = 0;

            while (current != null)
            {
                if (depth > 0)
                {
                    builder.AppendLine();
                    builder.Append("Caused by: ");
                }

                builder.Append(current.GetType().Name);
                builder.Append(": ");
                builder.Append(current.Message);

                if (includeStackTrace && !string.IsNullOrEmpty(current.StackTrace))
                {
                    builder.AppendLine();
                    builder.Append(current.StackTrace);
                }

                current = current.InnerException;
                depth++;
            }

            return builder.ToString();
        }

        /// <summary>
        /// Empties the log file. Used by the diagnostics menu before reproducing an issue.
        /// </summary>
        public static void Clear()
        {
            Delete();
        }

        /// <summary>
        /// Best effort removal of the log file and its rolled generation. Called when KeePass
        /// exits so no diagnostic data is left behind on the machine.
        /// </summary>
        public static void Delete()
        {
            lock (SyncRoot)
            {
                DeleteFile(LogFilePath);
                DeleteFile(LogFilePath + ".1");
            }
        }

        private static void DeleteFile(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch (Exception)
            {
                // Logging must never break the plugin, and the file may still be open in an editor.
            }
        }

        private static void Write(string level, string message)
        {
            if (!Enabled)
            {
                return;
            }

            lock (SyncRoot)
            {
                try
                {
                    string folder = Path.GetDirectoryName(LogFilePath);
                    if (!Directory.Exists(folder))
                    {
                        Directory.CreateDirectory(folder);
                    }

                    Roll();

                    string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) +
                                  " [" + level + "] " + message;

                    File.AppendAllText(LogFilePath, line + Environment.NewLine, Encoding.UTF8);
                }
                catch (Exception)
                {
                    // A failure to log must never surface to the user or abort a sync.
                }
            }
        }

        /// <summary>
        /// Keeps a single previous generation so the log cannot grow without bound.
        /// </summary>
        private static void Roll()
        {
            FileInfo info = new FileInfo(LogFilePath);
            if (!info.Exists || info.Length < MaxLogBytes)
            {
                return;
            }

            string previous = LogFilePath + ".1";
            if (File.Exists(previous))
            {
                File.Delete(previous);
            }

            File.Move(LogFilePath, previous);
        }
    }
}
