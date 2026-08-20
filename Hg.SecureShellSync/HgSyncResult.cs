using System;

namespace HgSecureShellSync
{
    /// <summary>
    /// Outcome of a synchronization attempt.
    ///
    /// The plugin used to return a bare <see cref="SyncResultCode"/>, which meant the exception
    /// that actually explained the failure was discarded at the catch site and the user was left
    /// with a generic "Unknown error" dialog. This type carries that detail back to the caller so
    /// it can be logged and displayed.
    /// </summary>
    public sealed class SyncResult
    {
        private SyncResult(SyncResultCode code, string context, Exception exception)
        {
            Code = code;
            Context = context;
            Exception = exception;
        }

        public SyncResultCode Code { get; private set; }

        /// <summary>
        /// Short description of the operation that failed, for example "Connect" or "Upload".
        /// </summary>
        public string Context { get; private set; }

        /// <summary>
        /// The originating exception, or null when the failure was not caused by one.
        /// </summary>
        public Exception Exception { get; private set; }

        public bool Succeeded
        {
            get { return Code == SyncResultCode.Success; }
        }

        public static SyncResult Ok()
        {
            return new SyncResult(SyncResultCode.Success, null, null);
        }

        public static SyncResult Fail(SyncResultCode code, string context)
        {
            return new SyncResult(code, context, null);
        }

        public static SyncResult Fail(SyncResultCode code, string context, Exception exception)
        {
            return new SyncResult(code, context, exception);
        }

        /// <summary>
        /// Lets the existing <c>return SyncResultCode.X</c> statements keep compiling unchanged.
        /// </summary>
        public static implicit operator SyncResult(SyncResultCode code)
        {
            return new SyncResult(code, null, null);
        }

        /// <summary>
        /// Detail suitable for a message box: the failing operation and the exception chain,
        /// without stack traces. Returns an empty string when there is nothing to add.
        /// </summary>
        public string GetDetail()
        {
            string detail = HgLog.Describe(Exception, false);

            if (string.IsNullOrEmpty(Context))
            {
                return detail;
            }

            if (string.IsNullOrEmpty(detail))
            {
                return Context + " failed.";
            }

            return Context + " failed." + Environment.NewLine + detail;
        }

        /// <summary>
        /// Detail suitable for the log file, including stack traces.
        /// </summary>
        public string GetLogDetail()
        {
            string detail = HgLog.Describe(Exception, true);
            string prefix = string.IsNullOrEmpty(Context) ? Code.ToString() : Code + " during " + Context;

            return string.IsNullOrEmpty(detail) ? prefix : prefix + Environment.NewLine + detail;
        }
    }
}
