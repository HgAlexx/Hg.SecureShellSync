using System;
using System.IO;
using System.Reflection;

namespace HgSecureShellSync
{
    /// <summary>
    /// Replacement for the binding redirects a normal application would declare in app.config.
    ///
    /// KeePass compiles this plugin into a PLGX and loads it into its own process, so the plugin
    /// has no configuration file of its own and KeePass.exe.config carries no redirect for our
    /// dependencies. Several of the assemblies shipped in lib\ were compiled against older
    /// versions of the .NET support packages, for example Microsoft.Extensions.Logging.Abstractions
    /// references System.Memory 4.0.1.2 while the version we ship is 4.0.5.0. Without a redirect
    /// the CLR refuses the load and the failure surfaces as a FileNotFoundException in the middle
    /// of an unrelated operation, such as SSH.NET disposing a session.
    ///
    /// This resolver answers those failed loads with the assembly of the same simple name that is
    /// already loaded, which is exactly what a "newest version wins" binding redirect would do.
    /// </summary>
    internal static class HgAssemblyResolver
    {
        private static readonly object SyncRoot = new object();
        private static bool _installed;

        /// <summary>
        /// Assemblies we ship and are willing to redirect. Restricting the list keeps the handler
        /// from interfering with KeePass itself or with any other plugin.
        /// </summary>
        private static readonly string[] RedirectableAssemblies =
        {
            "System.Memory",
            "System.Buffers",
            "System.Numerics.Vectors",
            "System.Runtime.CompilerServices.Unsafe",
            "System.Threading.Tasks.Extensions",
            "System.Formats.Asn1",
            "Microsoft.Bcl.AsyncInterfaces",
            "Microsoft.Bcl.Cryptography",
            "Microsoft.Extensions.Logging.Abstractions",
            "Microsoft.Extensions.DependencyInjection.Abstractions",
            "BouncyCastle.Cryptography",
            "Renci.SshNet"
        };

        public static void Install()
        {
            lock (SyncRoot)
            {
                if (_installed)
                {
                    return;
                }

                AppDomain.CurrentDomain.AssemblyResolve += OnAssemblyResolve;
                _installed = true;
            }
        }

        public static void Uninstall()
        {
            lock (SyncRoot)
            {
                if (!_installed)
                {
                    return;
                }

                AppDomain.CurrentDomain.AssemblyResolve -= OnAssemblyResolve;
                _installed = false;
            }
        }

        private static Assembly OnAssemblyResolve(object sender, ResolveEventArgs args)
        {
            try
            {
                AssemblyName requested = new AssemblyName(args.Name);

                if (!IsRedirectable(requested.Name))
                {
                    return null;
                }

                // The plugin assemblies are already loaded by KeePass from the PLGX cache
                // directory, so the correct version is in memory even though the exact identity
                // the caller asked for does not exist anywhere on disk.
                Assembly[] loaded = AppDomain.CurrentDomain.GetAssemblies();
                for (int i = 0; i < loaded.Length; i++)
                {
                    if (string.Equals(loaded[i].GetName().Name, requested.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        HgLog.Info("Redirected assembly load: " + args.Name + " -> " + loaded[i].GetName().FullName);
                        return loaded[i];
                    }
                }

                return ProbePluginDirectory(requested.Name);
            }
            catch (Exception ex)
            {
                // A throwing resolve handler would take down the whole process.
                HgLog.Warn("Assembly resolve handler failed for " + args.Name + ". " + HgLog.Describe(ex, true));
                return null;
            }
        }

        /// <summary>
        /// Fallback for a dependency that has not been loaded yet: look next to this assembly,
        /// which is where KeePass extracts the PLGX content at runtime.
        /// </summary>
        private static Assembly ProbePluginDirectory(string simpleName)
        {
            string folder = Path.GetDirectoryName(typeof(HgAssemblyResolver).Assembly.Location);
            if (string.IsNullOrEmpty(folder))
            {
                return null;
            }

            string candidate = Path.Combine(folder, simpleName + ".dll");
            if (!File.Exists(candidate))
            {
                return null;
            }

            Assembly assembly = Assembly.LoadFrom(candidate);
            HgLog.Info("Loaded assembly from plugin directory: " + candidate);
            return assembly;
        }

        private static bool IsRedirectable(string simpleName)
        {
            for (int i = 0; i < RedirectableAssemblies.Length; i++)
            {
                if (string.Equals(RedirectableAssemblies[i], simpleName, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
