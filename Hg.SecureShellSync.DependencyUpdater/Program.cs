using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Xml.Linq;

namespace Hg.SecureShellSync.DependencyUpdater
{
    /// <summary>
    /// Keeps the plugin's local <c>lib</c> folder in sync with the NuGet dependency
    /// closure resolved for this project.
    ///
    /// KeePass compiles the plugin into a PLGX and cannot restore NuGet packages, so every
    /// dependency has to be a committed DLL referenced through a HintPath. Declaring the
    /// packages here and running this tool removes the need to update those files by hand.
    ///
    /// Usage:
    ///   Hg.SecureShellSync.DependencyUpdater            report differences only
    ///   Hg.SecureShellSync.DependencyUpdater --update   copy the assemblies into lib and
    ///                                                   rewrite the plugin's Reference items
    /// </summary>
    internal static class Program
    {
        private const string PluginProjectName = "Hg.SecureShellSync";

        private const string LibFolderName = "lib";

        /// <summary>
        /// Assemblies produced by this tool itself, which must never end up in the plugin's lib folder.
        /// </summary>
        private static readonly HashSet<string> ExcludedAssemblies =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "Hg.SecureShellSync.DependencyUpdater"
            };

        /// <summary>
        /// Assemblies that .NET Framework 4.8 already provides as a facade. Shipping a copy in lib
        /// creates an unresolvable MSB3277 conflict, because the facade wins as the primary
        /// reference while the packaged dependencies bind to a higher version and a PLGX has no
        /// application configuration file to redirect them. These must be left to the framework.
        /// </summary>
        private static readonly HashSet<string> FrameworkFacades =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "System.ValueTuple"
            };

        private static int Main(string[] args)
        {
            var update = args.Any(a => string.Equals(a, "--update", StringComparison.OrdinalIgnoreCase));

            try
            {
                var outputDirectory = AppDomain.CurrentDomain.BaseDirectory;
                var libDirectory = ResolveLibDirectory();

                Console.WriteLine("Resolved packages : " + outputDirectory);
                Console.WriteLine("Plugin lib folder : " + libDirectory);
                Console.WriteLine();

                var resolved = ReadAssemblies(outputDirectory)
                    .Where(a => !ExcludedAssemblies.Contains(a.Name))
                    .Where(a => !FrameworkFacades.Contains(a.Name))
                    .OrderBy(a => a.Name, StringComparer.OrdinalIgnoreCase)
                    .ToList();

                if (resolved.Count == 0)
                {
                    Console.Error.WriteLine("No resolved assemblies found. Build this project first.");
                    return 1;
                }

                var changed = Report(resolved, libDirectory, update);
                ReportOrphans(resolved, libDirectory);

                if (update)
                {
                    var projectPath = ResolvePluginProjectPath();
                    Console.WriteLine();
                    if (UpdateProjectReferences(resolved, projectPath))
                    {
                        Console.WriteLine("Updated references in " + Path.GetFileName(projectPath) + ".");
                    }
                    else
                    {
                        Console.WriteLine("References in " + Path.GetFileName(projectPath) + " were already correct.");
                    }
                }
                else
                {
                    Console.WriteLine();
                    Console.WriteLine("References that would be written to " + PluginProjectName + ".csproj:");
                    Console.WriteLine();
                    Console.WriteLine(BuildReferenceXml(resolved, "    "));

                    if (changed)
                    {
                        Console.WriteLine("Re-run with --update to apply the changes.");
                    }
                }

                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
                return 1;
            }
        }

        /// <summary>
        /// Walks up from the output folder to the repository root and locates the plugin's lib folder.
        /// </summary>
        private static string ResolveLibDirectory()
        {
            var directory = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);

            while (directory != null)
            {
                var candidate = Path.Combine(directory.FullName, PluginProjectName, LibFolderName);
                if (Directory.Exists(candidate))
                {
                    return candidate;
                }

                directory = directory.Parent;
            }

            throw new DirectoryNotFoundException(
                "Could not locate the " + PluginProjectName + @"\lib folder above " +
                AppDomain.CurrentDomain.BaseDirectory + ".");
        }

        private static List<AssemblyEntry> ReadAssemblies(string directory)
        {
            var entries = new List<AssemblyEntry>();

            foreach (var file in Directory.GetFiles(directory, "*.dll"))
            {
                var entry = AssemblyEntry.TryRead(file);
                if (entry != null)
                {
                    entries.Add(entry);
                }
            }

            return entries;
        }

        /// <summary>
        /// Compares every resolved assembly with its counterpart in the lib folder and,
        /// when <paramref name="update"/> is set, copies the resolved file over.
        /// </summary>
        private static bool Report(IEnumerable<AssemblyEntry> resolved, string libDirectory, bool update)
        {
            var changed = false;

            foreach (var entry in resolved)
            {
                var target = Path.Combine(libDirectory, Path.GetFileName(entry.Path));
                var current = File.Exists(target) ? AssemblyEntry.TryRead(target) : null;

                string state;
                if (current == null)
                {
                    state = "MISSING  -> " + entry.DisplayVersion;
                    changed = true;
                }
                else if (current.Version == entry.Version && current.FileVersion == entry.FileVersion)
                {
                    state = "up to date  " + entry.DisplayVersion;
                }
                else
                {
                    state = current.DisplayVersion + " -> " + entry.DisplayVersion;
                    changed = true;
                }

                Console.WriteLine("  {0,-45} {1}", entry.Name, state);

                if (update && (current == null ||
                               current.Version != entry.Version ||
                               current.FileVersion != entry.FileVersion))
                {
                    File.Copy(entry.Path, target, true);
                    Console.WriteLine("  {0,-45} copied", string.Empty);
                }
            }

            return changed;
        }

        /// <summary>
        /// Lists DLLs still present in the lib folder that are no longer part of the dependency closure.
        /// They are only reported, never deleted, because the plugin may reference them directly.
        /// </summary>
        private static void ReportOrphans(IEnumerable<AssemblyEntry> resolved, string libDirectory)
        {
            var known = new HashSet<string>(
                resolved.Select(r => Path.GetFileName(r.Path)),
                StringComparer.OrdinalIgnoreCase);

            var orphans = Directory.GetFiles(libDirectory, "*.dll")
                .Select(Path.GetFileName)
                .Where(name => !known.Contains(name))
                .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (orphans.Count == 0)
            {
                return;
            }

            Console.WriteLine();
            Console.WriteLine("No longer part of the dependency graph (review before deleting):");
            foreach (var orphan in orphans)
            {
                var isFacade = FrameworkFacades.Contains(Path.GetFileNameWithoutExtension(orphan));
                Console.WriteLine("  " + orphan + (isFacade
                    ? "  <- provided by .NET Framework, delete it and drop its Reference"
                    : string.Empty));
            }
        }

        /// <summary>
        /// Locates the plugin project file next to the lib folder.
        /// </summary>
        private static string ResolvePluginProjectPath()
        {
            var libDirectory = new DirectoryInfo(ResolveLibDirectory());
            var projectPath = Path.Combine(libDirectory.Parent.FullName, PluginProjectName + ".csproj");

            if (!File.Exists(projectPath))
            {
                throw new FileNotFoundException("Could not find the plugin project file.", projectPath);
            }

            return projectPath;
        }

        /// <summary>
        /// Replaces the HintPath based Reference items in the plugin project with items whose
        /// identity matches the assemblies now present in lib, leaving every other reference
        /// (KeePass, framework assemblies) untouched.
        /// </summary>
        private static bool UpdateProjectReferences(IReadOnlyCollection<AssemblyEntry> resolved, string projectPath)
        {
            var document = XDocument.Load(projectPath, LoadOptions.PreserveWhitespace);
            var ns = document.Root.GetDefaultNamespace();

            var localReferences = document.Descendants(ns + "Reference")
                .Where(r => r.Elements(ns + "HintPath")
                    .Any(h => h.Value.StartsWith(LibFolderName + @"\", StringComparison.OrdinalIgnoreCase)))
                .ToList();

            if (localReferences.Count == 0)
            {
                throw new InvalidOperationException(
                    "No lib\\ references found in " + Path.GetFileName(projectPath) + ".");
            }

            var anchor = localReferences[0];
            var container = anchor.Parent;
            var indent = GetIndent(anchor);

            var desired = XElement.Parse(
                "<ItemGroup xmlns=\"" + ns.NamespaceName + "\">" +
                BuildReferenceXml(resolved, indent) +
                "</ItemGroup>",
                LoadOptions.PreserveWhitespace)
                .Elements(ns + "Reference")
                .ToList();

            if (ReferencesMatch(localReferences, desired, ns))
            {
                return false;
            }

            // Insert the new items where the first existing one was, so unrelated
            // references keep their position in the file.
            foreach (var reference in desired)
            {
                anchor.AddBeforeSelf(reference);
                anchor.AddBeforeSelf(new XText(Environment.NewLine + indent));
            }

            foreach (var reference in localReferences)
            {
                RemoveWithTrailingWhitespace(reference);
            }

            // A PLGX is compiled by KeePass from the raw project file, so it must stay
            // readable as plain XML without a BOM.
            using (var writer = new StreamWriter(projectPath, false, new UTF8Encoding(false)))
            {
                document.Save(writer, SaveOptions.DisableFormatting);
            }

            return true;
        }

        private static bool ReferencesMatch(
            IEnumerable<XElement> current,
            IEnumerable<XElement> desired,
            XNamespace ns)
        {
            Func<XElement, string> key = r =>
                (string)r.Attribute("Include") + "|" +
                string.Join(",", r.Elements(ns + "HintPath").Select(h => h.Value));

            return current.Select(key).SequenceEqual(desired.Select(key), StringComparer.Ordinal);
        }

        /// <summary>
        /// Returns the leading whitespace of the line the element sits on, so generated
        /// items line up with the existing file formatting.
        /// </summary>
        private static string GetIndent(XElement element)
        {
            var previous = element.PreviousNode as XText;
            if (previous == null)
            {
                return "    ";
            }

            var text = previous.Value;
            var index = text.LastIndexOf('\n');
            return index < 0 ? "    " : text.Substring(index + 1);
        }

        private static void RemoveWithTrailingWhitespace(XElement element)
        {
            var next = element.NextNode as XText;
            if (next != null && next.Value.Trim().Length == 0)
            {
                next.Remove();
            }

            element.Remove();
        }

        /// <summary>
        /// Emits Reference items whose identity matches the resolved assemblies exactly.
        /// A PLGX has no application configuration file, so binding redirects are unavailable
        /// and the identities must line up.
        /// </summary>
        private static string BuildReferenceXml(IEnumerable<AssemblyEntry> resolved, string indent)
        {
            var builder = new StringBuilder();

            foreach (var entry in resolved)
            {
                builder.Append(indent).AppendLine("<Reference Include=\"" + entry.FullName + "\">");
                builder.Append(indent).AppendLine("  <SpecificVersion>False</SpecificVersion>");
                builder.Append(indent).AppendLine(
                    "  <HintPath>" + LibFolderName + "\\" + Path.GetFileName(entry.Path) + "</HintPath>");
                builder.Append(indent).AppendLine("</Reference>");
            }

            return builder.ToString();
        }

        private sealed class AssemblyEntry
        {
            private AssemblyEntry(string path, AssemblyName name)
            {
                Path = path;
                Name = name.Name;
                Version = name.Version;
                FullName = name.FullName;
                FileVersion = FileVersionInfo.GetVersionInfo(path).FileVersion;
            }

            public string Path { get; }

            public string Name { get; }

            public Version Version { get; }

            public string FullName { get; }

            /// <summary>
            /// Some packages keep a stable assembly version across releases, so the file version
            /// is needed to tell two builds apart.
            /// </summary>
            public string FileVersion { get; }

            public string DisplayVersion
            {
                get { return Version + " (file " + FileVersion + ")"; }
            }

            /// <summary>
            /// Reads the assembly identity without loading the assembly, returning null for native files.
            /// </summary>
            public static AssemblyEntry TryRead(string path)
            {
                try
                {
                    return new AssemblyEntry(path, AssemblyName.GetAssemblyName(path));
                }
                catch (BadImageFormatException)
                {
                    return null;
                }
                catch (FileLoadException)
                {
                    return null;
                }
            }
        }
    }
}
