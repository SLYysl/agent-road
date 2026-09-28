using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Drawing;
using System.IO;
using System.ServiceProcess;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using System.Xml;
using System.Reflection;
using System.Security.Cryptography;

internal static class Program {
    static string InstallRoot() { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AgentRoadDiagnosticsPreview"); }
    static string Digest(string path) {
        using (var stream = File.OpenRead(path)) using (var sha = SHA256.Create())
            return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "");
    }
    static void PlainPath(string path) {
        for (var item = new DirectoryInfo(path); item != null; item = item.Parent)
            if (item.Exists && (item.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("REPARSE_PATH_REFUSED");
    }
    static void InstallLocal() {
        string root = InstallRoot(); PlainPath(root);
        if (Directory.Exists(root) || File.Exists(root)) throw new IOException("INSTALL_TARGET_EXISTS");
        string source = Assembly.GetExecutingAssembly().Location;
        string hash = Digest(source);
        Directory.CreateDirectory(root);
        string destination = Path.Combine(root, "AgentRoadDiagnostics.exe");
        File.Copy(source, destination, false);
        if (Digest(destination) != hash) throw new IOException("INSTALLED_HASH_MISMATCH");
        var record = new Dictionary<string, object> { { "schemaVersion", 1 }, { "product", "AgentRoadDiagnosticsPreview" }, { "sha256", hash } };
        using (var file = new FileStream(Path.Combine(root, "installed.json"), FileMode.CreateNew, FileAccess.Write))
        using (var writer = new StreamWriter(file)) writer.Write(new JavaScriptSerializer().Serialize(record));
    }
    static void UninstallLocal() {
        string root = InstallRoot(); PlainPath(root);
        string exe = Path.Combine(root, "AgentRoadDiagnostics.exe");
        string receipt = Path.Combine(root, "installed.json");
        if (String.Equals(Path.GetFullPath(Assembly.GetExecutingAssembly().Location), Path.GetFullPath(exe), StringComparison.OrdinalIgnoreCase))
            throw new IOException("USE_ORIGINAL_PACKAGE_TO_UNINSTALL");
        if (!Directory.Exists(root) || Directory.GetFileSystemEntries(root).Length != 2 || !File.Exists(exe) || !File.Exists(receipt))
            throw new IOException("UNINSTALL_CONTENT_CHANGED");
        foreach (string path in new[] { exe, receipt })
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException("REPARSE_PATH_REFUSED");
        if (new FileInfo(receipt).Length > 4096) throw new IOException("UNINSTALL_CONTENT_CHANGED");
        var record = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(File.ReadAllText(receipt));
        if (record.Count != 3 || !record.ContainsKey("schemaVersion") || !record.ContainsKey("product") || !record.ContainsKey("sha256")
            || !Object.Equals(record["schemaVersion"], 1) || !Object.Equals(record["product"], "AgentRoadDiagnosticsPreview")
            || !Object.Equals(record["sha256"], Digest(exe))) throw new IOException("UNINSTALL_CONTENT_CHANGED");
        File.Delete(exe); File.Delete(receipt); Directory.Delete(root, false);
    }
    static string Collect() {
        var report = new Dictionary<string, object>();
        report["schemaVersion"] = 1;
        report["product"] = "Agent Road Diagnostics Preview";
        report["utc"] = DateTime.UtcNow.ToString("o");
        report["osVersion"] = Environment.OSVersion.VersionString;
        report["remoteAccessConfiguredByThisApp"] = false;
        report["bootstrapDirectoryExists"] = Directory.Exists(@"C:\ProgramData\AgentRoad");
        var services = new Dictionary<string, string>();
        foreach (string name in new[] { "sshd", "Tailscale" }) {
            try { using (var s = new ServiceController(name)) services[name] = s.Status.ToString(); }
            catch { services[name] = "UNAVAILABLE_OR_NOT_INSTALLED"; }
        }
        report["services"] = services;
        var events = new List<object>();
        try {
            var query = new EventLogQuery("Microsoft-Windows-Windows Defender/Operational",
                PathType.LogName, "*[System[(EventID=1116 or EventID=1117)]]");
            query.ReverseDirection = true;
            using (var reader = new EventLogReader(query)) {
                for (int i = 0; i < 10; i++) {
                    using (var item = reader.ReadEvent()) {
                        if (item == null) break;
                        var fact = new Dictionary<string, object>();
                        fact["id"] = item.Id;
                        fact["utc"] = item.TimeCreated.HasValue ? item.TimeCreated.Value.ToUniversalTime().ToString("o") : null;
                        var xml = new XmlDocument(); xml.XmlResolver = null; xml.LoadXml(item.ToXml());
                        var ns = new XmlNamespaceManager(xml.NameTable); ns.AddNamespace("e", "http://schemas.microsoft.com/win/2004/08/events/event");
                        foreach (XmlNode node in xml.SelectNodes("//e:EventData/e:Data", ns)) {
                            string name = node.Attributes["Name"].Value;
                            if (name != "Threat Name" && name != "Action Name") continue;
                            if (System.Text.RegularExpressions.Regex.IsMatch(node.InnerText, @"^[A-Za-z0-9:/._! -]{1,160}$"))
                                fact[name] = node.InnerText;
                        }
                        events.Add(fact);
                    }
                }
            }
            report["eventRead"] = "AVAILABLE";
        } catch { report["eventRead"] = "UNAVAILABLE"; }
        report["defenderEvents"] = events;
        return new JavaScriptSerializer().Serialize(report);
    }

    [STAThread]
    static int Main(string[] args) {
        if (args.Length == 1 && (args[0] == "--install-local" || args[0] == "--uninstall-local")) {
            try { if (args[0] == "--install-local") InstallLocal(); else UninstallLocal(); return 0; }
            catch { return 2; }
        }
        if (args.Length == 2 && args[0] == "--report") {
            try {
                if (!Path.IsPathRooted(args[1])) return 2;
                using (var f = new FileStream(args[1], FileMode.CreateNew, FileAccess.Write))
                using (var w = new StreamWriter(f)) w.Write(Collect());
                return 0;
            } catch { return 2; }
        }
        if (args.Length != 0) return 2;
        Application.EnableVisualStyles();
        var form = new Form { Text = "Agent Road — Diagnostics Preview", Size = new Size(820, 590), MinimumSize = new Size(650, 420), StartPosition = FormStartPosition.CenterScreen };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(20), RowCount = 4, ColumnCount = 1 };
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 65));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 45));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.Controls.Add(new Label { Text = "Agent Road Diagnostics", Font = new Font("Segoe UI", 20), AutoSize = true }, 0, 0);
        layout.Controls.Add(new Label { Text = "Local checks only. This preview does not pair devices or install remote access.\nUnsigned development build. No credentials or raw event command lines are collected.", Dock = DockStyle.Fill }, 0, 1);
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill };
        var check = new Button { Text = "Run local checks", AutoSize = true };
        var save = new Button { Text = "Save report", AutoSize = true, Enabled = false };
        var install = new Button { Text = "Install for me", AutoSize = true };
        var uninstall = new Button { Text = "Uninstall", AutoSize = true };
        buttons.Controls.Add(check); buttons.Controls.Add(save); buttons.Controls.Add(install); buttons.Controls.Add(uninstall); layout.Controls.Add(buttons, 0, 2);
        var output = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, Dock = DockStyle.Fill, Font = new Font("Consolas", 10), Text = "Ready. No checks have run." };
        layout.Controls.Add(output, 0, 3);
        check.Click += delegate { output.Text = Collect(); save.Enabled = true; };
        install.Click += delegate {
            if (MessageBox.Show(form, "Install this local diagnostics tool to:\n" + InstallRoot() + "\n\nNo remote access will be installed.", "Install diagnostics", MessageBoxButtons.OKCancel) != DialogResult.OK) return;
            try { InstallLocal(); MessageBox.Show(form, "Diagnostics installed. Location:\n" + InstallRoot()); }
            catch { MessageBox.Show(form, "Installation stopped. The target may already exist or be unwritable. Inspect it before retrying. No existing installation is overwritten."); }
        };
        uninstall.Click += delegate {
            if (MessageBox.Show(form, "Remove the installed diagnostics copy? Exported reports are kept. Close the installed copy first and use the original package for removal.", "Uninstall diagnostics", MessageBoxButtons.OKCancel) != DialogResult.OK) return;
            try { UninstallLocal(); MessageBox.Show(form, "Diagnostics uninstalled."); }
            catch { MessageBox.Show(form, "Removal stopped. Use the original package, close the installed copy and inspect for changed or extra files. Nothing is removed recursively."); }
        };
        save.Click += delegate {
            using (var dialog = new SaveFileDialog { Filter = "JSON report|*.json", FileName = "agent-road-diagnostics.json" }) {
                if (dialog.ShowDialog(form) != DialogResult.OK) return;
                try {
                    using (var f = new FileStream(dialog.FileName, FileMode.CreateNew, FileAccess.Write))
                    using (var w = new StreamWriter(f)) w.Write(output.Text);
                } catch { MessageBox.Show(form, "Report not saved. Choose a new writable filename."); }
            }
        };
        form.Controls.Add(layout); Application.Run(form); return 0;
    }
}
