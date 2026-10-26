// NetGuard.cs —— 网控助手（绿色免安装的 Windows 程序联网管理 / 误触弹窗补救工具）
// 构建：双击 build.bat（使用系统自带 .NET Framework 编译器，产物为单个 exe，无需安装任何运行库以外的组件）
// 依赖：Windows 10/11 自带 .NET Framework 4.x；需管理员权限运行（清单已声明）

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Diagnostics.Eventing.Reader;
using System.Reflection;
using Microsoft.Win32;

// 程序集信息（发布新版本时更新版本号，并同步 使用说明.md 的版本历史）
[assembly: AssemblyTitle("网控助手 (NetGuardAssistant)")]
[assembly: AssemblyDescription("程序联网权限管理 / 误触弹窗补救")]
[assembly: AssemblyVersion("1.1.1")]
[assembly: AssemblyInformationalVersion("1.1.1")]
[assembly: AssemblyFileVersion("1.1.1")]

namespace NetGuard
{
    internal static class Program
    {
        [STAThread]
        static void Main()
        {
            bool createdNew;
            using (Mutex mutex = new Mutex(true, "Local\\NetGuardAssistant_SingleInstance", out createdNew))
            {
                if (!createdNew)
                {
                    MessageBox.Show("网控助手已在运行中，请查看任务栏右下角托盘图标。", "网控助手",
                        MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.ThreadException += delegate(object s, System.Threading.ThreadExceptionEventArgs e)
                {
                    try { Store.Log("全局异常: " + e.Exception.Message); } catch { }
                };
                Application.Run(new MainForm());
            }
        }
    }

    // ---------------- 配置与日志 ----------------
    internal static class Store
    {
        static Dictionary<string, string> _set = new Dictionary<string, string>();

        static Store()
        {
            try
            {
                Dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "NetGuardAssistant");
                if (!Directory.Exists(Dir)) Directory.CreateDirectory(Dir);
            }
            catch { Dir = "."; }
            try
            {
                if (File.Exists(SettingsPath))
                {
                    foreach (string line in File.ReadAllLines(SettingsPath))
                    {
                        int i = line.IndexOf('=');
                        if (i > 0) _set[line.Substring(0, i).Trim()] = line.Substring(i + 1).Trim();
                    }
                }
            }
            catch { }
        }

        public static string Dir;
        public static string SettingsPath { get { return Path.Combine(Dir, "settings.txt"); } }
        public static string HistoryPath { get { return Path.Combine(Dir, "history.log"); } }

        public static string Get(string key, string def)
        {
            string v;
            return _set.TryGetValue(key, out v) ? v : def;
        }

        public static bool GetBool(string key, bool def)
        {
            string v;
            if (!_set.TryGetValue(key, out v)) return def;
            return v == "1" || v.Equals("true", StringComparison.OrdinalIgnoreCase);
        }

        public static void Set(string key, string value)
        {
            _set[key] = value;
            try
            {
                StringBuilder sb = new StringBuilder();
                foreach (KeyValuePair<string, string> kv in _set) sb.AppendLine(kv.Key + "=" + kv.Value);
                File.WriteAllText(SettingsPath, sb.ToString(), Encoding.UTF8);
            }
            catch { }
        }

        public static void SetBool(string key, bool value) { Set(key, value ? "1" : "0"); }

        public static void Log(string msg)
        {
            try
            {
                File.AppendAllText(HistoryPath, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + msg + Environment.NewLine, Encoding.UTF8);
            }
            catch { }
        }

        public static List<string> ReadHistory(int max)
        {
            List<string> all = new List<string>();
            try
            {
                if (File.Exists(HistoryPath)) all.AddRange(File.ReadAllLines(HistoryPath));
            }
            catch { }
            int start = Math.Max(0, all.Count - max);
            List<string> res = new List<string>();
            for (int i = all.Count - 1; i >= start; i--) res.Add(all[i]);
            return res;
        }
    }

    // ---------------- 防火墙操作 ----------------
    public class FwRuleInfo
    {
        public string Name = "";
        public string App = "";
        public int Direction;   // 1=入站 2=出站
        public int Action;      // 0=阻止 1=允许
        public int Profiles;    // 位掩码 1=域 2=专用 4=公用
        public bool Enabled;

        public string Key()
        {
            return Name + "|" + App + "|" + Direction + "|" + Action + "|" + Profiles + "|" + (Enabled ? "1" : "0");
        }
    }

    public class AppEntry
    {
        public string App = "";
        public string DisplayName = "";
        public List<FwRuleInfo> Rules = new List<FwRuleInfo>();
        public bool Managed;
        public int Mode;
        public int[,] Eff = new int[2, 3]; // [0=入站,1=出站][0=域,1=内网,2=公网] 0=阻止 1=允许 2=无专门规则
        public int[,] Def = new int[2, 3]; // 对应位置的系统默认动作 0=阻止 1=允许
    }

    public static class Firewall
    {
        public const int DirIn = 1, DirOut = 2;
        public const int ActBlock = 0, ActAllow = 1;
        public const int ProfDomain = 1, ProfPrivate = 2, ProfPublic = 4, ProfAll = 0x7FFFFFFF;
        public const string ManagedPrefix = "[网控助手]";

        static dynamic _policy;

        public static dynamic Policy
        {
            get
            {
                if (_policy == null)
                {
                    Type t = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                    if (t == null) throw new Exception("系统缺少 Windows 防火墙组件 (HNetCfg.FwPolicy2)。");
                    _policy = Activator.CreateInstance(t);
                }
                return _policy;
            }
        }

        // 枚举全部规则（后台线程调用：独立创建 COM 实例，避免跨线程）
        public static List<FwRuleInfo> GetAllRules()
        {
            List<FwRuleInfo> list = new List<FwRuleInfo>();
            Type t = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            dynamic pol = Activator.CreateInstance(t);
            foreach (dynamic r in pol.Rules)
            {
                try
                {
                    FwRuleInfo i = new FwRuleInfo();
                    i.Name = Convert.ToString(r.Name);
                    try { i.App = Convert.ToString(r.ApplicationName) ?? ""; } catch { i.App = ""; }
                    if (i.App != null && i.App.Length > 0) i.App = DevicePathToWin32(i.App);
                    i.Direction = (int)r.Direction;
                    i.Action = (int)r.Action;
                    i.Profiles = (int)r.Profiles;
                    i.Enabled = (bool)r.Enabled;
                    if (!string.IsNullOrEmpty(i.Name)) list.Add(i);
                }
                catch { }
            }
            return list;
        }

        static string ManagedRuleName(string app, string suffix)
        {
            string baseName = Path.GetFileNameWithoutExtension(app);
            string hash = app.ToLower().GetHashCode().ToString("X8");
            return ManagedPrefix + baseName + "-" + hash + " " + suffix;
        }

        public static string[] ManagedRuleNames(string app)
        {
            return new string[]
            {
                ManagedRuleName(app, "入站允许"),
                ManagedRuleName(app, "出站允许"),
                ManagedRuleName(app, "入站阻止"),
                ManagedRuleName(app, "出站阻止"),
            };
        }

        static bool RuleExists(dynamic pol, string name)
        {
            foreach (dynamic r in pol.Rules)
            {
                try { if (Convert.ToString(r.Name) == name) return true; } catch { }
            }
            return false;
        }

        static void EnsureRule(dynamic pol, string name, string app, int dir, int action)
        {
            if (RuleExists(pol, name)) return;
            Type rt = Type.GetTypeFromProgID("HNetCfg.FWRule");
            dynamic rule = Activator.CreateInstance(rt);
            rule.Name = name;
            rule.ApplicationName = app;
            rule.Protocol = 256; // 任意协议
            rule.Direction = dir;
            rule.Action = action;
            rule.Enabled = false;
            rule.Description = "由网控助手创建";
            pol.Rules.Add(rule);
        }

        // mode: 0=跟随系统 1=全部允许 2=仅内网(阻止公网) 3=全部阻止
        public static void SetMode(string app, int mode)
        {
            if (mode < 0 || mode > 3) throw new Exception("未知策略: " + mode);
            if (!File.Exists(app)) throw new Exception("找不到程序文件：" + app);
            string[] names = ManagedRuleNames(app);
            dynamic pol = Policy;
            EnsureRule(pol, names[0], app, DirIn, ActAllow);
            EnsureRule(pol, names[1], app, DirOut, ActAllow);
            EnsureRule(pol, names[2], app, DirIn, ActBlock);
            EnsureRule(pol, names[3], app, DirOut, ActBlock);

            List<dynamic> targets = new List<dynamic>();
            foreach (dynamic r in pol.Rules)
            {
                try
                {
                    string n = Convert.ToString(r.Name);
                    if (n == names[0] || n == names[1] || n == names[2] || n == names[3]) targets.Add(r);
                }
                catch { }
            }
            foreach (dynamic r in targets)
            {
                try
                {
                    string n = Convert.ToString(r.Name);
                    if (n == names[0] || n == names[1]) // 放行规则
                    {
                        if (mode == 1) { r.Enabled = true; r.Action = ActAllow; r.Profiles = ProfAll; }
                        else if (mode == 2) { r.Enabled = true; r.Action = ActAllow; r.Profiles = ProfDomain | ProfPrivate; }
                        else { r.Enabled = false; }
                    }
                    else // 阻止规则
                    {
                        if (mode == 3) { r.Enabled = true; r.Action = ActBlock; r.Profiles = ProfAll; }
                        else if (mode == 2) { r.Enabled = true; r.Action = ActBlock; r.Profiles = ProfPublic; }
                        else { r.Enabled = false; }
                    }
                }
                catch { }
            }
        }

        public static void RemoveManaged(string app)
        {
            string[] names = ManagedRuleNames(app);
            dynamic pol = Policy;
            foreach (string n in names)
            {
                try { pol.Rules.Remove(n); } catch { }
            }
        }

        // 清除本工具创建的全部规则（版本升级 / 重置时清理残留用）
        public static int RemoveAllManaged()
        {
            List<string> names = new List<string>();
            foreach (dynamic r in Policy.Rules)
            {
                try
                {
                    string nm = Convert.ToString(r.Name);
                    if (nm != null && nm.StartsWith(ManagedPrefix, StringComparison.Ordinal)) names.Add(nm);
                }
                catch { }
            }
            int count = 0;
            foreach (string nm in names)
            {
                try { Policy.Rules.Remove(nm); count++; } catch { }
            }
            return count;
        }

        // mode: 0=跟随系统 1=全部允许 2=仅内网 3=全部阻止
        public static string ModeName(int mode)
        {
            switch (mode)
            {
                case 1: return "全部允许";
                case 2: return "仅内网(阻止公网)";
                case 3: return "全部阻止";
                default: return "跟随系统";
            }
        }

        static int Effective(List<FwRuleInfo> rules, int dir, int prof)
        {
            bool anyAllow = false;
            foreach (FwRuleInfo r in rules)
            {
                if (!r.Enabled || r.Direction != dir) continue;
                bool covers = r.Profiles == 0 || (r.Profiles & prof) != 0;
                if (!covers) continue;
                if (r.Action == ActBlock) return 0; // 阻止规则优先
                anyAllow = true;
            }
            return anyAllow ? 1 : 2;
        }

        static int ComputeMode(AppEntry e)
        {
            FwRuleInfo inA = null, inB = null;
            foreach (FwRuleInfo r in e.Rules)
            {
                if (r.Name == null || !r.Name.StartsWith(ManagedPrefix, StringComparison.Ordinal)) continue;
                if (r.Direction == DirIn && r.Action == ActAllow) inA = r;
                else if (r.Direction == DirIn && r.Action == ActBlock) inB = r;
            }
            if (inA == null && inB == null) return 0;
            if (inB != null && inB.Enabled && inB.Profiles == ProfAll) return 3;
            if (inA != null && inA.Enabled)
            {
                if (inB != null && inB.Enabled && (inB.Profiles & ProfPublic) != 0) return 2;
                return 1;
            }
            return 0;
        }

        public static List<AppEntry> BuildAppList(List<FwRuleInfo> allRules)
        {
            Dictionary<string, AppEntry> map = new Dictionary<string, AppEntry>(StringComparer.OrdinalIgnoreCase);
            foreach (FwRuleInfo r in allRules)
            {
                if (string.IsNullOrEmpty(r.App)) continue;
                AppEntry e;
                if (!map.TryGetValue(r.App, out e))
                {
                    e = new AppEntry();
                    e.App = r.App;
                    e.DisplayName = Path.GetFileNameWithoutExtension(r.App);
                    map[r.App] = e;
                }
                e.Rules.Add(r);
                if (r.Name != null && r.Name.StartsWith(ManagedPrefix, StringComparison.Ordinal)) e.Managed = true;
            }
            List<AppEntry> list = new List<AppEntry>(map.Values);
            foreach (AppEntry e in list)
            {
                e.Mode = ComputeMode(e);
                int[] profs = new int[] { ProfDomain, ProfPrivate, ProfPublic };
                for (int d = 0; d < 2; d++)
                {
                    for (int p = 0; p < 3; p++)
                    {
                        e.Eff[d, p] = Effective(e.Rules, d == 0 ? DirIn : DirOut, profs[p]);
                        e.Def[d, p] = DefaultAction(profs[p], d == 0);
                    }
                }
            }
            list.Sort(delegate(AppEntry a, AppEntry b) { return string.Compare(a.DisplayName, b.DisplayName, true); });
            return list;
        }

        // 系统默认策略（无专门规则时生效）。实测 COM 返回整数：0=阻止 1=允许
        public static int DefaultAction(int profile, bool inbound)
        {
            try
            {
                dynamic pol = Policy;
                int v = inbound ? (int)pol.DefaultInboundAction[profile] : (int)pol.DefaultOutboundAction[profile];
                return v == 1 ? 1 : 0;
            }
            catch { return inbound ? 0 : 1; }
        }

        public static string EffText(int[,] eff, int[,] def, int d)
        {
            bool anyExplicit = false;
            for (int p = 0; p < 3; p++)
                if (eff[d, p] != 2) { anyExplicit = true; break; }
            if (!anyExplicit) return "系统默认";
            int dom = eff[d, 0] == 2 ? def[d, 0] : eff[d, 0];
            int pri = eff[d, 1] == 2 ? def[d, 1] : eff[d, 1];
            int pub = eff[d, 2] == 2 ? def[d, 2] : eff[d, 2];
            if (dom == 1 && pri == 1 && pub == 1) return "全部允许";
            if (dom == 0 && pri == 0 && pub == 0) return "全部阻止";
            if (dom == 1 && pri == 1 && pub == 0) return "仅内网允许";
            string[] pn = new string[] { "域", "内", "公" };
            int[] vs = new int[] { dom, pri, pub };
            StringBuilder sb = new StringBuilder();
            for (int p = 0; p < 3; p++)
                sb.Append(pn[p]).Append(vs[p] == 1 ? "✔" : "✘").Append(' ');
            return sb.ToString().TrimEnd();
        }

        // 系统"是否允许访问"弹窗开关（三网络类型）
        public static bool GetSysNotify()
        {
            try
            {
                dynamic pol = Policy;
                try { return !((bool)pol.NotificationsDisabled[4]); }
                catch { return !((bool)pol.get_NotificationsDisabled(4)); }
            }
            catch { return true; }
        }

        public static bool SetSysNotify(bool enable)
        {
            try
            {
                dynamic pol = Policy;
                int[] profiles = new int[] { ProfDomain, ProfPrivate, ProfPublic };
                foreach (int p in profiles)
                {
                    try { pol.NotificationsDisabled[p] = !enable; }
                    catch
                    {
                        try { pol.put_NotificationsDisabled(p, !enable); }
                        catch { pol.set_NotificationsDisabled(p, !enable); }
                    }
                }
                return true;
            }
            catch { return false; }
        }

        static Dictionary<string, string> _devCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        static object _devLock = new object();

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

        // 把 \Device\HarddiskVolumeX\... 形式路径转换成 C:\...
        public static string DevicePathToWin32(string path)
        {
            if (string.IsNullOrEmpty(path) || !path.StartsWith("\\Device\\", StringComparison.OrdinalIgnoreCase)) return path;
            string cached;
            lock (_devLock) { if (_devCache.TryGetValue(path, out cached)) return cached; }
            string result = path;
            for (char c = 'A'; c <= 'Z'; c++)
            {
                StringBuilder sb = new StringBuilder(1024);
                int n = QueryDosDevice(c + ":", sb, sb.Capacity);
                if (n > 0)
                {
                    string target = sb.ToString();
                    int z = target.IndexOf('\0');
                    if (z >= 0) target = target.Substring(0, z);
                    if (target.Length > 0 && path.StartsWith(target, StringComparison.OrdinalIgnoreCase))
                    {
                        result = c + ":" + path.Substring(target.Length);
                        break;
                    }
                }
            }
            lock (_devLock) { _devCache[path] = result; }
            return result;
        }
    }

    // ---------------- 防火墙事件日志 ----------------
    public class EventItem
    {
        public DateTime Time;
        public long RecordId;
        public int Id;
        public string Kind = "";
        public string App = "";
        public string Msg = "";
    }

    public static class FirewallEvents
    {
        static readonly Regex ExeRegex = new Regex(
            "[A-Za-z]:\\\\[^\r\n\t<>\"|*?]+?\\.exe|\\\\\\\\Device\\\\\\\\[^\r\n\t<>\"|*?]+?\\.exe",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        // 5031=入站被系统阻止；2097=添加了规则（系统弹窗点"允许"或"取消"都会产生，取消时创建的是
        // "Query User"阻止规则）；2006=删除了规则。事件属性[3]是干净的应用程序路径。
        public static List<EventItem> RecentBlocks(int secondsBack, int max)
        {
            List<EventItem> list = new List<EventItem>();
            try
            {
                string xpath = "*[System[(EventID=5031 or EventID=2097 or EventID=2006) and TimeCreated[timediff(@SystemTime) <= " + (secondsBack * 1000L) + "]]]";
                EventLogQuery q = new EventLogQuery("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
                    PathType.LogName, xpath);
                using (EventLogReader reader = new EventLogReader(q))
                {
                    for (;;)
                    {
                        EventRecord evt = reader.ReadEvent();
                        if (evt == null) break;
                        using (evt)
                        {
                            try
                            {
                                EventItem it = new EventItem();
                                it.Time = evt.TimeCreated ?? DateTime.Now;
                                it.RecordId = evt.RecordId ?? 0;
                                it.Id = evt.Id;
                                it.Kind = evt.Id == 5031 ? "入站被系统阻止"
                                    : (evt.Id == 2097 ? "新增防火墙规则" : "删除防火墙规则");
                                try { it.Msg = evt.FormatDescription() ?? ""; } catch { it.Msg = ""; }
                                it.App = ExtractAppPath(it.Msg, evt);
                                list.Add(it);
                            }
                            catch { }
                        }
                    }
                }
                if (list.Count > max)
                {
                    int skip = list.Count - max;
                    list = list.Skip(skip).ToList();
                }
                list.Reverse();
            }
            catch (Exception ex)
            {
                EventItem err = new EventItem();
                err.Time = DateTime.Now;
                err.Msg = "读取事件日志失败: " + ex.Message;
                list.Add(err);
            }
            return list;
        }

        // 从事件属性/消息中提取应用程序路径：逐个候选跑正则，取中即回，
        // 兼容"干净路径"字段和"UDP Query User{GUID}C:\...exe"这类复合字段
        public static string ExtractAppPath(string msg, EventRecord evt)
        {
            try
            {
                if (evt != null)
                {
                    foreach (object p in evt.Properties)
                    {
                        string s = Convert.ToString(p);
                        if (string.IsNullOrEmpty(s) || s.IndexOf(".exe", StringComparison.OrdinalIgnoreCase) < 0) continue;
                        Match m = ExeRegex.Match(s);
                        if (m.Success) return Firewall.DevicePathToWin32(m.Value);
                    }
                }
            }
            catch { }
            if (!string.IsNullOrEmpty(msg))
            {
                Match m = ExeRegex.Match(msg);
                if (m.Success) return Firewall.DevicePathToWin32(m.Value);
            }
            return "";
        }
    }

    // ---------------- 已安装软件枚举 ----------------
    public class InstalledApp
    {
        public string Name = "";
        public string Version = "";
        public string Publisher = "";
        public string Exe;
    }

    public static class InstalledApps
    {
        public static List<InstalledApp> GetAll()
        {
            List<InstalledApp> list = new List<InstalledApp>();
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            RegistryKey[] roots = new RegistryKey[] { Registry.LocalMachine, Registry.LocalMachine, Registry.CurrentUser };
            string[] paths = new string[]
            {
                @"Software\Microsoft\Windows\CurrentVersion\Uninstall",
                @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
                @"Software\Microsoft\Windows\CurrentVersion\Uninstall",
            };
            for (int i = 0; i < roots.Length; i++)
            {
                try
                {
                    using (RegistryKey root = roots[i].OpenSubKey(paths[i]))
                    {
                        if (root == null) continue;
                        foreach (string sub in root.GetSubKeyNames())
                        {
                            try
                            {
                                using (RegistryKey sk = root.OpenSubKey(sub))
                                {
                                    if (sk == null) continue;
                                    InstalledApp a = new InstalledApp();
                                    a.Name = Convert.ToString(sk.GetValue("DisplayName"));
                                    if (string.IsNullOrEmpty(a.Name)) continue;
                                    a.Version = Convert.ToString(sk.GetValue("DisplayVersion"));
                                    a.Publisher = Convert.ToString(sk.GetValue("Publisher"));
                                    a.Exe = ExeFromDisplayIcon(Convert.ToString(sk.GetValue("DisplayIcon")));
                                    string key = a.Name + "|" + (a.Exe == null ? "" : a.Exe.ToLower());
                                    if (seen.Contains(key)) continue;
                                    seen.Add(key);
                                    list.Add(a);
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch { }
            }
            list.Sort(delegate(InstalledApp a, InstalledApp b) { return string.Compare(a.Name, b.Name, true); });
            return list;
        }

        static string ExeFromDisplayIcon(string raw)
        {
            if (string.IsNullOrEmpty(raw)) return null;
            string s = Environment.ExpandEnvironmentVariables(raw.Trim());
            if (s.StartsWith("\""))
            {
                int q = s.IndexOf('"', 1);
                if (q > 0) s = s.Substring(1, q - 1);
            }
            else
            {
                int c = s.IndexOf(',');
                if (c >= 0) s = s.Substring(0, c);
            }
            s = s.Trim();
            if (s.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && File.Exists(s)) return s;
            return null;
        }
    }

    // ---------------- 实时弹窗 ----------------
    public class PopupItem
    {
        public string App;
        public int Kind; // 0=被系统阻止 1=刚被放行
        public PopupItem(string app, int kind) { App = app; Kind = kind; }
    }

    public class PopupForm : Form
    {
        public int Result = 0;   // 0=忽略 1=全部允许 2=仅内网 3=全部阻止
        public bool Auto;

        string _app;
        int _kind;
        int _autoAction;
        int _left = 30;
        Label _countLbl;
        ProgressBar _bar;
        System.Windows.Forms.Timer _timer;

        public PopupForm(string app, int kind)
        {
            _app = app;
            _kind = kind;
            _autoAction = ParseAutoAction();

            Font = MainForm.AppFont;
            Text = "网控助手 · 网络访问提醒";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MinimizeBox = false;
            MaximizeBox = false;
            ShowInTaskbar = true;
            StartPosition = FormStartPosition.Manual;
            int w = 500, h = 330;
            Size = new Size(w, h);
            Rectangle wa = Screen.PrimaryScreen.WorkingArea;
            Location = new Point(wa.Right - w - 20, wa.Bottom - h - 20);
            TopMost = true;
            Icon = SystemIcons.Shield;
            KeyPreview = true;
            KeyDown += delegate(object s, KeyEventArgs e)
            {
                if (e.KeyCode == Keys.Escape) { Result = 0; DialogResult = DialogResult.OK; Close(); }
            };

            PictureBox pic = new PictureBox();
            pic.Image = SystemIcons.Shield.ToBitmap();
            pic.SizeMode = PictureBoxSizeMode.CenterImage;
            pic.Location = new Point(16, 16);
            pic.Size = new Size(48, 48);
            Controls.Add(pic);

            Label title = new Label();
            title.Text = Path.GetFileName(app);
            title.Font = new Font(Font.FontFamily, 13F, FontStyle.Bold);
            title.AutoSize = true;
            title.Location = new Point(74, 18);
            Controls.Add(title);

            Label path = new Label();
            path.Text = app;
            path.ForeColor = Color.DimGray;
            path.AutoSize = true;
            path.MaximumSize = new Size(400, 0);
            path.Location = new Point(76, 48);
            Controls.Add(path);

            Label reason = new Label();
            reason.Text = _kind == 1
                ? "系统刚为该程序创建了防火墙规则（可能是你在系统弹窗点了“允许”或“取消”）。\n如非本意，请选择正确的策略："
                : "系统防火墙正在阻止该程序联网（可能是系统弹窗被误点了“取消”）。\n如需放行，请选择：";
            reason.AutoSize = true;
            reason.MaximumSize = new Size(450, 0);
            reason.Location = new Point(16, 92);
            Controls.Add(reason);

            _countLbl = new Label();
            _countLbl.AutoSize = true;
            _countLbl.ForeColor = Color.Firebrick;
            _countLbl.Location = new Point(16, 150);
            UpdateCountLabel();
            Controls.Add(_countLbl);

            _bar = new ProgressBar();
            _bar.Location = new Point(16, 176);
            _bar.Size = new Size(450, 14);
            _bar.Maximum = _left;
            Controls.Add(_bar);

            Button btnAllow = MakeButton("全部允许", 16, 1, Color.FromArgb(0, 128, 0));
            Button btnPriv = MakeButton("仅内网", 132, 2, Color.FromArgb(0, 80, 160));
            Button btnBlock = MakeButton("全部阻止", 248, 3, Color.FromArgb(170, 0, 0));
            Button btnIgnore = new Button();
            btnIgnore.Text = "忽略";
            btnIgnore.Size = new Size(92, 34);
            btnIgnore.Location = new Point(374, 208);
            btnIgnore.Click += delegate { Result = 0; DialogResult = DialogResult.OK; Close(); };
            Controls.Add(btnIgnore);

            Label tip = new Label();
            tip.Text = "提示：阻止规则优先于允许规则，选择后立即生效，可随时在主界面修改。";
            tip.ForeColor = Color.Gray;
            tip.AutoSize = true;
            tip.Location = new Point(16, 254);
            Controls.Add(tip);

            _timer = new System.Windows.Forms.Timer();
            _timer.Interval = 1000;
            _timer.Tick += delegate
            {
                _left--;
                if (_left <= 0)
                {
                    _timer.Stop();
                    Auto = true;
                    Result = _autoAction;
                    DialogResult = DialogResult.OK;
                    Close();
                    return;
                }
                UpdateCountLabel();
                _bar.Value = _left;
            };
        }

        Button MakeButton(string text, int x, int mode, Color color)
        {
            Button b = new Button();
            b.Text = text;
            b.Size = new Size(110, 34);
            b.Location = new Point(x, 208);
            b.ForeColor = color;
            b.Click += delegate { Result = mode; DialogResult = DialogResult.OK; Close(); };
            Controls.Add(b);
            return b;
        }

        int ParseAutoAction()
        {
            int v;
            if (!int.TryParse(Store.Get("autoaction", "0"), out v)) return 0;
            if (v == 2 || v == 3) return v;
            return 0;
        }

        void UpdateCountLabel()
        {
            string act = _autoAction == 0 ? "忽略" : Firewall.ModeName(_autoAction);
            _countLbl.Text = _left + " 秒后自动执行：" + act;
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            Activate();
            _timer.Start();
        }

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            _timer.Stop();
            _timer.Dispose();
            base.OnFormClosed(e);
        }
    }

    // ---------------- 策略设置对话框 ----------------
    public class PolicyDialog : Form
    {
        public int Mode = -1;
        public bool Clear;

        RadioButton rdoFollow, rdoAllow, rdoPrivate, rdoBlock;
        CheckBox chkClear;

        public PolicyDialog(string app, int currentMode, string effIn, string effOut, bool managed)
        {
            string modeText = currentMode >= 0 ? Firewall.ModeName(currentMode) : "未设置（跟随系统）";
            Font = MainForm.AppFont;
            Text = "设置网络策略";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MinimizeBox = false;
            MaximizeBox = false;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(560, 330);

            Label l1 = new Label();
            l1.Text = app;
            l1.AutoSize = true;
            l1.MaximumSize = new Size(520, 32);
            l1.Location = new Point(16, 14);
            Controls.Add(l1);

            Label l2 = new Label();
            l2.Text = "当前策略: " + modeText + "    入站: " + effIn + "    出站: " + effOut;
            l2.ForeColor = Color.DimGray;
            l2.AutoSize = true;
            l2.Location = new Point(16, 50);
            Controls.Add(l2);

            GroupBox g = new GroupBox();
            g.Text = "选择策略";
            g.Location = new Point(16, 80);
            g.Size = new Size(528, 140);
            Controls.Add(g);

            rdoFollow = AddRadio(g, "跟随系统默认（不干预，由系统弹窗和默认策略管理）", 26);
            rdoAllow = AddRadio(g, "全部允许（域 / 内网 / 公网全部放行）", 54);
            rdoPrivate = AddRadio(g, "仅内网（域 / 专用网络放行，公网一律阻止）", 82);
            rdoBlock = AddRadio(g, "全部阻止（完全禁止该程序联网）", 110);
            if (currentMode == 1) rdoAllow.Checked = true;
            else if (currentMode == 2) rdoPrivate.Checked = true;
            else if (currentMode == 3) rdoBlock.Checked = true;
            else rdoFollow.Checked = true;

            chkClear = new CheckBox();
            chkClear.Text = "同时清除本工具创建的规则";
            chkClear.AutoSize = true;
            chkClear.Location = new Point(16, 228);
            chkClear.Visible = managed;
            Controls.Add(chkClear);

            Label help = new Label();
            help.Text = "说明：阻止规则优先级高于允许规则；“仅内网”会在公网创建阻止规则覆盖其他放行规则。";
            help.ForeColor = Color.Gray;
            help.AutoSize = true;
            help.Location = new Point(16, 262);
            Controls.Add(help);

            Button ok = new Button();
            ok.Text = "确定";
            ok.Size = new Size(88, 28);
            ok.Location = new Point(360, 292);
            ok.Click += delegate
            {
                if (chkClear.Checked) { Clear = true; DialogResult = DialogResult.OK; Close(); return; }
                if (rdoFollow.Checked) Mode = 0;
                else if (rdoAllow.Checked) Mode = 1;
                else if (rdoPrivate.Checked) Mode = 2;
                else if (rdoBlock.Checked) Mode = 3;
                DialogResult = DialogResult.OK;
                Close();
            };
            Controls.Add(ok);

            Button cancel = new Button();
            cancel.Text = "取消";
            cancel.Size = new Size(88, 28);
            cancel.Location = new Point(456, 292);
            cancel.DialogResult = DialogResult.Cancel;
            Controls.Add(cancel);

            AcceptButton = ok;
            CancelButton = cancel;
        }

        RadioButton AddRadio(GroupBox g, string text, int y)
        {
            RadioButton r = new RadioButton();
            r.Text = text;
            r.AutoSize = true;
            r.Location = new Point(14, y);
            g.Controls.Add(r);
            return r;
        }
    }

    // ---------------- 主窗口 ----------------
    public class MainForm : Form
    {
        public static Font AppFont = new Font("Microsoft YaHei UI", 9F);

        TabControl tabs;
        ListView lvApps, lvInstalled, lvEvents, lvHistory;
        TextBox txtSearch;
        CheckBox chkPause, chkMonitor, chkAutostart, chkSysNotify, chkStartMin;
        ComboBox cmbAutoAction;
        RadioButton rdoFollow, rdoAllow, rdoPrivate, rdoBlock;
        Label lblSelPath;
        ToolStripStatusLabel statusLbl, statusMon;
        NotifyIcon tray;
        ContextMenuStrip trayMenu;
        System.Windows.Forms.Timer monTimer;

        bool _busy, _popupShowing, _exiting, _balloonShown, _initDone, _warmedUp;
        List<FwRuleInfo> _lastRules;
        List<AppEntry> _appsCache = new List<AppEntry>();
        Dictionary<string, FwRuleInfo> _oldSnapshot;
        HashSet<long> _processedRecords = new HashSet<long>();
        Dictionary<string, DateTime> _lastPrompt = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        Queue<PopupItem> _popupQueue = new Queue<PopupItem>();
        int _lastFp;

        public MainForm()
        {
            Font = AppFont;
            Text = "网控助手 v" + Application.ProductVersion + " — 程序联网权限管理";
            Icon = SystemIcons.Shield;
            Size = new Size(1000, 660);
            MinimumSize = new Size(860, 560);
            StartPosition = FormStartPosition.CenterScreen;
            AutoScaleMode = AutoScaleMode.Dpi;

            BuildUi();
            BuildTray();

            monTimer = new System.Windows.Forms.Timer();
            monTimer.Interval = 4000;
            monTimer.Tick += MonTimer_Tick;
            monTimer.Start();

            Load += delegate { OnFirstLoad(); };
            Shown += delegate { Warmup(); };
        }

        // ================= UI 构建 =================
        void BuildUi()
        {
            tabs = new TabControl();
            tabs.Dock = DockStyle.Fill;

            // ---- Tab1 程序网络权限 ----
            TabPage tab1 = new TabPage("程序网络权限");
            lvApps = NewListView(new object[] { "程序名", 170 }, new object[] { "我的策略", 130 },
                new object[] { "入站", 130 }, new object[] { "出站", 130 }, new object[] { "路径", 400 });
            lvApps.ContextMenuStrip = BuildAppMenu();
            lvApps.DoubleClick += delegate { ShowSelectedPolicyDialog(); };
            lvApps.SelectedIndexChanged += delegate { UpdateSelPanel(); };

            Panel tab1Top = new Panel();
            tab1Top.Dock = DockStyle.Top;
            tab1Top.Height = 44;

            Button btnAdd = new Button();
            btnAdd.Text = "添加程序…";
            btnAdd.Size = new Size(96, 27);
            btnAdd.Location = new Point(10, 9);
            btnAdd.Click += delegate { AddProgram(); };
            tab1Top.Controls.Add(btnAdd);

            Button btnRefresh = new Button();
            btnRefresh.Text = "刷新";
            btnRefresh.Size = new Size(70, 27);
            btnRefresh.Location = new Point(112, 9);
            btnRefresh.Click += delegate { RefreshNow(); };
            tab1Top.Controls.Add(btnRefresh);

            txtSearch = new TextBox();
            txtSearch.Size = new Size(190, 25);
            txtSearch.Location = new Point(560, 10);
            txtSearch.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            txtSearch.TextChanged += delegate { if (_lastRules != null) RefreshAppList(_lastRules); };
            tab1Top.Controls.Add(txtSearch);

            chkPause = new CheckBox();
            chkPause.Text = "暂停监控";
            chkPause.AutoSize = true;
            chkPause.Location = new Point(760, 12);
            chkPause.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            chkPause.CheckedChanged += delegate { Store.SetBool("monitor", !chkPause.Checked); UpdateMonitorLabel(); };
            tab1Top.Controls.Add(chkPause);

            Panel tab1Bottom = new Panel();
            tab1Bottom.Dock = DockStyle.Bottom;
            tab1Bottom.Height = 92;

            lblSelPath = new Label();
            lblSelPath.Text = "（未选中程序 — 双击列表中的程序可设置策略）";
            lblSelPath.ForeColor = Color.DimGray;
            lblSelPath.AutoSize = true;
            lblSelPath.Location = new Point(12, 8);
            tab1Bottom.Controls.Add(lblSelPath);

            rdoFollow = new RadioButton();
            rdoFollow.Text = "跟随系统";
            rdoFollow.AutoSize = true;
            rdoFollow.Location = new Point(12, 36);
            tab1Bottom.Controls.Add(rdoFollow);
            rdoAllow = new RadioButton();
            rdoAllow.Text = "全部允许";
            rdoAllow.AutoSize = true;
            rdoAllow.Location = new Point(112, 36);
            tab1Bottom.Controls.Add(rdoAllow);
            rdoPrivate = new RadioButton();
            rdoPrivate.Text = "仅内网(阻止公网)";
            rdoPrivate.AutoSize = true;
            rdoPrivate.Location = new Point(222, 36);
            tab1Bottom.Controls.Add(rdoPrivate);
            rdoBlock = new RadioButton();
            rdoBlock.Text = "全部阻止";
            rdoBlock.AutoSize = true;
            rdoBlock.Location = new Point(380, 36);
            tab1Bottom.Controls.Add(rdoBlock);

            Button btnApply = new Button();
            btnApply.Text = "应用";
            btnApply.Size = new Size(70, 26);
            btnApply.Location = new Point(490, 33);
            btnApply.Click += delegate { ApplySelectedModeFromPanel(); };
            tab1Bottom.Controls.Add(btnApply);

            Button btnClear = new Button();
            btnClear.Text = "清除我的规则";
            btnClear.Size = new Size(110, 26);
            btnClear.Location = new Point(570, 33);
            btnClear.Click += delegate { ClearSelectedRules(); };
            tab1Bottom.Controls.Add(btnClear);

            Button btnFolder = new Button();
            btnFolder.Text = "打开所在文件夹";
            btnFolder.Size = new Size(120, 26);
            btnFolder.Location = new Point(690, 33);
            btnFolder.Click += delegate { OpenSelectedFolder(); };
            tab1Bottom.Controls.Add(btnFolder);

            tab1.Controls.Add(lvApps);
            tab1.Controls.Add(tab1Bottom);
            tab1.Controls.Add(tab1Top);
            tabs.TabPages.Add(tab1);

            // ---- Tab2 已安装软件 ----
            TabPage tab2 = new TabPage("已安装软件");
            lvInstalled = NewListView(new object[] { "名称", 240 }, new object[] { "版本", 110 },
                new object[] { "发布者", 170 }, new object[] { "主程序", 440 });
            lvInstalled.ContextMenuStrip = BuildInstalledMenu();
            lvInstalled.DoubleClick += delegate { SetInstalledPolicy(); };

            Panel tab2Top = new Panel();
            tab2Top.Dock = DockStyle.Top;
            tab2Top.Height = 44;
            Button btnRefInst = new Button();
            btnRefInst.Text = "刷新列表";
            btnRefInst.Size = new Size(90, 27);
            btnRefInst.Location = new Point(10, 9);
            btnRefInst.Click += delegate { RefreshInstalled(); };
            tab2Top.Controls.Add(btnRefInst);
            Label hintInst = new Label();
            hintInst.Text = "来自系统“已安装程序”注册表；双击可设置其网络策略（需能定位到主程序 exe）";
            hintInst.ForeColor = Color.DimGray;
            hintInst.AutoSize = true;
            hintInst.Location = new Point(110, 15);
            tab2Top.Controls.Add(hintInst);

            tab2.Controls.Add(lvInstalled);
            tab2.Controls.Add(tab2Top);
            tabs.TabPages.Add(tab2);

            // ---- Tab3 网络事件与历史 ----
            TabPage tab3 = new TabPage("网络事件与历史");
            lvEvents = NewListView(new object[] { "时间", 140 }, new object[] { "事件", 190 },
                new object[] { "程序", 290 }, new object[] { "详情", 430 });
            lvHistory = NewListView(new object[] { "时间", 140 }, new object[] { "本工具操作记录", 900 });

            SplitContainer sc = new SplitContainer();
            sc.Dock = DockStyle.Fill;
            sc.Orientation = Orientation.Horizontal;
            sc.Panel1.Controls.Add(lvEvents);
            sc.Panel2.Controls.Add(lvHistory);

            Panel tab3Top = new Panel();
            tab3Top.Dock = DockStyle.Top;
            tab3Top.Height = 44;
            Button btnRefEv = new Button();
            btnRefEv.Text = "刷新";
            btnRefEv.Size = new Size(70, 27);
            btnRefEv.Location = new Point(10, 9);
            btnRefEv.Click += delegate { RefreshEvents(); };
            tab3Top.Controls.Add(btnRefEv);
            Button btnLog = new Button();
            btnLog.Text = "打开数据文件夹";
            btnLog.Size = new Size(120, 27);
            btnLog.Location = new Point(86, 9);
            btnLog.Click += delegate { try { Process.Start(Store.Dir); } catch { } };
            tab3Top.Controls.Add(btnLog);
            Label hintEv = new Label();
            hintEv.Text = "上：系统防火墙事件（近7天：阻止入站/新增规则/删除规则）；下：本工具的操作记录";
            hintEv.ForeColor = Color.DimGray;
            hintEv.AutoSize = true;
            hintEv.Location = new Point(216, 15);
            tab3Top.Controls.Add(hintEv);

            tab3.Controls.Add(sc);
            tab3.Controls.Add(tab3Top);
            tabs.TabPages.Add(tab3);

            // ---- Tab4 设置 ----
            TabPage tab4 = new TabPage("设置与说明");
            Panel setPanel = new Panel();
            setPanel.Dock = DockStyle.Fill;
            setPanel.AutoScroll = true;

            chkMonitor = new CheckBox();
            chkMonitor.Text = "实时监控并在发现新程序联网/被阻止时弹窗提醒";
            chkMonitor.AutoSize = true;
            chkMonitor.Location = new Point(16, 16);
            chkMonitor.CheckedChanged += delegate
            {
                Store.SetBool("monitor", chkMonitor.Checked);
                chkPause.Checked = !chkMonitor.Checked;
                UpdateMonitorLabel();
            };
            setPanel.Controls.Add(chkMonitor);

            Label lblAuto = new Label();
            lblAuto.Text = "弹窗超时(30秒)后自动执行：";
            lblAuto.AutoSize = true;
            lblAuto.Location = new Point(16, 48);
            setPanel.Controls.Add(lblAuto);

            cmbAutoAction = new ComboBox();
            cmbAutoAction.DropDownStyle = ComboBoxStyle.DropDownList;
            cmbAutoAction.Items.Add("忽略（保持现状）");
            cmbAutoAction.Items.Add("设为仅内网");
            cmbAutoAction.Items.Add("设为全部阻止");
            cmbAutoAction.Location = new Point(200, 45);
            cmbAutoAction.Width = 160;
            cmbAutoAction.SelectedIndexChanged += delegate
            {
                int[] map = new int[] { 0, 2, 3 };
                Store.Set("autoaction", map[cmbAutoAction.SelectedIndex].ToString());
            };
            setPanel.Controls.Add(cmbAutoAction);

            chkSysNotify = new CheckBox();
            chkSysNotify.Text = "保留系统防火墙“是否允许访问”弹窗（关闭后只由本工具弹窗提醒）";
            chkSysNotify.AutoSize = true;
            chkSysNotify.Location = new Point(16, 80);
            chkSysNotify.CheckedChanged += delegate
            {
                if (!_initDone) return; // 初始化赋值时跳过，避免每次启动都重写系统弹窗设置
                bool ok = Firewall.SetSysNotify(chkSysNotify.Checked);
                Store.SetBool("sysnotify", chkSysNotify.Checked);
                if (!ok) MessageBox.Show(this, "修改系统弹窗设置失败（不影响本工具的其他功能）。", "网控助手",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
            };
            setPanel.Controls.Add(chkSysNotify);

            chkAutostart = new CheckBox();
            chkAutostart.Text = "开机自动启动（计划任务方式，静默提权不弹UAC）";
            chkAutostart.AutoSize = true;
            chkAutostart.Location = new Point(16, 112);
            chkAutostart.CheckedChanged += delegate { if (_initDone) SetAutostart(chkAutostart.Checked); };
            setPanel.Controls.Add(chkAutostart);

            chkStartMin = new CheckBox();
            chkStartMin.Text = "启动时最小化到托盘";
            chkStartMin.AutoSize = true;
            chkStartMin.Location = new Point(16, 144);
            chkStartMin.CheckedChanged += delegate { Store.SetBool("startmin", chkStartMin.Checked); };
            setPanel.Controls.Add(chkStartMin);

            Button btnClearAllRules = new Button();
            btnClearAllRules.Text = "清除本工具创建的全部防火墙规则（重置 / 清残留用，不影响系统规则）";
            btnClearAllRules.AutoSize = true;
            btnClearAllRules.Location = new Point(16, 178);
            btnClearAllRules.Click += delegate
            {
                if (MessageBox.Show(this, "将删除本工具创建的所有防火墙规则（不影响系统或其他软件创建的规则）。\n确定继续？",
                    "网控助手", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
                try
                {
                    _lastPrompt.Clear();
                    _popupQueue.Clear();
                    int n = Firewall.RemoveAllManaged();
                    Store.Log("清除全部托管规则: " + n + " 条");
                    MessageBox.Show(this, "已清除 " + n + " 条规则。", "网控助手");
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, "清除失败: " + ex.Message, "网控助手", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
                RefreshNow();
            };
            setPanel.Controls.Add(btnClearAllRules);

            TextBox help = new TextBox();
            help.Multiline = true;
            help.ReadOnly = true;
            help.ScrollBars = ScrollBars.Vertical;
            help.BackColor = SystemColors.Window;
            help.Location = new Point(16, 214);
            help.Size = new Size(940, 370);
            help.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            help.Text =
                "【版本】v" + Application.ProductVersion + "\r\n\r\n" +
                "【这是什么】\r\n" +
                "一个绿色免安装的 Windows 程序联网管理工具：集中管理每个软件的 内网/公网/阻止 联网权限，\r\n" +
                "并在系统防火墙弹窗（“是否允许此应用访问网络”）被误点后，提供一键补救和实时二次提醒。\r\n\r\n" +
                "【三种策略的含义】\r\n" +
                "· 全部允许 = 创建放行规则（域/专用/公用全部放行）\r\n" +
                "· 仅内网  = 域/专用网络放行，公用网络一律阻止（阻止规则优先级高于放行规则）\r\n" +
                "· 全部阻止 = 创建阻止规则，完全禁止联网\r\n" +
                "· 跟随系统 = 本工具不干预，由系统默认策略和系统弹窗决定\r\n\r\n" +
                "【误触系统弹窗后怎么办】\r\n" +
                "· 误点了“允许”：打开本工具 → “程序网络权限” → 找到该程序 → 改为“仅内网”或“全部阻止”。\r\n" +
                "  阻止规则会覆盖系统刚创建的放行规则，无需手动删除系统规则。\r\n" +
                "· 误点了“取消”：程序会被系统静默阻止；本工具监测到阻止事件后会自动弹窗，\r\n" +
                "  点“仅内网/全部允许”即可放行；也可以在列表中手动设置。\r\n\r\n" +
                "【实时弹窗】\r\n" +
                "工具后台监视防火墙规则变化与事件日志：发现新程序联网、或系统刚为其创建规则（系统弹窗\r\n" +
                "点“允许”或“取消”都会产生）、或程序被阻止时，自动弹出提醒；30 秒无操作按“设置”中的\r\n" +
                "默认动作处理（默认忽略）。同一程序 10 分钟内只提醒一次。\r\n\r\n" +
                "【权限与数据】\r\n" +
                "· 修改防火墙规则需要管理员权限，本程序启动时会弹出 UAC 确认框（属正常现象）。\r\n" +
                "· 列表中的 ✔/✘ 表示对应网络类型的放行/阻止，“–”表示无专门规则（入站默认阻止、出站默认允许）。\r\n" +
                "· 配置与日志保存在: " + Store.Dir + "\r\n" +
                "· 卸载：直接删除 exe；如开启过自启请先在“设置”中取消勾选。\r\n";
            setPanel.Controls.Add(help);

            tab4.Controls.Add(setPanel);
            tabs.TabPages.Add(tab4);

            Controls.Add(tabs);

            StatusStrip status = new StatusStrip();
            statusLbl = new ToolStripStatusLabel("正在初始化…");
            statusMon = new ToolStripStatusLabel("监控: 开");
            status.Items.Add(statusLbl);
            status.Items.Add(new ToolStripStatusLabel("    "));
            status.Items.Add(statusMon);
            Controls.Add(status);

            tabs.SelectedIndexChanged += delegate
            {
                if (tabs.SelectedIndex == 1 && lvInstalled.Items.Count == 0) RefreshInstalled();
                if (tabs.SelectedIndex == 2 && lvEvents.Items.Count == 0) RefreshEvents();
            };
        }

        ListView NewListView(params object[][] cols)
        {
            ListView lv = new ListView();
            lv.View = View.Details;
            lv.FullRowSelect = true;
            lv.HideSelection = false;
            lv.MultiSelect = false;
            lv.Dock = DockStyle.Fill;
            foreach (object[] c in cols)
            {
                lv.Columns.Add(Convert.ToString(c[0]), Convert.ToInt32(c[1]));
            }
            return lv;
        }

        ContextMenuStrip BuildAppMenu()
        {
            ContextMenuStrip menu = new ContextMenuStrip();
            menu.Items.Add("设置策略…", null, delegate { ShowSelectedPolicyDialog(); });
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("全部允许", null, delegate { ApplyQuick(1); });
            menu.Items.Add("仅内网(阻止公网)", null, delegate { ApplyQuick(2); });
            menu.Items.Add("全部阻止", null, delegate { ApplyQuick(3); });
            menu.Items.Add("跟随系统(清除干预)", null, delegate { ApplyQuick(0); });
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("打开程序所在文件夹", null, delegate { OpenSelectedFolder(); });
            menu.Items.Add("复制程序路径", null, delegate
            {
                AppEntry e = SelectedApp();
                if (e != null) try { Clipboard.SetText(e.App); } catch { }
            });
            return menu;
        }

        ContextMenuStrip BuildInstalledMenu()
        {
            ContextMenuStrip menu = new ContextMenuStrip();
            menu.Items.Add("设置网络策略…", null, delegate { SetInstalledPolicy(); });
            menu.Items.Add("打开主程序文件夹", null, delegate
            {
                InstalledApp a = SelectedInstalled();
                if (a != null && a.Exe != null)
                    try { Process.Start("explorer.exe", "/select,\"" + a.Exe + "\""); } catch { }
            });
            return menu;
        }

        void BuildTray()
        {
            tray = new NotifyIcon();
            tray.Icon = SystemIcons.Shield;
            tray.Text = "网控助手 — 程序联网监控中";
            tray.Visible = true;
            trayMenu = new ContextMenuStrip();
            trayMenu.Items.Add("打开主窗口", null, delegate { ShowMain(); });
            trayMenu.Items.Add("暂停监控", null, delegate
            {
                bool nowOn = Store.GetBool("monitor", true);
                Store.SetBool("monitor", !nowOn);
                SyncMonitorUi();
            });
            trayMenu.Items.Add(new ToolStripSeparator());
            trayMenu.Items.Add("退出", null, delegate { _exiting = true; tray.Visible = false; Application.Exit(); });
            tray.ContextMenuStrip = trayMenu;
            tray.DoubleClick += delegate { ShowMain(); };
        }

        void ShowMain()
        {
            Show();
            WindowState = FormWindowState.Normal;
            Activate();
        }

        // ================= 启动 =================
        void OnFirstLoad()
        {
            chkMonitor.Checked = Store.GetBool("monitor", true);
            chkPause.Checked = !chkMonitor.Checked;
            int aa;
            if (!int.TryParse(Store.Get("autoaction", "0"), out aa)) aa = 0;
            cmbAutoAction.SelectedIndex = aa == 2 ? 1 : (aa == 3 ? 2 : 0);
            chkSysNotify.Checked = Firewall.GetSysNotify();
            chkAutostart.Checked = GetAutostart();
            chkStartMin.Checked = Store.GetBool("startmin", false);
            _initDone = true;
            UpdateMonitorLabel();

            if (chkStartMin.Checked)
            {
                BeginInvoke(new Action(delegate
                {
                    Hide();
                    if (!_balloonShown)
                    {
                        _balloonShown = true;
                        tray.BalloonTipTitle = "网控助手";
                        tray.BalloonTipText = "已在后台监控程序联网。双击托盘图标打开主界面。";
                        tray.ShowBalloonTip(3000);
                    }
                }));
            }
        }

        async void Warmup()
        {
            if (_warmedUp) return;
            _warmedUp = true;
            _busy = true; // 与首个监控周期互斥，避免初始化期间重复快照
            try
            {
                List<FwRuleInfo> rules = await Task.Run(() => Firewall.GetAllRules());
                _oldSnapshot = BuildSnapshot(rules);
                _lastRules = rules;
                List<EventItem> evs = await Task.Run(() => FirewallEvents.RecentBlocks(600, 100));
                foreach (EventItem ev in evs)
                {
                    if (ev.RecordId == 0) continue;
                    // 刚发生（2分钟内）的阻止/新增规则事件不标记为已处理——
                    // 可能是用户启动本工具前刚误触了系统弹窗，交给监控流程立即弹窗补救
                    if ((ev.Id == 5031 || ev.Id == 2097) && IsPromptable(ev.App)
                        && (DateTime.Now - ev.Time).TotalMinutes <= 2) continue;
                    _processedRecords.Add(ev.RecordId);
                }
                RefreshAppList(rules);
            }
            catch (Exception ex)
            {
                statusLbl.Text = "初始化失败: " + ex.Message;
                Store.Log("初始化失败: " + ex.Message);
            }
            finally { _busy = false; }
        }

        // ================= 监控 =================
        async void MonTimer_Tick(object sender, EventArgs e)
        {
            if (_busy || !Store.GetBool("monitor", true)) return;
            _busy = true;
            try
            {
                List<FwRuleInfo> rules = await Task.Run(() => Firewall.GetAllRules());

                Dictionary<string, FwRuleInfo> snap = BuildSnapshot(rules);
                if (_oldSnapshot != null)
                {
                    foreach (KeyValuePair<string, FwRuleInfo> kv in snap)
                    {
                        FwRuleInfo r = kv.Value;
                        if (r.Action != Firewall.ActAllow || !r.Enabled) continue;
                        FwRuleInfo old;
                        if (_oldSnapshot.TryGetValue(kv.Key, out old) && old.Enabled) continue;
                        // 只提醒“新出现的放行规则”或“禁用规则被启用”，规则其他属性变化不打扰
                        if (IsPromptable(r.App))
                            EnqueuePopup(r.App, 1);
                    }
                }
                _oldSnapshot = snap;
                _lastRules = rules;

                List<EventItem> evs = await Task.Run(() => FirewallEvents.RecentBlocks(240, 80));
                foreach (EventItem ev in evs)
                {
                    long rid = ev.RecordId;
                    if (rid == 0 || _processedRecords.Contains(rid)) continue;
                    _processedRecords.Add(rid);
                    if (_processedRecords.Count > 5000) _processedRecords.Clear();
                    if (string.IsNullOrEmpty(ev.App) || !IsPromptable(ev.App)) continue;
                    if ((DateTime.Now - ev.Time).TotalMinutes > 2) continue;
                    if (ev.Id == 5031) EnqueuePopup(ev.App, 0);          // 入站被阻止（误点"取消"）
                    else if (ev.Id == 2097) EnqueuePopup(ev.App, 1);     // 新增规则（误点"允许"或"取消"都会产生）
                }

                int fp = 0;
                foreach (FwRuleInfo r in rules) fp = fp * 31 + r.Key().GetHashCode();
                if (fp != _lastFp)
                {
                    _lastFp = fp;
                    if (Visible) RefreshAppList(rules);
                }
            }
            catch (Exception ex)
            {
                statusLbl.Text = "监控异常: " + ex.Message;
            }
            finally { _busy = false; }
            PumpQueue();
        }

        Dictionary<string, FwRuleInfo> BuildSnapshot(List<FwRuleInfo> rules)
        {
            Dictionary<string, FwRuleInfo> snap = new Dictionary<string, FwRuleInfo>();
            foreach (FwRuleInfo r in rules)
            {
                if (string.IsNullOrEmpty(r.App)) continue;
                if (r.Name != null && r.Name.StartsWith(Firewall.ManagedPrefix, StringComparison.Ordinal)) continue;
                if (!IsPromptable(r.App)) continue;
                snap[r.Name + "|" + r.App + "|" + r.Direction] = r;
            }
            return snap;
        }

        bool IsPromptable(string app)
        {
            if (string.IsNullOrEmpty(app)) return false;
            if (!app.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return false;
            if (string.Equals(app, Application.ExecutablePath, StringComparison.OrdinalIgnoreCase)) return false;
            string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (app.StartsWith(winDir, StringComparison.OrdinalIgnoreCase)) return false;
            return true;
        }

        void EnqueuePopup(string app, int kind)
        {
            AppendKnownApp(app);
            DateTime last;
            if (_lastPrompt.TryGetValue(app, out last) && (DateTime.Now - last).TotalMinutes < 10) return;
            if (_lastPrompt.Count > 200) _lastPrompt.Clear();
            _lastPrompt[app] = DateTime.Now;
            if (_popupQueue.Count > 25) _popupQueue.Dequeue();
            _popupQueue.Enqueue(new PopupItem(app, kind));
            PumpQueue();
        }

        void PumpQueue()
        {
            if (_popupShowing || !Store.GetBool("monitor", true)) return;
            if (_popupQueue.Count == 0) return;
            PopupItem item = _popupQueue.Dequeue();
            _popupShowing = true;
            try
            {
                Store.Log("弹窗提醒: " + (item.Kind == 1 ? "刚被放行 " : "被系统阻止 ") + item.App);
                using (PopupForm pf = new PopupForm(item.App, item.Kind))
                {
                    pf.ShowDialog(Visible ? (IWin32Window)this : null);
                    if (pf.Result >= 1) SetModeLogged(item.App, pf.Result);
                    else Store.Log((pf.Auto ? "弹窗超时自动忽略" : "弹窗忽略") + ": " + item.App);
                }
                RefreshNow();
            }
            catch (Exception ex)
            {
                Store.Log("弹窗处理异常: " + ex.Message);
            }
            finally { _popupShowing = false; }
            if (_popupQueue.Count > 0) BeginInvoke(new Action(PumpQueue));
        }

        void AppendKnownApp(string app)
        {
            try
            {
                if (string.IsNullOrEmpty(app) || !app.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return;
                string cur = Store.Get("knownapps", "");
                List<string> list = new List<string>(cur.Split(new char[] { ';' }, StringSplitOptions.RemoveEmptyEntries));
                string lower = app.ToLower();
                foreach (string s in list)
                    if (s.Trim().ToLower() == lower) return;
                list.Add(app);
                if (list.Count > 300) list.RemoveRange(0, list.Count - 300);
                Store.Set("knownapps", string.Join(";", list));
            }
            catch { }
        }

        // ================= 列表刷新 =================
        async void RefreshNow()
        {
            try
            {
                List<FwRuleInfo> rules = await Task.Run(() => Firewall.GetAllRules());
                _oldSnapshot = BuildSnapshot(rules);
                _lastRules = rules;
                int fp = 0;
                foreach (FwRuleInfo r in rules) fp = fp * 31 + r.Key().GetHashCode();
                _lastFp = fp;
                RefreshAppList(rules);
            }
            catch (Exception ex)
            {
                statusLbl.Text = "刷新失败: " + ex.Message;
            }
        }

        void RefreshAppList(List<FwRuleInfo> rules)
        {
            string selPath = null;
            AppEntry sel = SelectedApp();
            if (sel != null) selPath = sel.App;

            List<AppEntry> apps = Firewall.BuildAppList(rules);
            Dictionary<string, AppEntry> map = new Dictionary<string, AppEntry>(StringComparer.OrdinalIgnoreCase);
            foreach (AppEntry e in apps) map[e.App] = e;

            string known = Store.Get("knownapps", "");
            string[] knownArr = known.Split(new char[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string k in knownArr)
            {
                string p = k.Trim();
                if (p.Length == 0 || map.ContainsKey(p)) continue;
                if (!File.Exists(p)) continue;
                AppEntry e = new AppEntry();
                e.App = p;
                e.DisplayName = Path.GetFileNameWithoutExtension(p);
                apps.Add(e);
                map[p] = e;
            }
            apps.Sort(delegate(AppEntry a, AppEntry b) { return string.Compare(a.DisplayName, b.DisplayName, true); });
            _appsCache = apps;

            string filter = txtSearch.Text.Trim();
            lvApps.BeginUpdate();
            lvApps.Items.Clear();
            foreach (AppEntry e in apps)
            {
                if (filter.Length > 0
                    && e.DisplayName.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0
                    && e.App.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0) continue;

                ListViewItem it = new ListViewItem(e.DisplayName);
                it.SubItems.Add(e.Managed ? Firewall.ModeName(e.Mode) : "未设置");
                it.SubItems.Add(Firewall.EffText(e.Eff, e.Def, 0));
                it.SubItems.Add(Firewall.EffText(e.Eff, e.Def, 1));
                it.SubItems.Add(e.App);
                it.Tag = e;
                it.UseItemStyleForSubItems = false;
                if (e.Managed)
                {
                    if (e.Mode == 3) it.SubItems[1].ForeColor = Color.FromArgb(170, 0, 0);
                    else if (e.Mode == 2) it.SubItems[1].ForeColor = Color.FromArgb(0, 80, 160);
                    else if (e.Mode == 1) it.SubItems[1].ForeColor = Color.FromArgb(0, 128, 0);
                }
                else it.SubItems[1].ForeColor = Color.Gray;
                if (!File.Exists(e.App)) it.ForeColor = Color.Gray;
                lvApps.Items.Add(it);
            }
            lvApps.EndUpdate();

            if (selPath != null)
            {
                foreach (ListViewItem it in lvApps.Items)
                {
                    AppEntry e = it.Tag as AppEntry;
                    if (e != null && string.Equals(e.App, selPath, StringComparison.OrdinalIgnoreCase))
                    {
                        it.Selected = true;
                        it.Focused = true;
                        break;
                    }
                }
            }
            UpdateSelPanel();
            statusLbl.Text = string.Format("程序 {0} 个", lvApps.Items.Count);
        }

        AppEntry SelectedApp()
        {
            if (lvApps.SelectedItems.Count == 0) return null;
            return lvApps.SelectedItems[0].Tag as AppEntry;
        }

        void UpdateSelPanel()
        {
            AppEntry e = SelectedApp();
            if (e == null)
            {
                lblSelPath.Text = "（未选中程序 — 双击列表中的程序可设置策略）";
                lblSelPath.ForeColor = Color.DimGray;
                rdoFollow.Checked = true;
                SetPanelEnabled(false);
                return;
            }
            SetPanelEnabled(true);
            lblSelPath.ForeColor = SystemColors.ControlText;
            lblSelPath.Text = e.App + (File.Exists(e.App) ? "" : "   [程序文件不存在]");
            if (e.Managed)
            {
                if (e.Mode == 1) rdoAllow.Checked = true;
                else if (e.Mode == 2) rdoPrivate.Checked = true;
                else if (e.Mode == 3) rdoBlock.Checked = true;
                else rdoFollow.Checked = true;
            }
            else rdoFollow.Checked = true;
        }

        void SetPanelEnabled(bool on)
        {
            rdoFollow.Enabled = rdoAllow.Enabled = rdoPrivate.Enabled = rdoBlock.Enabled = on;
        }

        // ================= 操作 =================
        void SetModeLogged(string app, int mode)
        {
            try
            {
                _lastPrompt[app] = DateTime.Now; // 用户刚自己改过，抑制随之而来的新增规则事件弹窗
                Firewall.SetMode(app, mode);
                Store.Log("设置策略: " + app + " → " + Firewall.ModeName(mode));
                AppendKnownApp(app);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "设置失败: " + ex.Message, "网控助手", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        void ApplySelectedModeFromPanel()
        {
            AppEntry e = SelectedApp();
            if (e == null) return;
            int mode = rdoAllow.Checked ? 1 : rdoPrivate.Checked ? 2 : rdoBlock.Checked ? 3 : 0;
            if (mode == 0 && !e.Managed)
            {
                MessageBox.Show(this, "该程序尚未被本工具管理，无需设置“跟随系统”。", "网控助手");
                return;
            }
            SetModeLogged(e.App, mode);
            RefreshNow();
        }

        void ApplyQuick(int mode)
        {
            AppEntry e = SelectedApp();
            if (e == null) return;
            if (mode == 0 && !e.Managed) return;
            SetModeLogged(e.App, mode);
            RefreshNow();
        }

        void ClearSelectedRules()
        {
            AppEntry e = SelectedApp();
            if (e == null) return;
            try
            {
                _lastPrompt[e.App] = DateTime.Now;
                Firewall.RemoveManaged(e.App);
                Store.Log("清除规则: " + e.App);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "清除失败: " + ex.Message, "网控助手", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            RefreshNow();
        }

        void OpenSelectedFolder()
        {
            AppEntry e = SelectedApp();
            if (e == null) return;
            try { Process.Start("explorer.exe", "/select,\"" + e.App + "\""); } catch { }
        }

        void ShowSelectedPolicyDialog()
        {
            AppEntry e = SelectedApp();
            if (e == null) return;
            ShowPolicyDialog(e.App, e);
        }

        void ShowPolicyDialog(string app, AppEntry known)
        {
            bool managed = known != null && known.Managed;
            int currentMode = managed ? known.Mode : -1;
            string effIn = "系统默认", effOut = "系统默认";
            if (known != null)
            {
                effIn = Firewall.EffText(known.Eff, known.Def, 0);
                effOut = Firewall.EffText(known.Eff, known.Def, 1);
            }
            using (PolicyDialog dlg = new PolicyDialog(app, currentMode, effIn, effOut, managed))
            {
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                if (dlg.Clear)
                {
                    _lastPrompt[app] = DateTime.Now;
                    try { Firewall.RemoveManaged(app); Store.Log("清除规则: " + app); }
                    catch (Exception ex)
                    {
                        MessageBox.Show(this, "清除失败: " + ex.Message, "网控助手", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }
                }
                else if (dlg.Mode >= 0)
                {
                    if (dlg.Mode == 0 && !managed) return; // 未管理程序设“跟随系统”没有意义，避免创建无用规则
                    SetModeLogged(app, dlg.Mode);
                }
                else return;
                RefreshNow();
            }
        }

        void AddProgram()
        {
            using (OpenFileDialog ofd = new OpenFileDialog())
            {
                ofd.Filter = "程序 (*.exe)|*.exe|所有文件 (*.*)|*.*";
                ofd.Title = "选择要管理的程序";
                if (ofd.ShowDialog(this) != DialogResult.OK) return;
                ShowPolicyDialog(ofd.FileName, null);
            }
        }

        // ================= 已安装软件 =================
        InstalledApp SelectedInstalled()
        {
            if (lvInstalled.SelectedItems.Count == 0) return null;
            return lvInstalled.SelectedItems[0].Tag as InstalledApp;
        }

        void RefreshInstalled()
        {
            Cursor = Cursors.WaitCursor;
            try
            {
                List<InstalledApp> apps = InstalledApps.GetAll();
                lvInstalled.BeginUpdate();
                lvInstalled.Items.Clear();
                foreach (InstalledApp a in apps)
                {
                    ListViewItem it = new ListViewItem(a.Name);
                    it.SubItems.Add(a.Version);
                    it.SubItems.Add(a.Publisher);
                    it.SubItems.Add(a.Exe ?? "（未定位到主程序）");
                    it.Tag = a;
                    if (a.Exe == null) it.ForeColor = Color.Gray;
                    lvInstalled.Items.Add(it);
                }
                lvInstalled.EndUpdate();
                statusLbl.Text = string.Format("已安装软件 {0} 个", lvInstalled.Items.Count);
            }
            finally { Cursor = Cursors.Default; }
        }

        void SetInstalledPolicy()
        {
            InstalledApp a = SelectedInstalled();
            if (a == null) return;
            if (a.Exe == null)
            {
                MessageBox.Show(this, "无法从安装信息定位主程序 exe。\n请在“程序网络权限”页点“添加程序…”手动选择。", "网控助手");
                return;
            }
            AppEntry known = null;
            foreach (AppEntry e in _appsCache)
                if (string.Equals(e.App, a.Exe, StringComparison.OrdinalIgnoreCase)) { known = e; break; }
            ShowPolicyDialog(a.Exe, known);
        }

        // ================= 事件与历史 =================
        async void RefreshEvents()
        {
            Cursor = Cursors.WaitCursor;
            try
            {
                List<EventItem> evs = await Task.Run(() => FirewallEvents.RecentBlocks(7 * 24 * 3600, 300));
                lvEvents.BeginUpdate();
                lvEvents.Items.Clear();
                foreach (EventItem ev in evs)
                {
                    ListViewItem it = new ListViewItem(ev.Time.ToString("yyyy-MM-dd HH:mm:ss"));
                    it.SubItems.Add(ev.Kind);
                    it.SubItems.Add(ev.App);
                    string msg = ev.Msg;
                    if (msg.Length > 160) msg = msg.Substring(0, 160) + "…";
                    it.SubItems.Add(msg);
                    lvEvents.Items.Add(it);
                }
                lvEvents.EndUpdate();
                if (lvEvents.Items.Count == 0)
                {
                    lvEvents.Items.Add(new ListViewItem(new string[] { "", "最近 7 天没有相关事件记录", "", "" }));
                }

                List<string> hist = Store.ReadHistory(300);
                lvHistory.BeginUpdate();
                lvHistory.Items.Clear();
                foreach (string line in hist)
                {
                    if (line.Length <= 21)
                    {
                        lvHistory.Items.Add(new ListViewItem(new string[] { line, "" }));
                        continue;
                    }
                    lvHistory.Items.Add(new ListViewItem(new string[] { line.Substring(0, 19), line.Substring(21) }));
                }
                lvHistory.EndUpdate();
            }
            finally { Cursor = Cursors.Default; }
        }

        // ================= 设置 =================
        void UpdateMonitorLabel()
        {
            bool on = Store.GetBool("monitor", true);
            statusMon.Text = "监控: " + (on ? "开" : "关");
            tray.Text = "网控助手 — 程序联网" + (on ? "监控中" : "已暂停");
        }

        void SyncMonitorUi()
        {
            bool on = Store.GetBool("monitor", true);
            if (chkMonitor.Checked != on) chkMonitor.Checked = on;
            if (chkPause.Checked != !on) chkPause.Checked = !on;
            UpdateMonitorLabel();
        }

        static bool RunSchtasks(string args)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("schtasks.exe", args);
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                using (Process p = Process.Start(psi))
                {
                    p.WaitForExit(15000);
                    return p.ExitCode == 0;
                }
            }
            catch { return false; }
        }

        bool GetAutostart()
        {
            if (RunSchtasks("/Query /TN NetGuardAssistant")) return true;
            using (RegistryKey rk = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run"))
                return rk != null && rk.GetValue("NetGuardAssistant") != null;
        }

        void SetAutostart(bool enable)
        {
            try
            {
                if (enable)
                {
                    bool ok = RunSchtasks("/Create /F /SC ONLOGON /RL HIGHEST /TN NetGuardAssistant /TR \"\\\"" +
                        Application.ExecutablePath + "\\\"\"");
                    if (!ok)
                    {
                        using (RegistryKey rk = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true))
                        {
                            if (rk != null) rk.SetValue("NetGuardAssistant", "\"" + Application.ExecutablePath + "\"");
                        }
                        MessageBox.Show(this, "计划任务创建失败，已改用注册表自启（每次登录会弹一次 UAC）。", "网控助手");
                    }
                    Store.Log("开启开机自启");
                }
                else
                {
                    RunSchtasks("/Delete /F /TN NetGuardAssistant");
                    using (RegistryKey rk = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true))
                    {
                        if (rk != null && rk.GetValue("NetGuardAssistant") != null) rk.DeleteValue("NetGuardAssistant");
                    }
                    Store.Log("关闭开机自启");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "设置自启失败: " + ex.Message, "网控助手", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        // ================= 关闭行为 =================
        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (!_exiting && e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                Hide();
                if (!_balloonShown)
                {
                    _balloonShown = true;
                    tray.BalloonTipTitle = "网控助手";
                    tray.BalloonTipText = "已最小化到托盘，后台继续监控。右键托盘图标可退出。";
                    tray.ShowBalloonTip(3000);
                }
                return;
            }
            base.OnFormClosing(e);
        }

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            monTimer.Stop();
            if (tray != null) tray.Visible = false;
            base.OnFormClosed(e);
        }
    }
}
