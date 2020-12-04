using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Net;
using System.Management;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Collections;
using System.DirectoryServices.AccountManagement;
using System.Net.NetworkInformation;
using Microsoft.Win32;


namespace enumTest
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(@"
 _____ _                      _____                      
/  ___| |                    |  ___|                     
\ `--.| |__   __ _ _ __ _ __ | |__ _ __  _   _ _ __ ___  
 `--. \ '_ \ / _` | '__| '_ \|  __| '_ \| | | | '_ ` _ \ 
/\__/ / | | | (_| | |  | |_) | |__| | | | |_| | | | | | |
\____/|_| |_|\__,_|_|  | .__/\____/_| |_|\__,_|_| |_| |_|
                       | |                               
                       |_|                               
");
            Console.WriteLine("");
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("------------------------------");
            Console.WriteLine("[*] System and User Information");
            Console.WriteLine("------------------------------");
            Console.ResetColor();
            sysinfo();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("------------------------------");
            Console.WriteLine("[*] Domain Information");
            Console.WriteLine("------------------------------");
            Console.ResetColor();
            domain();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("------------------------------");
            Console.WriteLine("[*] Network Information");
            Console.WriteLine("------------------------------");
            Console.ResetColor();
            network();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("------------------------------");
            Console.WriteLine("[*] Process Information");
            Console.WriteLine("------------------------------");
            Console.ResetColor();
            processes();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("------------------------------");
            Console.WriteLine("[*] Searching for Cleartext Credentials");
            Console.WriteLine("------------------------------");
            Console.ResetColor();
            cleartext();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("------------------------------");
            Console.WriteLine("[*] COMPLETE!");
            Console.WriteLine("------------------------------");
            Console.ResetColor();
        }
        public static void sysinfo()
        {
            //hostname-------------------------------------------
            Console.WriteLine("------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Hostname");
            Console.ResetColor();
            Console.WriteLine("------------------------------");
            Console.WriteLine(System.Environment.GetEnvironmentVariable("COMPUTERNAME"));
            Console.WriteLine("------------------------------");
            //OS version info-----------------------------------
            Console.WriteLine("------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("OS Version");
            Console.ResetColor();
            Console.WriteLine("------------------------------");
            Console.WriteLine(Environment.OSVersion);
            Console.WriteLine("------------------------------");
            //system root directory----------------------------
            Console.WriteLine("------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("System Directory");
            Console.ResetColor();
            Console.WriteLine("------------------------------");
            Console.WriteLine(Environment.SystemDirectory);
            Console.WriteLine("------------------------------");
            //mounted drive info-------------------------------
            Console.WriteLine("------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Drive Information");
            Console.ResetColor();
            Console.WriteLine("------------------------------");

            foreach (System.IO.DriveInfo drive in System.IO.DriveInfo.GetDrives())
                try
                {
                    Console.WriteLine("------------------------------");
                    Console.WriteLine("Drive Name");
                    Console.WriteLine(drive.Name);
                    Console.WriteLine("------------------------------");

                    Console.WriteLine("------------------------------");
                    Console.WriteLine("Volume");
                    Console.WriteLine(drive.VolumeLabel);
                    Console.WriteLine("------------------------------");
                }
                catch
                {

                }
            //username-----------------------------------------
            Console.WriteLine("------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Username");
            Console.ResetColor();
            Console.WriteLine("------------------------------");
            Console.WriteLine(Environment.UserName);
            Console.WriteLine("------------------------------");
            Console.WriteLine("------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Local Groups");
            Console.ResetColor();
            Console.WriteLine("------------------------------");
            DirectoryEntry machine = new DirectoryEntry("WinNT://" + Environment.MachineName + ",Computer");
            foreach (DirectoryEntry child in machine.Children)
            {
                if (child.SchemaClassName == "Group")
                {
                    Console.WriteLine(child.Name.ToString());
                }
            }
            //local admin group members---------------------
            Console.WriteLine("------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Local Administrator Group Members");
            Console.ResetColor();
            Console.WriteLine("------------------------------");
            using (DirectoryEntry d = new DirectoryEntry("WinNT://" + Environment.MachineName + ",computer"))
            {
                using (DirectoryEntry g = d.Children.Find("Administrators", "group"))
                {
                    object members = g.Invoke("Members", null);
                    foreach (object member in (IEnumerable)members)
                    {
                        DirectoryEntry x = new DirectoryEntry(member);
                        Console.Out.WriteLine(x.Name);
                    }
                }
            }
            //AV, Anti-Spyware, Firewall detection (https://stackoverflow.com/questions/1331887/detect-antivirus-on-windows-using-c-sharp)
            ManagementObjectSearcher wmiData1 = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT * FROM AntiVirusProduct");
            ManagementObjectCollection data1 = wmiData1.Get();

            ManagementObjectSearcher wmiData2 = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT * FROM FirewallProduct");
            ManagementObjectCollection data2 = wmiData2.Get();

            ManagementObjectSearcher wmiData3 = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT * FROM AntiSpywareProduct");
            ManagementObjectCollection data3 = wmiData3.Get();

            Console.WriteLine("------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("AntiVirus Installed");
            Console.ResetColor();
            Console.WriteLine("------------------------------");
            foreach (ManagementObject virusChecker in data1)
            {
                var virusCheckerName = virusChecker["displayName"];
                Console.WriteLine(virusCheckerName);
            }
            Console.WriteLine("------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Third Party Firewall Products");
            Console.ResetColor();
            Console.WriteLine("------------------------------");
            foreach (ManagementObject virusChecker in data2)
            {
                var virusCheckerName = virusChecker["displayName"];
                Console.WriteLine(virusCheckerName);
            }
            Console.WriteLine("------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Anti-Spyware Installed");
            Console.ResetColor();
            Console.WriteLine("------------------------------");
            foreach (ManagementObject virusChecker in data3)
            {
                var virusCheckerName = virusChecker["displayName"];
                Console.WriteLine(virusCheckerName);
            }

        }
        public static void domain()
        {
            //domain name-------------------------------------
            Console.WriteLine("------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Domain Name");
            Console.ResetColor();
            Console.WriteLine("------------------------------");
            Console.WriteLine(Environment.UserDomainName);
            //domain controller location
            Console.WriteLine("------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Domain Controllers");
            Console.ResetColor();
            Console.WriteLine("------------------------------");
            try
            {
                Domain domain = Domain.GetCurrentDomain();
                using (domain)
                {
                    foreach (DomainController dc in domain.FindAllDiscoverableDomainControllers())
                    {

                        using (dc)
                        {
                            if (dc == null || dc.ToString() == "")
                            {
                                Console.WriteLine("No Domain Controllers Found");
                            }
                            else
                            {
                                Console.WriteLine(dc.Name);
                                Console.WriteLine(dc.OSVersion);
                                Console.WriteLine(dc.SiteName);
                                Console.WriteLine(dc.IPAddress);
                                Console.WriteLine(dc.Forest);
                                Console.WriteLine("");
                            }
                        }
                    }
                }
            }
            catch
            {
                Console.WriteLine("[!] Error Contacting Domain Controller");
            }
            //domain user groups-----------------------------------
            Console.WriteLine("------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Domain User Groups for " + Environment.UserName);
            Console.ResetColor();
            Console.WriteLine("------------------------------");
            try
            {
                using (PrincipalContext grps = new PrincipalContext(ContextType.Domain))
                {
                    UserPrincipal user = UserPrincipal.FindByIdentity(grps, Environment.UserName);
                    Console.WriteLine(user);
                    if (user != null)
                    {
                        var groups = user.GetAuthorizationGroups();
                        foreach (GroupPrincipal group in groups)
                        {
                            Console.WriteLine(group);
                        }
                    }
                }
            }
            catch
            {
                Console.WriteLine("[!] Error Contacting Domain Controller");
            }
            Console.WriteLine("------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Available File Shares");
            Console.ResetColor();
            Console.WriteLine("------------------------------");
            using (ManagementClass shares = new ManagementClass(@"\\.\root\cimv2", "Win32_Share", new ObjectGetOptions()))
            {
                foreach (ManagementObject share in shares.GetInstances())
                {
                    Console.WriteLine(share["Name"]);
                }
            }
        }
        public static void network()
        {
            //ipconfig-----------------------------------------
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Local Network Interfaces");
            Console.ResetColor();
            Console.WriteLine("------------------------------");
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 || ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet)
                {
                    Console.WriteLine(ni.Name);
                    foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            Console.WriteLine(ip.Address.ToString());
                            Console.WriteLine("\n");
                        }
                    }
                }
            }
            //IPv6--------------------------------------------------
            Console.WriteLine("------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("IPv6 Support");
            Console.ResetColor();
            Console.WriteLine("------------------------------");
            NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
            IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
            int count = 0;

            foreach (NetworkInterface adapter in nics)
            {
                if (adapter.Supports(NetworkInterfaceComponent.IPv6) == false)
                {
                    continue;
                }
                else if (adapter.Supports(NetworkInterfaceComponent.IPv6) == true)
                {
                    Console.WriteLine(adapter.Description + " Supports IPv6!");
                    Console.WriteLine("\n");
                }

                count++;
            }
            //netstat (from https://avtechshare.wordpress.com/2009/02/09/netstat-in-c/)---------------------------------------
            Console.WriteLine("------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Open Network Connections");
            Console.ResetColor();
            Console.WriteLine("------------------------------");
            IPGlobalProperties ipprops = IPGlobalProperties.GetIPGlobalProperties();
            IPEndPoint[] endpoints = ipprops.GetActiveTcpListeners();
            TcpConnectionInformation[] tcpConnections = ipprops.GetActiveTcpConnections();

            foreach (TcpConnectionInformation info in tcpConnections)
            {
                Console.WriteLine("Local: " + info.LocalEndPoint.Address.ToString()
                    + ":" + info.LocalEndPoint.Port.ToString() + "\nRemote: "
                    + info.RemoteEndPoint.Address.ToString() + ":" + info.RemoteEndPoint.Port.ToString()
                    + "\nState: " + info.State.ToString() + "\n\n");
            }
            //print hosts file------------------------------------------------------
            Console.WriteLine("------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Hosts file content");
            Console.ResetColor();
            Console.WriteLine("------------------------------");
            string hosts = File.ReadAllText(@"C:\\Windows\\System32\\drivers\\etc\\hosts");
            Console.WriteLine(hosts);
        }

        public static void processes()
        {
            //tasklist------------------------------------
            Console.WriteLine("------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Tasklist");
            Console.ResetColor();
            Console.WriteLine("------------------------------");
            Process[] processes = Process.GetProcesses();
            foreach (Process proc in processes)
            {
                Console.WriteLine("Process Name: " + proc.ProcessName);
                Console.WriteLine("Process ID: " + proc.Id);

                try
                {
                    //https://www.dreamincode.net/forums/topic/192381-unable-to-get-process-username/
                    ObjectQuery objQuery = new ObjectQuery("Select * from Win32_Process where ProcessId='" + proc.Id + "'");
                    ManagementObjectSearcher mos = new ManagementObjectSearcher(objQuery);
                    string processOwner = "";
                    string domain = "";
                    foreach (ManagementObject mo in mos.Get())
                    {
                        string[] s = new string[2];
                        mo.InvokeMethod("GetOwner", (object[])s);
                        processOwner = s[0].ToString();
                        domain = s[1].ToString();
                        break;
                    }
                    Console.WriteLine("Process Owner: " + domain + "\\" + processOwner);
                }
                catch
                {
                    Console.WriteLine("Process Owner: N/A");
                }
                Console.WriteLine("");
            }
            //Installed Updates https://stackoverflow.com/questions/815340/how-do-i-get-a-list-of-installed-updates-and-hotfixes
            Console.WriteLine("------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Installed Updates");
            Console.ResetColor();
            Console.WriteLine("------------------------------");
            const string querys = "SELECT HotFixID FROM Win32_QuickFixEngineering";
            var search = new ManagementObjectSearcher(querys);
            var collection = search.Get();

            foreach (ManagementObject quickfix in collection)
            {
                var hotfix = quickfix["HotFixID"].ToString();
                Console.WriteLine(hotfix);
            }
            Console.WriteLine("");
            //Program Files directory listing
            Console.WriteLine("------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("C:\\Program Files\\ directory content");
            Console.ResetColor();
            Console.WriteLine("------------------------------");
            try
            {
                string[] dirs1 = Directory.GetDirectories(@"C:\\Program Files\");
                foreach (string dir1 in dirs1)
                {
                    Console.WriteLine(dir1);
                }
            }
            catch
            {

            }
            Console.WriteLine("");
            //Program Files (x86) listing------------------------------------
            Console.WriteLine("------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("C:\\Program Files (x86)\\ directory content");
            Console.ResetColor();
            Console.WriteLine("------------------------------");
            try
            {
                string[] dirs1 = Directory.GetDirectories(@"C:\\Program Files (x86)\");
                foreach (string dir1 in dirs1)
                {
                    Console.WriteLine(dir1);
                }
            }
            catch
            {

            }
            Console.WriteLine("");
            //figure out how to read nested subkeys from registry (cause documentation on this sucks)

        }
        public static void cleartext()
        {
            //Cleartext passwords in files-------------------------------------------
            string[] files = { @"C:\unattend.xml", @"C:\Windows\Panther\Unattend.xml", @"C:\Windows\Panther\Unattend\Unattend.xml", @"C:\Windows\system32\sysprep.inf", @"C:\Windows\system32\sysprep\sysprep.xml" };
            Console.WriteLine("------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Cleartext Passwords in Common Files");
            Console.ResetColor();
            Console.WriteLine("------------------------------");
            foreach (string f in files)
            {
                if (File.Exists(f))
                {
                    Console.WriteLine(f + " Exists!");
                    string text = File.ReadAllText(f);
                    Console.WriteLine(text);
                }
                else
                {
                    Console.WriteLine(f + " Does Not Exist On This System!");
                }
            }
        }
    }

    //WSL Enumeration
    //write file output option

    //To Do
    //Finish initial version
    //Shorten functions using string arrays and foreach loops
    //Modularize
    //Attempt to replicate using windows API calls directly

    //Think about WSL enumeration script
}

