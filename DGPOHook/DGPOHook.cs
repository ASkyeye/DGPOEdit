using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;
using EasyHook;

using static EasyHook.RemoteHooking;

namespace DGPOHook {

    public enum ExtendedNameFormat {
        NameUnknown = 0,
        NameFullyQualifiedDN = 1,
        NameSamCompatible = 2,
        NameDisplay = 3,
        NameUniqueId = 6,
        NameCanonical = 7,
        NameUserPrincipal = 8,
        NameCanonicalEx = 9,
        NameServicePrincipal = 10,
        NameDnsDomain = 12
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct SHELLEXECUTEINFOW {
        public int cbSize;
        public uint fMask;
        public IntPtr hwnd;
        public IntPtr lpVerb;
        public IntPtr lpFile;
        public IntPtr lpParameters;
        public IntPtr lpDirectory;
        public int nShow;
        public IntPtr hInstApp;
        public IntPtr lpIDList;
        public IntPtr lpClass;
        public IntPtr hkeyClass;
        public uint dwHotKey;
        public IntPtr hIcon;
        public IntPtr hProcess;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct DOMAIN_CONTROLLER_INFO {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string DomainControllerName;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string DomainControllerAddress;
        public uint DomainControllerAddressType;
        public Guid DomainGuid;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string DomainName;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string DnsForestName;
        public uint Flags;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string DcSiteName;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string ClientSiteName;
    }

    public class ServerRpc : MarshalByRefObject  {

        public void IsInstalled(int clientPID) {
            Console.WriteLine($"DGPOEdit has injected hooks into process {clientPID}.\r\n");
        }
 
        public void ReportMessage(int clientPID, string message) {
            Console.WriteLine(message);
        }

        public void ReportException(Exception e) {
            Console.WriteLine("The target process has reported an error:\r\n" + e.ToString());
        }

        public void Ping() {
        }
    }

    public class DGPOHook : IEntryPoint {

        static Regex ldapPattern = new Regex("^LDAP:\\/\\/([^\\/]+)([\\/]?[^\\/]+)?");
        string TargetDomain;
        string DomainController;
        ServerRpc Server;
        string LastMessage = null;

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError=true)]
        delegate bool GetUserNameEx_Delegate(ExtendedNameFormat nameFormat, IntPtr userNamePtr, ref int userNameSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError=true)]
        delegate bool ShellExecuteExW_Delegate(ref SHELLEXECUTEINFOW lpExecInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate uint NtCreateFile_Delegate(out IntPtr handle, uint access, ref OBJECT_ATTRIBUTES objectAttributes, IntPtr ioStatus, ref long allocSize,
                                                uint fileAttributes, uint share, uint createDisposition, uint createOptions, IntPtr eaBuffer, uint eaLength);
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate uint DsRoleGetPrimaryDomainInformation_Delegate(string lpServer, uint InfoLevel, out IntPtr buffer);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate uint ADsGetObject_Delegate(string lpszPathName, ref Guid riid, out IntPtr ppObject);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate int DsGetDcNameW_Delegate(string ComputerName, string DomainName, IntPtr DomainGuid, string SiteName, int Flags, out IntPtr pDOMAIN_CONTROLLER_INFO);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool LookupAccountSidW_Delegate(string lpSystemName, [MarshalAs(UnmanagedType.LPArray)] byte[] Sid, IntPtr lpName, ref uint cchName,
                                                IntPtr ReferencedDomainName, ref uint cchReferencedDomainName, out uint peUse);


        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("Activeds.dll", CharSet = CharSet.Unicode)]
        static extern uint ADsGetObject(string lpszPathName, ref Guid riid, out IntPtr ppObject);

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        static extern uint DsRoleGetPrimaryDomainInformation(string lpServer, uint InfoLevel, out IntPtr buffer);

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int DsGetDcNameW(string ComputerName, string DomainName, IntPtr DomainGuid, string SiteName, int Flags, out IntPtr pDOMAIN_CONTROLLER_INFO);

        [DllImport("sspicli.dll", CharSet = CharSet.Unicode)]
        static extern bool GetUserNameExW(ExtendedNameFormat nameFormat, IntPtr userName, ref int userNameSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern void SetLastError(uint dwErrorCode);

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        static extern bool ShellExecuteExW(ref SHELLEXECUTEINFOW lpExecInfo);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = true)]
        public static extern uint NtCreateFile(out IntPtr handle, uint access, ref OBJECT_ATTRIBUTES objectAttributes, IntPtr ioStatus, ref long allocSize,
                                                uint fileAttributes, uint share, uint createDisposition, uint createOptions, IntPtr eaBuffer, uint eaLength);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool RtlCreateUnicodeString(ref UNICODE_STRING DestinationString, string SourceString);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool RtlFreeUnicodeString( ref UNICODE_STRING String);

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool LookupAccountSidW(string lpSystemName,[MarshalAs(UnmanagedType.LPArray)] byte[] Sid, IntPtr lpName, ref uint cchName,
                                                IntPtr ReferencedDomainName,ref uint cchReferencedDomainName, out uint peUse);

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct IO_STATUS_BLOCK {
            public uint status;
            public IntPtr information;
        }
       
        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct OBJECT_ATTRIBUTES {
            public uint Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;

        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct UNICODE_STRING {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;

        }

        public DGPOHook(IContext ctx, string domain, string domainController, string channelName) {
            TargetDomain = domain;
            DomainController = domainController;

            // Connect to server object using provided channel name
            Server = IpcConnectClient<ServerRpc>(channelName);

            Server.Ping();
        }

        bool GetRedirectedFileName(ref string fileName) {
 
            var prefix = $@"\??\unc\{TargetDomain.ToLower()}\";

            if (fileName.ToLower().StartsWith(prefix)) {
                fileName = $@"\??\UNC\{DomainController}\{fileName.Substring(prefix.Length)}";
                LastMessage = $"[=] Redirected GPO file to {fileName}";
                return true;
            }

            return false;
        }

        uint NtCreateFile_Hook(out IntPtr handle, uint access, ref OBJECT_ATTRIBUTES objectAttributes, IntPtr ioStatus, ref long allocSize,
                                                uint fileAttributes, uint share, uint createDisposition, uint createOptions, IntPtr eaBuffer, uint eaLength) {

            
            if (objectAttributes.ObjectName != IntPtr.Zero) {
                var objName = Marshal.PtrToStructure<UNICODE_STRING>(objectAttributes.ObjectName);
                var rawName = new byte[objName.Length];
                Marshal.Copy(objName.Buffer, rawName,0, objName.Length);
                var path = Encoding.Unicode.GetString(rawName);

                if (GetRedirectedFileName(ref path)) {

                    var originalName = objectAttributes.ObjectName;
                    UNICODE_STRING redirectedName = new UNICODE_STRING();                    
                    RtlCreateUnicodeString(ref redirectedName, path);

                    objectAttributes.ObjectName = Marshal.AllocHGlobal(Marshal.SizeOf<UNICODE_STRING>());
                    Marshal.StructureToPtr(redirectedName, objectAttributes.ObjectName, false);

                    var result = NtCreateFile(out handle, access, ref objectAttributes, ioStatus, ref allocSize, fileAttributes, 
                        share, createDisposition, createOptions, eaBuffer, eaLength);

                    RtlFreeUnicodeString(ref redirectedName);
                    Marshal.FreeHGlobal(objectAttributes.ObjectName);
                    objectAttributes.ObjectName = originalName;

                    return result;
                }
            }            

            return NtCreateFile(out handle, access, ref objectAttributes, ioStatus, ref allocSize, fileAttributes, share, createDisposition, createOptions, eaBuffer, eaLength);
        }

        bool ShellExecuteExW_Hook(ref SHELLEXECUTEINFOW lpExecInfo) {

            var lpFileOrig = lpExecInfo.lpFile;
            var lpParamOrig = lpExecInfo.lpParameters;

            if(lpExecInfo.lpFile != IntPtr.Zero) {

                var managedFileName = Marshal.PtrToStringUni(lpFileOrig);
                     
                if (managedFileName == "gpme.msc") {
                    lpExecInfo.lpFile = Marshal.StringToHGlobalUni(Path.Combine(Path.GetDirectoryName(Assembly.GetCallingAssembly().Location), "DGPOEdit.exe"));
                } else if (managedFileName == "certtmpl.msc") {
                    lpExecInfo.lpFile = Marshal.StringToHGlobalUni(Path.Combine(Path.GetDirectoryName(Assembly.GetCallingAssembly().Location), "DGPOEdit.exe"));
                    lpExecInfo.lpParameters = Marshal.StringToHGlobalUni($"template {TargetDomain}");
                }
            }
               
            var result = ShellExecuteExW(ref lpExecInfo);

            if (lpExecInfo.lpFile != lpFileOrig) {
                Marshal.FreeHGlobal(lpExecInfo.lpFile);
                lpExecInfo.lpFile = lpFileOrig;

            }

            if (lpExecInfo.lpParameters != lpParamOrig) {
                Marshal.FreeHGlobal(lpExecInfo.lpParameters);
                lpExecInfo.lpParameters = lpParamOrig;
            }
            
            return result;
        }

        bool GetUserNameEx_Hook(ExtendedNameFormat nameFormat, IntPtr userNamePtr, ref int userNameSize) {

            if (nameFormat == ExtendedNameFormat.NameDnsDomain) {
                
                var fullName =  $"{TargetDomain}\\User";

                //If the input is not long enough, just pass onto the original function
                if (userNameSize < fullName.Length + 1) {
                    userNameSize = fullName.Length + 1;
                    SetLastError(0xea); //ERROR_MORE_DATA;
                    LastMessage = $"[+] GetUserNameEx_Hook - Faked domain joined error condition";
                    return false;
                } else {
                    var rawName = Encoding.Unicode.GetBytes(fullName + '\0');
                    Marshal.Copy(rawName, 0, userNamePtr, rawName.Length);
                    userNameSize = fullName.Length;
                    LastMessage = $"[+] GetUserNameEx_Hook - Faked domain user format with {fullName}";
                    return true;
                }
                
            } else {
                return GetUserNameExW(nameFormat, userNamePtr, ref userNameSize); 
            }            
        }

        uint DsRoleGetPrimaryDomainInformation_Hook(string lpServer, uint InfoLevel, out IntPtr buffer) {
            return DsRoleGetPrimaryDomainInformation(lpServer == null ? DomainController : lpServer, InfoLevel, out buffer);
        }

        uint ADsGetObject_Hook(string lpszPathName, ref Guid riid, out IntPtr ppObject) {

            if (lpszPathName != null) {

                if (lpszPathName == "LDAP://RootDSE")
                    lpszPathName = $"LDAP://{DomainController}/RootDSE";
                else {
                    var match = ldapPattern.Match(lpszPathName);
                    if (match.Success) {
                        if (match.Groups[1].Value.Contains("=")){
                            lpszPathName = $"LDAP://{DomainController}/{match.Groups[1].Value}";
                        }
                    }
                }
            }
                        
            return ADsGetObject(lpszPathName, ref riid, out ppObject);
        }

        int DsGetDcNameW_Hook(string ComputerName, string DomainName, IntPtr DomainGuid, string SiteName, int Flags, out IntPtr pDOMAIN_CONTROLLER_INFO) {
            return DsGetDcNameW(ComputerName == null ? DomainController : ComputerName, DomainName, DomainGuid, SiteName, Flags, out pDOMAIN_CONTROLLER_INFO);
        }

        LocalHook CreateHook(string dll, string export, Delegate hookFunction) {
            var localHook = LocalHook.Create(EasyHook.LocalHook.GetProcAddress(dll, export),
                hookFunction, this);
            localHook.ThreadACL.SetExclusiveACL(new int[] { 0 });
            return localHook;
        }

        bool LookupAccountSidW_Hook(string lpSystemName, [MarshalAs(UnmanagedType.LPArray)] byte[] Sid, IntPtr lpName, ref uint cchName,
                                                IntPtr ReferencedDomainName, ref uint cchReferencedDomainName, out uint peUse) {
            return LookupAccountSidW(lpSystemName == null ? DomainController : lpSystemName, Sid, lpName, ref cchName, ReferencedDomainName, ref cchReferencedDomainName, out peUse);
        }

        public void Run(IContext ctx, string domain, string domainController, string channelName) {

            if (string.IsNullOrEmpty(domainController)) {

                if (DsGetDcNameW(null, domain, IntPtr.Zero, null, 0, out var pDomainInfo) > 0) {
                    MessageBox.Show($"Failed to get domain controller info for domain {domain}", "DGPOEdit", MessageBoxButtons.OK);
                    return;
                }
                                    
                var domainInfo = Marshal.PtrToStructure<DOMAIN_CONTROLLER_INFO>(pDomainInfo);
                DomainController = domainInfo.DomainControllerName.Substring(2);                         
            }

            //pre-load DLL's otherwise EasyHook wont find it
            LoadLibrary("Activeds.dll");
            LoadLibrary("netapi32.dll");

            var ntCreateFileHook = (LocalHook)null;
            var getUserNameExHook = CreateHook("sspicli.dll", "GetUserNameExW", new GetUserNameEx_Delegate(GetUserNameEx_Hook));                
            var dsRoleGetPrimaryDomainInformation_Hook = CreateHook("netapi32.dll", "DsRoleGetPrimaryDomainInformation", new DsRoleGetPrimaryDomainInformation_Delegate(DsRoleGetPrimaryDomainInformation_Hook));
            var adsGetObject_Hook = CreateHook("activeds.dll", "ADsGetObject", new ADsGetObject_Delegate(ADsGetObject_Hook));
            var dsGetDcNameW_Hook = CreateHook("NetApi32.dll", "DsGetDcNameW", new DsGetDcNameW_Delegate(DsGetDcNameW_Hook));
            var lookupAccountSidW_Hook = CreateHook("advapi32.dll", "LookupAccountSidW", new LookupAccountSidW_Delegate(LookupAccountSidW_Hook));
            var shellExecuteExW_Hook = CreateHook("shell32.dll", "ShellExecuteExW", new ShellExecuteExW_Delegate(ShellExecuteExW_Hook));

            if (domainController != "") {
                ntCreateFileHook = LocalHook.Create(EasyHook.LocalHook.GetProcAddress("ntdll.dll", "NtCreateFile"),
                    new NtCreateFile_Delegate(NtCreateFile_Hook), this);
                ntCreateFileHook.ThreadACL.SetExclusiveACL(new int[] { 0 });
            }

            Server.ReportMessage(Process.GetCurrentProcess().Id, $"[=] Hooks installed using target domain {TargetDomain}, resuming process");

            WakeUpProcess();

            try {
                while (true) {
                    Thread.Sleep(500);

                    if (LastMessage != null) {
                        Server.ReportMessage(Process.GetCurrentProcess().Id, LastMessage);
                        LastMessage = null;
                    } else {
                        Server.Ping();
                    }
                }
            } catch {
                // Ping() or ReportMessages() will raise an exception if host is unreachable
            }

            getUserNameExHook.Dispose();
            dsRoleGetPrimaryDomainInformation_Hook.Dispose();
            adsGetObject_Hook.Dispose();
            lookupAccountSidW_Hook.Dispose();

            if (domainController != null) {
                ntCreateFileHook.Dispose();
            }

            LocalHook.Release();            
        }
    }
}
