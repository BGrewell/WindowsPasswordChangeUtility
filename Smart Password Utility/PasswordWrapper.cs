using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Smart_Password_Utility
{

    class PasswordWrapper
    {
        private const string API_URL = "https://api.pwnedpasswords.com/range/{0}";

        /// #define NET_API_STATUS DWORD
        /// </summary>
        public enum NET_API_STATUS : uint
        {
            NERR_Success = 0,
            NERR_InvalidComputer = 2351,
            NERR_NotPrimary = 2226,
            NERR_SpeGroupOp = 2234,
            NERR_LastAdmin = 2452,
            NERR_BadPassword = 2203,
            NERR_PasswordTooShort = 2245,
            NERR_UserNotFound = 2221,
            ERROR_ACCESS_DENIED = 5,
            ERROR_NOT_ENOUGH_MEMORY = 8,
            ERROR_INVALID_PASSWORD = 86,
            ERROR_INVALID_PARAMETER = 87,
            ERROR_INVALID_NAME = 123,
            ERROR_INVALID_LEVEL = 124,
            ERROR_MORE_DATA = 234,
            ERROR_SESSION_CREDENTIAL_CONFLICT = 1219,
            RPC_S_SERVER_UNAVAILABLE = 2147944122,
            RPC_E_REMOTE_DISABLED = 2147549468
        }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        public static extern NET_API_STATUS NetUserChangePassword([MarshalAs(UnmanagedType.LPWStr)] string domainname, [MarshalAs(UnmanagedType.LPWStr)] string username,
                                                                  [MarshalAs(UnmanagedType.LPWStr)] string oldpassword,[MarshalAs(UnmanagedType.LPWStr)] string newpassword);

        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int memcmp(byte[] b1, byte[] b2, UIntPtr count);

        static PasswordWrapper()
        {
            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
        }

        public static int CheckIsPasswordPwned(string password)
        {
            int count = 0;
            try
            {
                string passwordHash = GetSHA1Hash(password);
                string prefix = passwordHash.Substring(0, 5);
                string suffix = passwordHash.Substring(5);
                Dictionary<string, int> results = QueryPwnedPasswordsAPI(prefix).GetAwaiter().GetResult();
                if (results.ContainsKey(suffix))
                {
                    count = results[suffix];
                }

                return count;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
                return -1;
            }
        }

        private static string GetSHA1Hash(string password)
        {
            using (SHA1Managed hasher = new SHA1Managed())
            {
                var hash = hasher.ComputeHash(Encoding.UTF8.GetBytes(password));
                return string.Join("", hash.Select(x => x.ToString("X2")).ToArray());
            }
        }

        private static async Task<Dictionary<string, int>> QueryPwnedPasswordsAPI(string prefix)
        {
            string url = API_URL.Replace("{0}", prefix);
            WebClient client = new WebClient();
            Stream responseStream = client.OpenRead(url);
            StreamReader reader = new StreamReader(responseStream);
            string response = reader.ReadToEnd();
            if (string.IsNullOrEmpty(response)) 
            {
                return null;
            }
            string[] entries = response.Split(new char[] { '\r', '\n', '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
            Dictionary<string, int> results = new Dictionary<string, int>();
            foreach(string entry in entries)
            {
                string[] parts = entry.Split(':');
                results.Add(parts[0], int.Parse(parts[1]));
            }
            return results;
        }

        public static bool SecureStringsMatch(SecureString s1, SecureString s2)
        {
            if (s1 == s2) return true; //reference equality check

            if (s1 == null || s2 == null || s1.Length != s2.Length) return false;
            IntPtr bstr1 = IntPtr.Zero;
            IntPtr bstr2 = IntPtr.Zero;
            try
            {
                bstr1 = Marshal.SecureStringToBSTR(s1);
                bstr2 = Marshal.SecureStringToBSTR(s2);
                byte b1 = 1;
                byte b2 = 1;
                int i = 0;
                while (((char)b1) != '\0')
                {
                    b1 = Marshal.ReadByte(bstr1, i);
                    b2 = Marshal.ReadByte(bstr2, i);
                    if (b1 != b2)
                    {
                        return false;
                    }
                    i += 2;
                }
                return true;
            }
            finally
            {
                if (bstr1 != IntPtr.Zero)
                {
                    Marshal.ZeroFreeBSTR(bstr1);
                }
                if (bstr2 != IntPtr.Zero)
                {
                    Marshal.ZeroFreeBSTR(bstr2);
                }
            }
        }
    }
}
