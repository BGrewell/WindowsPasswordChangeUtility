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

//MIT License
//
//Copyright(c) 2018 Ben Grewell
//
//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.

namespace Smart_Password_Utility
{
    /// <summary>
    /// Wrapper class around the password management functions
    /// </summary>
    class PasswordWrapper
    {
        /// <summary>
        /// URL to access the pwnedpasswords API
        /// </summary>
        private const string API_URL = "https://api.pwnedpasswords.com/range/{0}";

        /// <summary>
        /// Some common enums to translate error numbers to a slightly more useful message. 
        /// TODO: This could be made much more user friendly still.
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
            ERROR_INVALID_OLD_PASSWORD = 86,
            ERROR_INVALID_PARAMETER = 87,
            ERROR_INVALID_NAME = 123,
            ERROR_INVALID_LEVEL = 124,
            ERROR_MORE_DATA = 234,
            ERROR_SESSION_CREDENTIAL_CONFLICT = 1219,
            RPC_S_SERVER_UNAVAILABLE = 2147944122,
            RPC_E_REMOTE_DISABLED = 2147549468
        }

        //TODO: Add method to change password without old password if user executing has proper privs.
        /// <summary>
        /// Pinvokes to change passwords
        /// </summary>
        /// <param name="domainname">Domain name of the target user</param>
        /// <param name="username">Username to change password on</param>
        /// <param name="oldpassword">Users old password</param>
        /// <param name="newpassword">Password with which to replace the users current password</param>
        /// <returns></returns>
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        public static extern NET_API_STATUS NetUserChangePassword([MarshalAs(UnmanagedType.LPWStr)] string domainname, [MarshalAs(UnmanagedType.LPWStr)] string username,
                                                                  [MarshalAs(UnmanagedType.LPWStr)] string oldpassword,[MarshalAs(UnmanagedType.LPWStr)] string newpassword);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        public static extern NET_API_STATUS NetUserChangePassword([MarshalAs(UnmanagedType.LPWStr)] string domainname, [MarshalAs(UnmanagedType.LPWStr)] string username,
                                                                  IntPtr oldpassword, IntPtr newpassword);

        /// <summary>
        /// Constructor
        /// </summary>
        static PasswordWrapper()
        {
            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
        }

        /// <summary>
        /// Function to check if the password is in the pwned passwords database using the k-anonymity method.
        /// </summary>
        /// <param name="hash">Full SHA1 hash of the password (only the first 5 chars are sent to the internet)</param>
        /// <returns>count of how many times the password was found</returns>
        public static int CheckIsPasswordPwned(string hash)
        {
            int count = 0;
            try
            {
                string prefix = hash.Substring(0, 5);
                string suffix = hash.Substring(5);
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

        /// <summary>
        /// Helper function to get a SHA1 hash of a string
        /// </summary>
        /// <param name="password">password as a string</param>
        /// <returns>hex string of SHA1 hash</returns>
        public static string GetSHA1Hash(string password)
        {
            using (SHA1Managed hasher = new SHA1Managed())
            {
                var hash = hasher.ComputeHash(Encoding.UTF8.GetBytes(password));
                return string.Join("", hash.Select(x => x.ToString("X2")).ToArray());
            }
        }

        /// <summary>
        /// Helper to perform the acutal query
        /// </summary>
        /// <param name="prefix">first 5 chars of the SHA1 hash</param>
        /// <returns>A dictionary of results that start with that prefix and a count of how many times each has been seen</returns>
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
    }
}
