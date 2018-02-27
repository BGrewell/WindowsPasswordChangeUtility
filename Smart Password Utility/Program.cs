using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using static Smart_Password_Utility.PasswordWrapper;

namespace Smart_Password_Utility
{
    class Program
    {
        static void Main(string[] args)
        {
            // Default the username and domain to the current users.
            string username = Environment.UserName;
            string domain = Environment.UserDomainName;

            // Handle parsing the domain and username if it is passed as an argument.
            if (args.Length > 0)
            {
                if (args[0].Contains("\\"))
                {
                    string[] parts = args[0].Split('\\');
                    if (!parts[0].Equals('.'))
                    {
                        domain = parts[0].Trim();
                    }
                    username = parts[1].Trim();
                } else
                {
                    username = args[0];
                }
            }

            // Setup to get info from user
            Console.WriteLine("[+] Smart Password Change Utility");
            Console.WriteLine("    Changing password for user: {0}\\{1}", domain, username);
            int maxTries = 3;
            int tries = 0;
            while (tries < maxTries)
            {
                // Prompt for old password
                Console.Write("    Old Password: ");
                SecureStringHelper oldPassword = new SecureStringHelper(ReadPasswordInput());

                prompt:
                // Prompt for new password
                Console.Write("    New Password: ");
                SecureStringHelper newPassword1 = new SecureStringHelper(ReadPasswordInput());

                // Check against the pwned password api
                var count = PasswordWrapper.CheckIsPasswordPwned(newPassword1.GetSHA1Hash());

                // If password was found warn and prompt to try a different password
                if (count > 0)
                {
                    Console.WriteLine("    This password has been found {0:N0} times in data breaches.\r\n    Please try another password.\r\n", count);
                    newPassword1.Dispose();
                    goto prompt;
                }

                // Once we are good confirm the password
                Console.Write("    Confirm Password: ");
                SecureStringHelper newPassword2 = new SecureStringHelper(ReadPasswordInput());

                // Check to make sure the passwords match
                if (!newPassword1.Equals(newPassword2))
                {
                    Console.WriteLine("    Passwords don't match. Try again!\r\n");
                    oldPassword.Dispose();
                    newPassword1.Dispose();
                    newPassword2.Dispose();
                    continue;
                } else
                    {

                    // Setup to change the password
                    NET_API_STATUS result = (NET_API_STATUS)uint.MaxValue;
                    IntPtr oldPassPtr = IntPtr.Zero;
                    IntPtr newPassPtr = IntPtr.Zero;
                    try
                    {
                        // Get pointers to unmanaged memory containing the passwords
                        oldPassPtr = oldPassword.GetPointerToPasswordString();
                        newPassPtr = newPassword1.GetPointerToPasswordString();

                        // Change the password
                        result = PasswordWrapper.NetUserChangePassword(domain, username, oldPassPtr, newPassPtr);
                    }
                    finally
                    {
                        // Cleanup the unmanaged memory
                        if (oldPassPtr != IntPtr.Zero)
                        {
                            Marshal.ZeroFreeGlobalAllocUnicode(oldPassPtr);
                        }
                        if (newPassPtr != IntPtr.Zero)
                        {

                            Marshal.ZeroFreeGlobalAllocUnicode(newPassPtr);
                        }
                        oldPassword.Dispose();
                        newPassword1.Dispose();
                        newPassword2.Dispose();
                    }

                    // Check the results of the password change.
                    if (result == 0)
                    {
                        Console.WriteLine("[+] Password Changed! Please Log Out And Use New Password To Log In.");
                        break;
                    }

                    Console.WriteLine("[-] Error: {0} [{1} tries remaining]", result, maxTries - tries - 1);
                    tries++;
                }
            }
        }

        /// <summary>
        /// Reads input from the user and echo's back * instead of the characters. Places the characters into a SecureString
        /// </summary>
        /// <returns>SecureString with the password value</returns>
        public static SecureString ReadPasswordInput()
        {
            SecureString pass = new SecureString();
            while (true)
            {
                ConsoleKeyInfo key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (pass.Length > 0)
                    {
                        pass.RemoveAt(pass.Length - 1);
                        Console.Write("\b \b");

                    }
                } else if (key.Key == ConsoleKey.Enter)
                {
                    break;
                } else
                {
                    pass.AppendChar(key.KeyChar);
                    Console.Write("*");
                }
            }

            Console.WriteLine("");
            return pass;
        }
    }
}
