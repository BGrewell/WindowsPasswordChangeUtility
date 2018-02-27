using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace Smart_Password_Utility
{
    class Program
    {
        static void Main(string[] args)
        {
            int maxTries = 3;
            int tries = 0;
            while (tries < maxTries)
            {
                // Prompt for old password
                Console.Write("Old Password: ");
                string oldPassword = ReadPasswordInput().ToString();

                //prompt:
                // Prompt for new password
                Console.Write("New Password: ");
                SecureString newPassword1 = ReadPasswordInput();

                //// Check against the pwned password api
                //var count = PasswordWrapper.CheckIsPasswordPwned(newPassword1);

                //// If password was found warn and prompt to try a different password
                //if (count > 0)
                //{
                //    Console.WriteLine("This password has been found {0:N0} times in data breaches. Please try another password.\r\n", count);
                //    goto prompt;
                //} 

                // Once we are good confirm the password
                Console.Write("Confirm Password: ");
                SecureString newPassword2 = ReadPasswordInput();
                if (!PasswordWrapper.SecureStringsMatch(newPassword1, newPassword2))
                {
                    Console.WriteLine("Passwords don't match. Try again!\r\n");
                    continue;
                } else
                {
                    Console.WriteLine("Passwords match!");
                }
            //    } else
            //    {
            //        var result = PasswordWrapper.NetUserChangePassword(Environment.UserDomainName, "bob", oldPassword, newPassword1);
            //        if (result == 0)
            //        {
            //            Console.WriteLine("Password Changed!");
            //            break;
            //        }

            //        Console.WriteLine("Error: {0} [{1} tries remaining]", result, maxTries-tries-1);
            //        tries++;
            //    }
            }

            Console.WriteLine("Press any key to exit ... remove me");
            Console.ReadKey();
        }

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
