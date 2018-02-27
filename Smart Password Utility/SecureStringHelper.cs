using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Smart_Password_Utility
{
    /// <summary>
    /// Helper class to make working with SecureStrings a bit simpiler while hopefully keeping 
    /// the sensitive data as secure as possible. 
    /// </summary>
    class SecureStringHelper
    {
        private readonly Encoding encoding;
        private readonly SecureString secureString;
        private byte[] _bytes = null;

        /// <summary>
        /// Constructors
        /// </summary>
        /// <param name="secureString">The SecureString to wrap</param>
        public SecureStringHelper(SecureString secureString)
              : this(secureString, Encoding.UTF8)
        { }

        public SecureStringHelper(SecureString secureString, Encoding encoding)
        {
            this.encoding = encoding ?? Encoding.UTF8;
            this.secureString = secureString;
        }

        /// <summary>
        /// Get a reference to the SecureString
        /// </summary>
        /// <returns>SecureString</returns>
        public SecureString GetSecureString()
        {
            return this.secureString;
        }

        /// <summary>
        /// Get a pointer to unmanaged memory containing the value in the secure string
        /// ** IMPORTRANT: Make sure and free this when done with the following call
        /// ** CALL: Marshal.ZeroFreeGlobalAllocUnicode(pointer);
        /// </summary>
        /// <returns>Pointer to unmanaged memory containing the SecureStrings value as unicode string</returns>
        public IntPtr GetPointerToPasswordString()
        {
            return Marshal.SecureStringToGlobalAllocUnicode(secureString);
        }

        /// <summary>
        /// Get the SHA1 hash of the SecureStrings value
        /// </summary>
        /// <returns>SHA1 of value in the SecureString</returns>
        public unsafe string GetSHA1Hash()
        {
            int maxLength = encoding.GetMaxByteCount(secureString.Length);

            IntPtr bytes = IntPtr.Zero;
            IntPtr str = IntPtr.Zero;

            try
            {
                bytes = Marshal.AllocHGlobal(maxLength);
                str = Marshal.SecureStringToBSTR(secureString);

                char* chars = (char*)str.ToPointer();
                byte* bptr = (byte*)bytes.ToPointer();
                int len = encoding.GetBytes(chars, secureString.Length, bptr, maxLength);

                _bytes = new byte[len];
                for (int i = 0; i < len; ++i)
                {
                    _bytes[i] = *bptr;
                    bptr++;
                }

                using (SHA1Managed hasher = new SHA1Managed())
                {
                    var hash = hasher.ComputeHash(_bytes);
                    return string.Join("", hash.Select(x => x.ToString("X2")).ToArray());
                }
            }
            finally
            {
                if (bytes != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(bytes);
                }
                if (str != IntPtr.Zero)
                {
                    Marshal.ZeroFreeBSTR(str);
                }
            }
        }

        /// <summary>
        /// Test to see if two SecureStringHelpers have the same value inside them
        /// </summary>
        /// <param name="lh">SecureStringHelper1</param>
        /// <param name="rh">SecureStringHelper2</param>
        /// <returns>True if the internal value is the same, False if it is not</returns>
        public static bool operator ==(SecureStringHelper lh, SecureStringHelper rh)
        {
            // Check for null on left side
            if (Object.ReferenceEquals(lh, null))
            {
                if (Object.ReferenceEquals(rh, null))
                {
                    return true;
                }

                return false;
            }

            return lh.Equals(rh);
        }

        /// <summary>
        /// Test to see if two SecureStringHelpers have a different value inside them
        /// </summary>
        /// <param name="lh">SecureStringHelper1</param>
        /// <param name="rh">SecureStringHelper2</param>
        /// <returns>True if the internal value is the different, False if it is the same</returns>
        public static bool operator !=(SecureStringHelper lh, SecureStringHelper rh)
        {
            return !(lh == rh);
        }

        /// <summary>
        /// Test to see if two SecureStringHelpers have the same value inside them
        /// </summary>
        /// <param name="lh">SecureStringHelper1</param>
        /// <param name="rh">SecureStringHelper2</param>
        /// <returns>True if the internal value is the same, False if it is not</returns>
        public override bool Equals(object obj)
        {
            return this.Equals(obj as SecureStringHelper);
        }

        /// <summary>
        /// Test to see if two SecureStringHelpers have the same value inside them
        /// </summary>
        /// <param name="lh">SecureStringHelper1</param>
        /// <param name="rh">SecureStringHelper2</param>
        /// <returns>True if the internal value is the same, False if it is not</returns>
        public bool Equals(SecureStringHelper p)
        {
            if (Object.ReferenceEquals(p, null))
            {
                return false;
            }

            // Optimization for a common success case.
            if (Object.ReferenceEquals(this, p))
            {
                return true;
            }

            if (this.GetType() != p.GetType())
            {
                return false;
            }

            IntPtr bstr1 = IntPtr.Zero;
            IntPtr bstr2 = IntPtr.Zero;
            try
            {
                bstr1 = Marshal.SecureStringToBSTR(secureString);
                bstr2 = Marshal.SecureStringToBSTR(p.GetSecureString());
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

        /// <summary>
        /// Gets a hashcode for the object. Probably a crappy implementation but since it's not used it should be ok.
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            return int.Parse(GetSHA1Hash().Substring(35), System.Globalization.NumberStyles.HexNumber);
        }

        private bool _disposed = false;

        /// <summary>
        /// Cleans up the object
        /// </summary>
        public void Dispose()
        {
            if (!_disposed)
            {
                Destroy();
                _disposed = true;
            }
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Cleans up the managed byte array.
        /// </summary>
        private void Destroy()
        {
            if (_bytes == null) { return; }

            for (int i = 0; i < _bytes.Length; i++)
            {
                _bytes[i] = 0;
            }
            _bytes = null;
        }

        ~SecureStringHelper()
        {
            Dispose();
        }
    }
}
