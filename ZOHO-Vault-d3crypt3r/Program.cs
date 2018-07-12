using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Security.Cryptography;


namespace ZOHO_Vault_d3crypt3r
{
    class Program
    {
        static int Main(string[] args)
        {
            if (args.Length == 0)
            {
                System.Console.WriteLine("Please enter the password to decrypt.");
                return 1;
            }
            else
            {
                string password = args[0];
                string cleartextpassword = Provisioning_Utils.CryptUtil.decrypt(password);
                System.Console.WriteLine(cleartextpassword);
                return 0;
            }
        }
    }
}


namespace Provisioning_Utils
{
  public class CryptUtil
  {
    private static UTF8Encoding encoding = new UTF8Encoding();
    private static byte[] kBytes = CryptUtil.encoding.GetBytes("6ZUJiqpBKHuNuS@*");
    private static byte[] tmpIV = CryptUtil.encoding.GetBytes("BJLTHGVTPJQMDEXO");

    public static string decrypt(string encodedStr)
    {
      return CryptUtil.decrypt(CryptUtil.kBytes, encodedStr);
    }

    public static string decrypt(byte[] keyBytes, string encodedStr)
    {
      if (encodedStr != null)
      {
        if (!encodedStr.Equals(""))
        {
          try
          {
            byte[] buffer = Convert.FromBase64String(encodedStr);
            RijndaelManaged rijndaelManaged = new RijndaelManaged();
            byte[] bytes = new PasswordDeriveBytes(CryptUtil.tmpIV, new SHA1CryptoServiceProvider().ComputeHash(CryptUtil.tmpIV)).GetBytes(16);
            rijndaelManaged.Mode = CipherMode.CBC;
            rijndaelManaged.Padding = PaddingMode.PKCS7;
            rijndaelManaged.KeySize = 128;
            rijndaelManaged.BlockSize = 128;
            rijndaelManaged.Key = keyBytes;
            rijndaelManaged.IV = bytes;
            ICryptoTransform decryptor = rijndaelManaged.CreateDecryptor();
            using (MemoryStream memoryStream = new MemoryStream(buffer))
            {
              using (CryptoStream cryptoStream = new CryptoStream((Stream) memoryStream, decryptor, CryptoStreamMode.Read))
              {
                using (StreamReader streamReader = new StreamReader((Stream) cryptoStream))
                  return streamReader.ReadToEnd();
              }
            }
          }
          catch (Exception ex)
          {
            return string.Format("{0}", (object) ex);
          }
        }
      }
      return encodedStr;
    }
  }
}
