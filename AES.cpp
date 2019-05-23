using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Encryption
{
    class AES
    {
        private readonly static string keyStr = "This is Key";
        private readonly static string vector = "This is Vector";

        static void Main(string[] args)
        {
            Encrypt("C:\\test\\100-Sales-Records.zip", "C:\\test\\100-Sales-RecordsEncrypted.enc");

        }
        /**
         * 32자리의 키값을 이용하여 Rfc2898DeriveBytes 생성
         * @param  password                     절대 유출되서는 안되는 키 값이며, 이것으로 암호키를 생성
         */
        public static Rfc2898DeriveBytes MakeKey(string password)
        {

            byte[] keyBytes = System.Text.Encoding.UTF8.GetBytes(password);
            byte[] saltBytes = SHA512.Create().ComputeHash(keyBytes);
            Rfc2898DeriveBytes result = new Rfc2898DeriveBytes(keyBytes, saltBytes, 65536);

            return result;
        }
        /**
         * 16자리의 초기화 벡터값을 이용하여 Rfc2898DeriveBytes 생성
         * @param  iv                     절대 유출되서는 안되는 초기화 벡터 값이며, 이것으로 초기화벡터를 생성
         */
        public static Rfc2898DeriveBytes MakeVector(string vector)
        {

            byte[] vectorBytes = System.Text.Encoding.UTF8.GetBytes(vector);
            byte[] saltBytes = SHA512.Create().ComputeHash(vectorBytes);
            Rfc2898DeriveBytes result = new Rfc2898DeriveBytes(vectorBytes, saltBytes, 65536);

            return result;
        }
        /**
         * 복호화 처리 레지달 알고리즘을 사용하여 AES256-CBC 구현.
         * @param inputFile              암호화할 파일
         * @param outputFile             복호화한 후의 파일명
         * @Step
         *  1. File.ReadAllBytes를 통하여 파일의 모든 Byte를 읽어들임.
         *  2. csEncrypt를 활용하여 AES256-CBC로 Encrypte (PlainFile byte[] -> AES256 Encrypted byte[])
         *  3. 해당 값을 메모리 스트림에 적재
         *  4. msEncrypt.ToArray() : 메모리에 적재된 값을 배열로 읽어 byte[] encrypted에 적재. (AES256 Encrypted byte[])
         *  5. AES256 Encrypted byte[] -> Base64 Encoded String
         *  6. Base64 Encoded String Write on the dest File
         */
        public static void Encrypt(String source, String dest)
        {
            using (RijndaelManaged aes = new RijndaelManaged())
            {
                //Create Key and Vector
                Rfc2898DeriveBytes key = AES.MakeKey(AES.keyStr);
                Rfc2898DeriveBytes vector = AES.MakeVector(AES.vector);

                //AES256
                aes.BlockSize = 128;
                aes.KeySize = 256;

                // It is equal in java
                // Cipher _Cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key.GetBytes(32); //256bit key
                aes.IV = vector.GetBytes(16); //128bit block size


                //processing Encrypt
                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                byte[] encrypted;

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] inputBytes = File.ReadAllBytes(source);
                        csEncrypt.Write(inputBytes, 0, inputBytes.Length);
                    }
                    encrypted = msEncrypt.ToArray();
                }
                string encodedString = Convert.ToBase64String(encrypted);
                File.WriteAllText(dest, encodedString);
            }
        }
    }
}
