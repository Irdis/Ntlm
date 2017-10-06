using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace In.Ntlm.Http
{
    // http://davenport.sourceforge.net/ntlm.html#appendixD
    public class NtlmTools
    {
        public static byte[] GetLmResponse(string password, byte[] challenge)
        {
            var lmHash = LmHash(password);
            return LmResponse(lmHash, challenge);
        }

        public static byte[] GetNtlmResponse(string password, byte[] challenge)
        {
            var ntlmHash = NtlmHash(password);
            return LmResponse(ntlmHash, challenge);
        }

        public static byte[] GetNtlMv2Response(string target, string user,
            string password, byte[] targetInformation, byte[] challenge,
            byte[] clientNonce)
        {
            var ntlmv2Hash = Ntlmv2Hash(target, user, password);
            var blob = CreateBlob(targetInformation, clientNonce);
            return Lmv2Response(ntlmv2Hash, blob, challenge);
        }

        public static byte[] GetLMv2Response(string target, string user,
            string password, byte[] challenge, byte[] clientNonce)
        {
            var ntlmv2Hash = Ntlmv2Hash(target, user, password);
            return Lmv2Response(ntlmv2Hash, clientNonce, challenge);
        }

        public static byte[] GetNtlm2SessionResponse(string password,
            byte[] challenge, byte[] clientNonce)
        {
            var ntlmHash = NtlmHash(password);
            using (var md5 = MD5.Create())
            {
                var buf = new byte[challenge.Length + clientNonce.Length];
                Array.Copy(challenge, 0, buf, 0, challenge.Length);
                Array.Copy(clientNonce, 0, buf, challenge.Length, clientNonce.Length);

                var sessionHash = new byte[8];
                var computeHash = md5.ComputeHash(buf);
                Array.Copy(computeHash, 0, sessionHash, 0, 8);
                return LmResponse(ntlmHash, sessionHash);
            }
        }

        private static byte[] LmHash(string password)
        {
            var oemPassword = Encoding.ASCII.GetBytes(password.ToUpper());
            var length = Math.Min(oemPassword.Length, 14);
            var keyBytes = new byte[14];
            Array.Copy(oemPassword, 0, keyBytes, 0, length);
            var lowKey = CreateDesKey(keyBytes, 0);
            var highKey = CreateDesKey(keyBytes, 7);
            var magicConstant = Encoding.ASCII.GetBytes("KGS!@#$%");

            byte[] lowHash;
            var des1 = new DESCryptoServiceProvider();
            des1.Key = lowKey;
            des1.IV = new byte[8];
            using (var stream = new MemoryStream())
            {
                using (var cryptStream = new CryptoStream(stream,
                    des1.CreateEncryptor(), CryptoStreamMode.Write))
                using (var writer = new BinaryWriter(cryptStream))
                    writer.Write(magicConstant);

                lowHash = stream.ToArray();
            }

            byte[] highHash;
            var des2 = new DESCryptoServiceProvider();
            des2.Key = highKey;
            des2.IV = new byte[8];
            using (var stream = new MemoryStream())
            {
                using (var cryptStream = new CryptoStream(stream,
                    des2.CreateEncryptor(), CryptoStreamMode.Write))
                using (var writer = new BinaryWriter(cryptStream))
                    writer.Write(magicConstant);

                highHash = stream.ToArray();
            }
            var lmHash = new byte[16];
            Array.Copy(lowHash, 0, lmHash, 0, 8);
            Array.Copy(highHash, 0, lmHash, 8, 8);
            return lmHash;
        }

        public static byte[] NtlmHash(string password)
        {
            var unicodePassword = Encoding.Unicode.GetBytes(password);
            using (var md4 = new MD4())
            {
                return md4.ComputeHash(unicodePassword);
            }
        }

        private static byte[] Ntlmv2Hash(string target, string user,
            string password)
        {
            var ntlmHash = NtlmHash(password);
            var identity = user.ToUpper() + target;
            return HmacMd5(Encoding.Unicode.GetBytes(identity), ntlmHash);
        }

        public static byte[] LmResponse(byte[] hash, byte[] challenge)
        {
            var passHashPadded = new byte[21];
            Array.Copy(hash, 0, passHashPadded, 0, hash.Length);
            var keyBytes = new byte[21];
            Array.Copy(hash, 0, keyBytes, 0, 16);
            var lowKey = CreateDesKey(keyBytes, 0);
            var middleKey = CreateDesKey(keyBytes, 7);
            var highKey = CreateDesKey(keyBytes, 14);
            var part1 = DesEncrypt(lowKey, challenge);
            var part2 = DesEncrypt(middleKey, challenge);
            var part3 = DesEncrypt(highKey, challenge);

            var result = new byte[part1.Length + part2.Length + part3.Length];
            Array.Copy(part1, 0, result, 0, part1.Length);
            Array.Copy(part2, 0, result, part1.Length, part2.Length);
            Array.Copy(part3, 0, result, part1.Length + part2.Length, part3.Length);
            return result;
        }


        private static byte[] DesEncrypt(byte[] key, byte[] challenge)
        {
            DES des = new DESCryptoServiceProvider();
            des.Mode = CipherMode.ECB;
            des.Padding = PaddingMode.None;
            des.Key = key;

            using (var ct1 = des.CreateEncryptor())
            {
                var result = ct1.TransformFinalBlock(challenge, 0, challenge.Length);
                des.Clear();
                return result;
            }
        }

        private static byte[] Lmv2Response(byte[] hash, byte[] clientData,
            byte[] challenge)
        {
            var data = new byte[challenge.Length + clientData.Length];
            Array.Copy(challenge, 0, data, 0, challenge.Length);
            Array.Copy(clientData, 0, data, challenge.Length,
                clientData.Length);
            var mac = HmacMd5(data, hash);
            var lmv2Response = new byte[mac.Length + clientData.Length];
            Array.Copy(mac, 0, lmv2Response, 0, mac.Length);
            Array.Copy(clientData, 0, lmv2Response, mac.Length, clientData.Length);
            return lmv2Response;
        }

        private static byte[] CreateBlob(byte[] targetInformation,
            byte[] clientNonce)
        {
            var blobSignature = new byte[]
            {
                0x01, 0x01, 0x00, 0x00
            };
            var reserved = new byte[]
            {
                0x00, 0x00, 0x00, 0x00
            };
            var unknown1 = new byte[]
            {
                0x00, 0x00, 0x00, 0x00
            };
            var unknown2 = new byte[]
            {
                0x00, 0x00, 0x00, 0x00
            };
            long time = DateTime.Now.Millisecond;
            time += 11644473600000l; // milliseconds from January 1, 1601 -> epoch.
            time *= 10000; // tenths of a microsecond.
            // convert to little-endian byte array.
            var timestamp = new byte[8];
            for (var i = 0; i < 8; i++)
            {
                timestamp[i] = (byte)time;
                time >>= 8;
            }
            var blob = new byte[blobSignature.Length + reserved.Length +
                                timestamp.Length + clientNonce.Length +
                                unknown1.Length + targetInformation.Length +
                                unknown2.Length];
            var offset = 0;
            Array.Copy(blobSignature, 0, blob, offset, blobSignature.Length);
            offset += blobSignature.Length;
            Array.Copy(reserved, 0, blob, offset, reserved.Length);
            offset += reserved.Length;
            Array.Copy(timestamp, 0, blob, offset, timestamp.Length);
            offset += timestamp.Length;
            Array.Copy(clientNonce, 0, blob, offset,
                clientNonce.Length);
            offset += clientNonce.Length;
            Array.Copy(unknown1, 0, blob, offset, unknown1.Length);
            offset += unknown1.Length;
            Array.Copy(targetInformation, 0, blob, offset,
                targetInformation.Length);
            offset += targetInformation.Length;
            Array.Copy(unknown2, 0, blob, offset, unknown2.Length);
            return blob;
        }

        private static byte[] HmacMd5(byte[] data, byte[] key)
        {
            var ipad = new byte[64];
            var opad = new byte[64];
            for (var i = 0; i < 64; i++)
            {
                ipad[i] = 0x36;
                opad[i] = 0x5c;
            }
            for (var i = key.Length - 1; i >= 0; i--)
            {
                ipad[i] ^= key[i];
                opad[i] ^= key[i];
            }
            var content = new byte[data.Length + 64];
            Array.Copy(ipad, 0, content, 0, 64);
            Array.Copy(data, 0, content, 64, data.Length);
            var md5 = new MD5CryptoServiceProvider();
            data = md5.ComputeHash(content);
            content = new byte[data.Length + 64];
            Array.Copy(opad, 0, content, 0, 64);
            Array.Copy(data, 0, content, 64, data.Length);
            return md5.ComputeHash(content);
        }

        private static byte[] CreateDesKey(byte[] bytes, int offset)
        {
            var keyBytes = new byte[7];
            Array.Copy(bytes, offset, keyBytes, 0, 7);
            // inserts 0 every 7'th bit
            var material = new byte[8];
            material[0] = (byte)(keyBytes[0] & 0xfe);
            material[1] = (byte)(((keyBytes[0] << 7) | (keyBytes[1] >> 1)) & 0xfe);
            material[2] = (byte)(((keyBytes[1] << 6) | (keyBytes[2] >> 2)) & 0xfe);
            material[3] = (byte)(((keyBytes[2] << 5) | (keyBytes[3] >> 3)) & 0xfe);
            material[4] = (byte)(((keyBytes[3] << 4) | (keyBytes[4] >> 4)) & 0xfe);
            material[5] = (byte)(((keyBytes[4] << 3) | (keyBytes[5] >> 5)) & 0xfe);
            material[6] = (byte)(((keyBytes[5] << 2) | (keyBytes[6] >> 6)) & 0xfe);
            material[7] = (byte)(keyBytes[6] << 1);
            return material;
        }
    }
}