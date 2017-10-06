using System;
using System.IO;
using System.Text;

namespace In.Ntlm.Http
{
    // https://github.com/SamDecrock/node-http-ntlm/blob/master/ntlm.js
    public class NtlmNode
    {
        private const uint NTLM_NegotiateUnicode = 0x00000001;
        private const uint NTLM_NegotiateOEM = 0x00000002;
        private const uint NTLM_RequestTarget = 0x00000004;
        private const uint NTLM_Unknown9 = 0x00000008;
        private const uint NTLM_NegotiateSign = 0x00000010;
        private const uint NTLM_NegotiateSeal = 0x00000020;
        private const uint NTLM_NegotiateDatagram = 0x00000040;
        private const uint NTLM_NegotiateLanManagerKey = 0x00000080;
        private const uint NTLM_Unknown8 = 0x00000100;
        private const uint NTLM_NegotiateNTLM = 0x00000200;
        private const uint NTLM_NegotiateNTOnly = 0x00000400;
        private const uint NTLM_Anonymous = 0x00000800;
        private const uint NTLM_NegotiateOemDomainSupplied = 0x00001000;
        private const uint NTLM_NegotiateOemWorkstationSupplied = 0x00002000;
        private const uint NTLM_Unknown6 = 0x00004000;
        private const uint NTLM_NegotiateAlwaysSign = 0x00008000;
        private const uint NTLM_TargetTypeDomain = 0x00010000;
        private const uint NTLM_TargetTypeServer = 0x00020000;
        private const uint NTLM_TargetTypeShare = 0x00040000;
        private const uint NTLM_NegotiateExtendedSecurity = 0x00080000;
        private const uint NTLM_NegotiateIdentify = 0x00100000;
        private const uint NTLM_Unknown5 = 0x00200000;
        private const uint NTLM_RequestNonNTSessionKey = 0x00400000;
        private const uint NTLM_NegotiateTargetInfo = 0x00800000;
        private const uint NTLM_Unknown4 = 0x01000000;
        private const uint NTLM_NegotiateVersion = 0x02000000;
        private const uint NTLM_Unknown3 = 0x04000000;
        private const uint NTLM_Unknown2 = 0x08000000;
        private const uint NTLM_Unknown1 = 0x10000000;
        private const uint NTLM_Negotiate128 = 0x20000000;
        private const uint NTLM_NegotiateKeyExchange = 0x40000000;
        private const uint NTLM_Negotiate56 = 0x80000000;

        private const uint NTLM_TYPE1_FLAGS = NTLM_NegotiateUnicode
                                              + NTLM_NegotiateOEM
                                              + NTLM_RequestTarget
                                              + NTLM_NegotiateNTLM
                                              + NTLM_NegotiateOemDomainSupplied
                                              + NTLM_NegotiateOemWorkstationSupplied
                                              + NTLM_NegotiateAlwaysSign
                                              + NTLM_NegotiateExtendedSecurity
                                              + NTLM_NegotiateVersion
                                              + NTLM_Negotiate128
                                              + NTLM_Negotiate56;

        private const uint NTLM_TYPE2_FLAGS = NTLM_NegotiateUnicode
                                              + NTLM_RequestTarget
                                              + NTLM_NegotiateNTLM
                                              + NTLM_NegotiateAlwaysSign
                                              + NTLM_NegotiateExtendedSecurity
                                              + NTLM_NegotiateTargetInfo
                                              + NTLM_NegotiateVersion
                                              + NTLM_Negotiate128
                                              + NTLM_Negotiate56;

        private static readonly Random _random = new Random();
        private static readonly byte[] _protocol = Encoding.ASCII.GetBytes("NTLMSSP\0");

        public static string CreateType1Message(string domain, string workstation)
        {
            var domainBytes = domain != null ? Encoding.ASCII.GetBytes(domain.ToUpper()) : new byte[0] { };
            var workstationBytes = workstation != null ? Encoding.ASCII.GetBytes(workstation.ToUpper()) : new byte[0] { };

            const uint BODY_LENGTH = 40;

            var type1Flags = NTLM_TYPE1_FLAGS;
            if (string.IsNullOrEmpty(domain))
                type1Flags = type1Flags - NTLM_NegotiateOemDomainSupplied;

            using (var memory = new MemoryStream())
            using (var buf = new BinaryWriter(memory, Encoding.ASCII))
            {
                buf.Write(_protocol);
                buf.Write((uint)1);
                buf.Write(type1Flags);

                buf.Write((ushort)domainBytes.Length);
                buf.Write((ushort)domainBytes.Length);
                buf.Write(BODY_LENGTH + (uint)workstationBytes.Length);

                buf.Write((ushort)workstationBytes.Length);
                buf.Write((ushort)workstationBytes.Length);
                buf.Write(BODY_LENGTH);

                buf.Write((byte)5);
                buf.Write((byte)1);
                buf.Write((ushort)2600);

                buf.Write((byte)0);
                buf.Write((byte)0);
                buf.Write((byte)0);
                buf.Write((byte)15);

                buf.Write(workstationBytes); // workstation string
                buf.Write(domainBytes); // domain string

                var inArray = memory.ToArray();
                return "NTLM " + Convert.ToBase64String(inArray);
            }
        }

        public static NtlmType2Msg ParseType2Message(string rawmsg)
        {
            var bytes = Convert.FromBase64String(rawmsg);
            using (var memory = new MemoryStream(bytes))
            using (var buf = new BinaryReader(memory, Encoding.ASCII))
            {
                memory.Position += 8;
                //var signature = buf.ReadBytes(8);
                var type = buf.ReadUInt32();

                if (type != 2)
                {
                    return null;
                }
                memory.Position += 2;
                //var targetNameLen = buf.ReadUInt16();
                var targetNameMaxLen = buf.ReadUInt16();
                var targetNameOffset = buf.ReadUInt32();

                var negotiateFlags = buf.ReadInt32();
                var serverChallenge = buf.ReadBytes(8);
                memory.Position += 8;
                //var reserved = buf.ReadBytes(8);

                memory.Position += 2;
                //var targetInfoLen = buf.ReadUInt16();
                var targetInfoMaxLen = buf.ReadUInt16();
                var targetInfoOffset = buf.ReadUInt32();

                var targetName = new byte[targetNameMaxLen];
                Array.Copy(bytes, targetNameOffset, targetName, 0, targetNameMaxLen);
                var targetInfo = new byte[targetInfoMaxLen];
                Array.Copy(bytes, targetInfoOffset, targetInfo, 0, targetInfoMaxLen);
                return new NtlmType2Msg
                {
                    Challenge = serverChallenge,
                    NegotiateFlags = negotiateFlags,
                    Info = targetInfo,
                    Name = targetName
                };
            }
        }

        public static string CreateType3Message(string userName, string password, int negotiateFlags, string domain, string workstation, byte[] serverChallenge)
        {
            var isUnicode = negotiateFlags & NTLM_NegotiateUnicode;
            var isNegotiateExtendedSecurity = negotiateFlags & NTLM_NegotiateExtendedSecurity;
            const int BODY_LENGTH = 72;
            byte[] workstationBytes;
            byte[] domainNameBytes;
            byte[] usernameBytes;
            //byte[] encryptedRandomSessionKeyBytes = new byte[0];
            if (isUnicode > 0)
            {
                workstationBytes = Encoding.Unicode.GetBytes(workstation);
                domainNameBytes = Encoding.Unicode.GetBytes(domain);
                usernameBytes = Encoding.Unicode.GetBytes(userName);
            }
            else
            {
                workstationBytes = Encoding.ASCII.GetBytes(workstation);
                domainNameBytes = Encoding.ASCII.GetBytes(domain);
                usernameBytes = Encoding.ASCII.GetBytes(userName);
            }
            byte[] lmPass;
            byte[] ntPass;

            if (isNegotiateExtendedSecurity > 0)
            {
                var clientChallengeBytes = new byte[8];
                FillRandom(clientChallengeBytes);
                ntPass = NtlmTools.GetNtlm2SessionResponse(password, serverChallenge, clientChallengeBytes);
                lmPass = new byte[clientChallengeBytes.Length + 16];
                Array.Copy(clientChallengeBytes, 0, lmPass, 0, clientChallengeBytes.Length);
            }
            else
            {
                lmPass = NtlmTools.GetLmResponse(password, serverChallenge);
                ntPass = NtlmTools.GetNtlmResponse(password, serverChallenge);
            }
            byte[] buffer = new byte[BODY_LENGTH + domainNameBytes.Length + usernameBytes.Length + workstationBytes.Length + ntPass.Length + lmPass.Length /* + encryptedRandomSessionKeyBytes.Length*/];
            using (var memory = new MemoryStream(buffer))
            using (var buf = new BinaryWriter(memory, Encoding.ASCII))
            {
                buf.Write(_protocol);
                buf.Write((uint) 3);

                buf.Write((ushort) lmPass.Length);
                buf.Write((ushort) lmPass.Length);
                buf.Write((uint) (BODY_LENGTH + domainNameBytes.Length + usernameBytes.Length + workstationBytes.Length));

                buf.Write((ushort) ntPass.Length);
                buf.Write((ushort) ntPass.Length);
                buf.Write(
                    (uint)
                    (BODY_LENGTH + domainNameBytes.Length + usernameBytes.Length + workstationBytes.Length +
                     lmPass.Length));

                buf.Write((ushort) domainNameBytes.Length);
                buf.Write((ushort) domainNameBytes.Length);
                buf.Write((uint) BODY_LENGTH);

                buf.Write((ushort) usernameBytes.Length);
                buf.Write((ushort) usernameBytes.Length);
                buf.Write((uint) (BODY_LENGTH + domainNameBytes.Length));

                buf.Write((ushort) workstationBytes.Length);
                buf.Write((ushort) workstationBytes.Length);
                buf.Write((uint) (BODY_LENGTH + domainNameBytes.Length + usernameBytes.Length));

                buf.Write((ushort) 0);
                buf.Write((ushort) 0);
                buf.Write(
                    (uint)
                    (BODY_LENGTH + domainNameBytes.Length + usernameBytes.Length + workstationBytes.Length +
                     ntPass.Length + lmPass.Length));
                //buf.Write((ushort)encryptedRandomSessionKeyBytes.Length);
                //buf.Write((ushort)encryptedRandomSessionKeyBytes.Length);
                //buf.Write((uint)(BODY_LENGTH + domainNameBytes.Length + usernameBytes.Length + workstationBytes.Length + ntPass.Length + lmPass.Length));

                buf.Write(NTLM_TYPE2_FLAGS);
                buf.Write((byte) 5);
                buf.Write((byte) 1);
                buf.Write((ushort) 260);
                buf.Write((byte) 0);
                buf.Write((byte) 0);
                buf.Write((byte) 0);
                buf.Write((byte) 15);

                buf.Write(domainNameBytes);
                buf.Write(usernameBytes);
                buf.Write(workstationBytes);
                buf.Write(lmPass);
                buf.Write(ntPass);

                return "NTLM " + Convert.ToBase64String(memory.ToArray());
            }
        }

        private static void FillRandom(byte[] buffer)
        {
            lock (_random)
            {
                _random.NextBytes(buffer);
            }
        }
    }
}
