namespace In.Ntlm.Http
{
    public class NtlmType2Msg
    {
        public byte[] Challenge { get; set; }
        public int NegotiateFlags { get; set; }
        public byte[] Name { get; set; }
        public byte[] Info { get; set; }
    }
}