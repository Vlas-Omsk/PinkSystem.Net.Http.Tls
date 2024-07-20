using System.Text;

namespace BotsCommon.Net.Http.Tls
{
    public static class StringBuilderExtensions
    {
        private static readonly string _httpLine = "\r\n";

        public static void AppendHttpLine(this StringBuilder self)
        {
            self.Append(_httpLine);
        }
    }
}
