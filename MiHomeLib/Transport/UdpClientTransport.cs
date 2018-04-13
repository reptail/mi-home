using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System;
using System.IO;
using Newtonsoft.Json.Linq;
using System.Security.Cryptography;
using MiHomeLib.Commands;
using Newtonsoft.Json;

namespace MiHomeLib.Transport
{
    public class UdpClientTransport : IDisposable, ITransport
    {
        private readonly string _gatewayWritePassword;
        private readonly string _multicastAddress;
        private readonly int _serverPort;
        private readonly UdpClient _udpClient;

        private readonly byte[] _initialVector =
            {0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28, 0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58, 0x56, 0x2e};

        private static string _currentToken;

        public UdpClientTransport(string gatewayWritePassword, string multicastAddress = "224.0.0.50", int serverPort = 9898)
        {
            _gatewayWritePassword = gatewayWritePassword;
            _multicastAddress = multicastAddress;
            _serverPort = serverPort;

            _udpClient = new UdpClient();
            _udpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            _udpClient.Client.Bind(new IPEndPoint(IPAddress.Any, serverPort));
            _udpClient.JoinMulticastGroup(IPAddress.Parse(multicastAddress));
        }

        private static string GetWriteKey(byte[] key, byte[] iv)
        {
            byte[] encrypted;
            
            using (var aesCbc128 = Aes.Create())
            {
                aesCbc128.KeySize = 128;
                aesCbc128.BlockSize = 128;
                aesCbc128.IV = iv;
                aesCbc128.Key = key;
                aesCbc128.Mode = CipherMode.CBC;
                aesCbc128.Padding = PaddingMode.None;

                var encryptor = aesCbc128.CreateEncryptor(aesCbc128.Key, aesCbc128.IV);

                using (var ms = new MemoryStream())
                {
                    using (var cryptoStream = new StreamWriter(new CryptoStream(ms, encryptor, CryptoStreamMode.Write)))
                    {
                        cryptoStream.Write(_currentToken);
                    }

                    encrypted = ms.ToArray();
                }
            }
            
            return BitConverter.ToString(encrypted).Replace("-", string.Empty);
        }

        public int SendCommand(Command command)
        {
            return SendCommand(command.ToString());
        }

        private int SendCommand(string data)
        {
            byte[] buffer = Encoding.ASCII.GetBytes(data);

            return _udpClient.SendAsync(buffer, buffer.Length, new IPEndPoint(IPAddress.Parse(_multicastAddress), _serverPort))
                .GetAwaiter()
                .GetResult();
        }

        public int SendWriteCommand(string sid, string type, Command data)
        {
            if(_gatewayWritePassword == null) throw new Exception("You cannot send commands to gateway without password");

            while (true)
            {
                if (_currentToken == null)
                {
                    Task.Delay(5000).Wait(); // gateway may not send us correct write token till the time, so waiting for here
                    continue;
                }

                var jObj = JObject.Parse(data.ToString());

                jObj["key"] = GetWriteKey(Encoding.ASCII.GetBytes(_gatewayWritePassword), _initialVector);

                return SendCommand(new WriteCommand(sid, type, JsonConvert.SerializeObject(jObj.ToString(Formatting.None))));
            }
        }

        public async Task<string> ReceiveAsync()
        {
            UdpReceiveResult result = await _udpClient.ReceiveAsync();            

            return Encoding.ASCII.GetString(result.Buffer);
        }

        public void Dispose()
        {
            _udpClient?.DropMulticastGroup(IPAddress.Parse(_multicastAddress));
            _udpClient?.Client?.Shutdown(SocketShutdown.Both);
            _udpClient?.Dispose();
        }

        public void SetToken(string token)
        {
            _currentToken = token;
        }
    }
}