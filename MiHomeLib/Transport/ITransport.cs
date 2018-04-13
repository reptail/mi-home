using System.Threading.Tasks;
using MiHomeLib.Commands;

namespace MiHomeLib.Transport
{
    public interface ITransport
    {
        void Dispose();
        Task<string> ReceiveAsync();
        int SendCommand(Command command);
        int SendWriteCommand(string sid, string type, Command data);
        void SetToken(string token);
    }
}