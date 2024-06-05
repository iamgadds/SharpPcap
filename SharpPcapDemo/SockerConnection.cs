using System;
using System.Net.WebSockets;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace SharpPcapDemo
{
    public class SockerConnection : IDisposable
    {
        private HttpListener _listener;
        private WebSocket _webSocket;

        public void Dispose()
        {
            _webSocket?.Dispose();
            _listener?.Close();
        }

        public async Task StartConnectionAsync()
        {
            _listener = new HttpListener();
            _listener.Prefixes.Add("http://localhost:8080/");
            _listener.Start();
            Console.WriteLine("WebSocket server started at ws://localhost:8080/");

            while (true)
            {
                HttpListenerContext context = await _listener.GetContextAsync();
                if (context.Request.IsWebSocketRequest)
                {
                    HttpListenerWebSocketContext webSocketContext = await context.AcceptWebSocketAsync(null);
                    _webSocket = webSocketContext.WebSocket;
                    break;
                }
            }
        }

        public async Task SendDataAsync(object data)
        {
            if (_webSocket != null && _webSocket.State == WebSocketState.Open)
            {
                string jsonData = JsonConvert.SerializeObject(data);
                byte[] buffer = Encoding.UTF8.GetBytes(jsonData);
                await _webSocket.SendAsync(new ArraySegment<byte>(buffer), WebSocketMessageType.Text, true, CancellationToken.None);
            }
        }
    }
}
