using Newtonsoft.Json;
using System.Net;
using System.Net.WebSockets;
using System.Text;

namespace SharpPcapDemo
{
    public class SocketConnection : IDisposable
    {
        private HttpListener? _listener;
        private WebSocket? _webSocket;
        private CancellationTokenSource? _cancellationTokenSource;

        public void Dispose()
        {
            _cancellationTokenSource?.Cancel();
            _webSocket?.Dispose();
            _listener?.Close();
        }

        public async Task StartConnectionAsync()
        {
            _listener = new HttpListener();
            _listener.Prefixes.Add("http://localhost:8080/");
            _listener.Start();
            Console.WriteLine("WebSocket server started at ws://localhost:8080/");
            _cancellationTokenSource = new CancellationTokenSource();

            while (!_cancellationTokenSource.Token.IsCancellationRequested)
            {
                try
                {
                    HttpListenerContext context = await _listener.GetContextAsync();
                    if (context.Request.IsWebSocketRequest)
                    {
                        HttpListenerWebSocketContext webSocketContext = await context.AcceptWebSocketAsync(null);
                        _webSocket = webSocketContext.WebSocket;
                        Console.WriteLine("WebSocket connection established");
                        break;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error accepting WebSocket connection: {ex.Message}");
                }
            }
        }

        public async Task SendDataAsync(object data)
        {
            if (_webSocket != null && _webSocket.State == WebSocketState.Open)
            {
                try
                {
                    string jsonData = JsonConvert.SerializeObject(data);
                    byte[] buffer = Encoding.UTF8.GetBytes(jsonData);
                    await _webSocket.SendAsync(new ArraySegment<byte>(buffer), WebSocketMessageType.Text, true, CancellationToken.None);
                }
                catch (WebSocketException ex)
                {
                    Console.WriteLine($"WebSocket error: {ex.Message}");
                    // Handle WebSocket error (e.g., attempt to reconnect or notify the user)
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error sending data: {ex.Message}");
                }
            }
            else
            {
                Console.WriteLine("WebSocket is not in an open state.");
            }
        }
    }
}
