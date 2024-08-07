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
        private CancellationTokenSource? _cancellationTokenSource = new CancellationTokenSource();

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

            while (!_cancellationTokenSource.Token.IsCancellationRequested)
            {
                try
                {
                    HttpListenerContext context = await _listener.GetContextAsync();
                    Console.WriteLine("Received HTTP request");

                    if (context.Request.IsWebSocketRequest)
                    {
                        HttpListenerWebSocketContext webSocketContext = await context.AcceptWebSocketAsync(null);
                        _webSocket = webSocketContext.WebSocket;
                        Console.WriteLine("WebSocket connection established");

                        // Handle WebSocket communication in a separate task
                        _ = Task.Run(() => HandleWebSocketAsync(_webSocket, _cancellationTokenSource.Token));
                    }
                    else
                    {
                        context.Response.StatusCode = 400;
                        context.Response.Close();
                        Console.WriteLine("Non-WebSocket request rejected");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error in connection loop: {ex.Message}");
                }
            }
        }

        private async Task HandleWebSocketAsync(WebSocket webSocket, CancellationToken token)
        {
            var buffer = new byte[1024 * 4];
            WebSocketReceiveResult result;

            try
            {
                while (webSocket.State == WebSocketState.Open && !token.IsCancellationRequested)
                {
                    result = await webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), token);
                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closing", token);
                        Console.WriteLine("WebSocket connection closed by client");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"WebSocket error: {ex.Message}");
            }
            finally
            {
                webSocket?.Dispose();
                Console.WriteLine("WebSocket disposed");
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
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error sending data: {ex.Message}");
                }
            }
            else
            {
                Console.WriteLine("WebSocket is not open. Cannot send data.");
            }
        }
    }
}
