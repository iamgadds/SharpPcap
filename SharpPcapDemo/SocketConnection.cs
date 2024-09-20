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
        private CancellationTokenSource _cancellationTokenSource = new CancellationTokenSource();
        private DateTime _lastPingTime = DateTime.Now;
        private readonly TimeSpan _pingTimeout = TimeSpan.FromSeconds(15);
        private const string ExpectedToken = "9671e20d4fc256efffd56109d09be296556ba39e"; // Set your expected token here
        public void Dispose()
        {
            _webSocket?.Dispose();
            _listener?.Close();
            _cancellationTokenSource.Cancel();
        }


        public async Task StartConnectionAsync()
        {
            _listener = new HttpListener();
            _listener.Prefixes.Add("http://localhost:8080/");
            _listener.Start();
            Console.WriteLine("WebSocket server started at ws://localhost:8080/");


            // Start a task to monitor the ping time
            _ = Task.Run(() => MonitorPingAsync(_cancellationTokenSource.Token));


            while (_cancellationTokenSource != null && !_cancellationTokenSource.Token.IsCancellationRequested)
            {
                try
                {
                    HttpListenerContext context = await _listener.GetContextAsync();
                    Console.WriteLine("Received HTTP request");


                    if (context.Request.IsWebSocketRequest)
                    {


                        // Check if the Sec-WebSocket-Protocol header contains the expected token
                        var tokenHeader = context.Request.Headers["Sec-WebSocket-Protocol"];
                        if (tokenHeader == ExpectedToken)
                        {
                            HttpListenerWebSocketContext webSocketContext = await context.AcceptWebSocketAsync(ExpectedToken); // Return the token in the response header
                            _webSocket = webSocketContext.WebSocket;
                            Console.WriteLine("WebSocket connection established with valid token");


                            // Initialize the last ping time
                            _lastPingTime = DateTime.Now;


                            // Handle WebSocket communication in a separate task
                            _ = Task.Run(() => HandleWebSocketAsync(_webSocket, _cancellationTokenSource.Token));
                        }
                        else
                        {
                            context.Response.StatusCode = 401; // Unauthorized
                            context.Response.Close();
                            Console.WriteLine("Unauthorized WebSocket request rejected");
                        }


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
                    else if (result.MessageType == WebSocketMessageType.Text)
                    {
                        string message = Encoding.UTF8.GetString(buffer, 0, result.Count);
                        Console.WriteLine($"Received message: {message}");


                        // Handle Ping-Pong messages
                        if (message == "ping")
                        {
                            Console.WriteLine("Received 'ping', sending 'pong'...");
                            _lastPingTime = DateTime.Now; // Update last ping time
                            await SendPongAsync(); // Respond with "pong"
                        }
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


        private async Task SendPongAsync()
        {
            if (_webSocket != null && _webSocket.State == WebSocketState.Open)
            {
                byte[] buffer = Encoding.UTF8.GetBytes("pong");
                await _webSocket.SendAsync(new ArraySegment<byte>(buffer), WebSocketMessageType.Text, true, CancellationToken.None);
                Console.WriteLine("Sent 'pong'");
            }
        }


        private async Task MonitorPingAsync(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                if (DateTime.Now - _lastPingTime > _pingTimeout)
                {
                    Console.WriteLine("No 'ping' received in the last 10 seconds. Shutting down...");
                    OnApplicationExit(); // Gracefully exit the app
                    break;
                }


                await Task.Delay(1000, token); // Check every second
            }
        }


        private void OnApplicationExit()
        {
            _cancellationTokenSource.Cancel();
            Console.WriteLine("Shutting down...");
            Environment.Exit(0); // Terminate the application
        }
    }
}