Network Packet Capture Application
This application is designed to capture network packets and measure network speed. It supports both Windows and macOS with separate implementations for each platform using different libraries. The application communicates with an Electron app over WebSocket, using token-based authentication to ensure secure connections.

Features
Captures network packets using SharpPcap for Windows and libpcap for macOS.
Measures network upload and download speeds.
Communicates with Electron app via WebSocket.
Monitors and auto-restarts packet capture after interruptions (e.g., system sleep).
Token-based WebSocket authentication for secure communication.
Prerequisites
Windows:
.NET 6.0 SDK or later: Download .NET
SharpPcap library: Already included in the project.
Admin privileges: The application may require elevated privileges to access network devices.
macOS:
.NET 6.0 SDK or later: Download .NET
libpcap: Installed by default on macOS.
Admin privileges: May require elevated privileges to access network devices.
Installation
Windows
Clone the repository to your local machine:

bash
Copy code
git clone https://github.com/your-username/your-repo.git
Navigate to the project folder:

bash
Copy code
cd your-repo/NetworkPacketCaptureApp
Open the solution in Visual Studio or another IDE that supports .NET projects.

Restore the dependencies:

bash
Copy code
dotnet restore
Build the project:

bash
Copy code
dotnet build
Run the application:

bash
Copy code
dotnet run
If you wish to create a self-contained executable, run:

bash
Copy code
dotnet publish -c Release -r win-x64 --self-contained
Ensure that you have the necessary permissions to capture network packets:

Run the application with admin privileges.
macOS
Clone the repository to your local machine:

bash
Copy code
git clone https://github.com/your-username/your-repo.git
Navigate to the project folder:

bash
Copy code
cd your-repo/NetworkPacketCaptureApp
Restore the dependencies:

bash
Copy code
dotnet restore
Build the project:

bash
Copy code
dotnet build
Run the application:

bash
Copy code
dotnet run
To create a self-contained build:

bash
Copy code
dotnet publish -c Release -r osx-x64 --self-contained
Permissions for macOS:

You may need to give the application permissions to bypass security checks as follows:
Open System Preferences > Security & Privacy > General.
Click "Allow" to enable the app after the first launch error.
If you encounter the error "cannot be opened because the developer cannot be verified", use the following command in the terminal to remove the quarantine:

bash
Copy code
xattr -d com.apple.quarantine /path/to/your/build/SharpPcapDemo
Running the Application
Windows and macOS:
Ensure the Electron app is running before starting this application.
This application will connect to the Electron app via WebSocket.
The application requires a valid token in the Sec-WebSocket-Protocol header for the WebSocket connection.
Example token format: Bearer your-token-here
To run the application:
bash
Copy code
dotnet run
WebSocket Security
The WebSocket connection is secured using token-based authentication. Only the Electron app with the valid token in the Sec-WebSocket-Protocol header can establish a connection.

The token should be provided by the Electron app when it connects to the C# application.
Example Request from Electron (JavaScript):
javascript
Copy code
const ws = new WebSocket('ws://localhost:8080', ['Bearer your-token-here']);
Troubleshooting
If the application fails to start capturing packets, ensure you are running with admin privileges.
On macOS, if you see a security error, make sure to manually allow the app in the Security & Privacy settings.
If you encounter issues with the WebSocket connection, verify that the token is correctly formatted and sent in the header.
This README.md should help users understand how to install, run, and troubleshoot the application for both Windows and macOS environments. Let me know if you want to adjust any of the details!
