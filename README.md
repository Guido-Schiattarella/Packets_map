# Packets Map - A Real-Time Network Packet Visualizer

Packets Map is a desktop application that captures network packets on your machine in real-time, identifies the geographical location of the remote servers, and visualizes the communication on an interactive world map. It provides a detailed view of your computer's network activity, showing you where in the world your data is going to and coming from.

## Features

- **Real-Time Packet Sniffing**: Captures live network traffic using `pyshark`.
- **IP Geolocation**: Enriches packet data with geographical information (country, city, coordinates) using the `ipinfo.io` API.
- **Interactive Map Visualization**: Displays servers as markers on a dark-themed world map powered by Leaflet.js.
- **Detailed Information Panels**:
  - Click on a server marker to view detailed information, including IP address, location, and the server's organization.
  - Double-click a marker to open a log of all packets exchanged with that server.
- **Server Clustering**: Groups multiple servers at the same physical location under a single map marker, allowing you to cycle through them.
- **Dynamic UI**: The interface is built with HTML, CSS, and JavaScript, providing a rich and responsive user experience within a Python application.
- **Concurrent Processing**: Uses a producer-consumer threading model to ensure smooth performance, separating the packet capture process from the UI updates.

## How It Works

The application operates on a producer-consumer architecture:

1. **The Producer (`sniffer.py`)**: A dedicated thread continuously sniffs network packets from a specified network interface. It filters for relevant IP packets, ignoring local traffic. For each packet involving a remote server, it uses the `ipinfo.io` API to fetch geolocation and organization details. This information is then placed into a shared buffer.

2. **The Consumer (`main.py`)**: The main thread reads packet data from the buffer. It processes this data and forwards it to the front-end.

3. **The Interface (`map_template.html`, `map.py`)**: The application uses `pywebview` to create a desktop window that renders an HTML file. The consumer thread injects the packet data into the webview by executing a JavaScript function (`addMarker`). This JavaScript code, using the Leaflet.js library, is responsible for creating, updating, and managing the server markers and interactive panels on the map.

## Getting Started

To get the application up and running, follow these steps.

### Prerequisites

- **Python 3**: Make sure you have Python 3 installed.
- **Wireshark**: The `pyshark` library is a wrapper for **TShark**, which is the command-line interface for Wireshark. You must install Wireshark on your system. You can download it from [wireshark.org](https://www.wireshark.org/download.html).

### Installation

1. **Clone the repository:**

   For Linux
   
   ```bash
   git clone https://github.com/Guido-Schiattarella/Packets_map.git
   cd Packets_map
   
   ```

   For Windows

   ```bash
   git clone https://github.com/Guido-Schiattarella/Packets_map.git
   cd Packets_map\windows
   
   ```

1. **Install Python dependencies:**
   It is recommended to use a virtual environment.

   ```bash
   # Create and activate a virtual environment (optional but recommended)
   python -m venv venv
   source venv/bin/activate

   # Create and activate a virtual environment in Windows powershell (optional but recommended)
   python -m venv venv
   .\venv\Scripts\Activate.ps1

   # Install the required libraries for linux
   pip install pyshark ipinfo netifaces ipaddress pywebview

   #Install the required libraries for windows
   python -m pip install -U pip
   python -m pip install --only-binary=:all: netifaces-plus
   pip install pyshark ipinfo ipaddress pywebview
   

   ```

### Configuration For Linux

Before running the application, you **must** configure the sniffer script (`sniffer.py`):

1. **Set the Network Interface**:
   Open `sniffer.py` and find the `interface` variable. Change its value to the name of the network interface you want to monitor (e.g., `eth0` for Ethernet, `wlan0` or `en0` for Wi-Fi).

   ```python
   # sniffer.py

   ########################################
   ## INSERT HERE YOUR NETWORK INTERFACE ##
   ########################################
   interface = 'your_interface_name_here' # e.g., 'wlp0s20f3', 'eth0'
   
   ```

2. **Set your IPinfo API Token**:
   The application uses `ipinfo.io` to get geolocation data. You will need a free API token.

   - Sign up at [ipinfo.io](https://ipinfo.io/signup).
   - Copy your access token from your dashboard.
   - Open `sniffer.py` and paste your token into the `token` variable.

   ```python
   # sniffer.py

   ###################################
   ## INSERT HERE YOUR IPINFO TOKEN ##
   ###################################
   token = 'your_ipinfo_token_here'
   
   ```

### Configuration For Windows

Before running the application, you **must** configure the sniffer script (`sniffer.py`):

1. **Set the Network Interface**:
   Open `sniffer.py` and find the `INTERFACE_FOR_PYSHARK` variable. Change its value to the name of the network interface you want to monitor.

   ```python
   # sniffer.py

   ########################################
   ## INSERT HERE YOUR NETWORK INTERFACE ##
   ########################################
   INTERFACE_FOR_PYSHARK = 'your_interface_name_here' 
   
   ```
   
2. **Set your Network Interface GUID for Natifaces**:
   Open `sniffer.py` and find the `INTERFACE_GUID_FOR_NETIFACES` variable. Change its value to the firs (or the other one) curly brackets of the Network Interface GUID command output
   
   ```python
   # sniffer.py
   
   #####################################################
   ## INSET HERE YOUR NETWORK INTERFACE FOR NATIFACES ##
   #####################################################

   INTERFACE_GUID_FOR_NETIFACES = '{your_alphanumeric_string}'
   
   ```  

3. **Set your IPinfo API Token**:
   The application uses `ipinfo.io` to get geolocation data. You will need a free API token.

   - Sign up at [ipinfo.io](https://ipinfo.io/signup).
   - Copy your access token from your dashboard.
   - Open `sniffer.py` and paste your token into the `IPINFO_TOKEN` variable.

   ```python
   # sniffer.py

   ###################################
   ## INSERT HERE YOUR IPINFO TOKEN ##
   ###################################
   IPINFO_TOKEN = 'your_ipinfo_token_here'
   
   ```


## Usage

Once the prerequisites are installed and the configuration is complete, run the application from the main directory:

```bash
python main.py

```

The application window will open, displaying the world map. As you browse the internet or as background services make network requests, you will see markers appear on the map in real-time.

- **Hover** over a marker to see a quick summary.
- **Single-click** a marker to open the "SERVER DETAILS" panel on the right.
- **Double-click** a marker to open the "PACKETS LOG" panel on the left.
- **Click** anywhere on the map to close the panels.

## File Structure

```
packets-map/
   └── windows/
       ├── main.py              # Main entry point and thread management (windows)
       ├── sniffer.py          # Packet capture and geolocation logic (windows)
       ├── map.py              # Bridge between backend and frontend (windows)
       ├── map_template.html   # HTML interface with Leaflet.js map (windows)
       └── stile.css          # Stylesheet with dark theme (windows)
├── main.py              # Main entry point and thread management
├── sniffer.py          # Packet capture and geolocation logic
├── map.py              # Bridge between backend and frontend
├── map_template.html   # HTML interface with Leaflet.js map
├── stile.css          # Stylesheet with dark theme
└── README.md          # This documentation

```

## File Descriptions

- **`main.py`**: The main entry point of the application. It initializes the `pywebview` window and manages the producer and consumer threads for packet processing.
- **`sniffer.py`**: Contains the core packet sniffing logic. It uses `pyshark` to capture packets and `ipinfo` to retrieve geolocation data.
- **`map.py`**: Acts as the bridge between the back-end sniffer and the front-end map. It receives packet data and calls the appropriate JavaScript functions in the webview.
- **`map_template.html`**: The HTML file that defines the structure of the user interface. It includes the Leaflet.js map, information panels, and all the client-side JavaScript for handling map interactions.
- **`stile.css`**: The stylesheet for the application, defining the dark, futuristic theme for all UI elements.

## How to Find Your Network Interface

### Linux
```bash
ip link show
# or
ifconfig

```

### Windows  
Open power shell and paste this command (change `tshark.exe` path with your `tshark.exe` path) 

```powershell
C:\Program Files\Wireshark\tshark.exe -D

```  
  
Copy the entire string corresponding to the desired network interface name, up to and including the }  
 


## To take your Network Interface GUID  
  
Open power shell and paste this command  

```powershell
python -c "import netifaces, pprint; from pprint import pprint as p; p(netifaces.interfaces()); print({i: netifaces.ifaddresses(i) for i in netifaces.interfaces()})"

```

## Troubleshooting

### Common Issues

1. **Permission Denied Error**:
   ### Linux
   
   ```bash
   sudo python main.py
   
   ```
   ### Windows
   
   run cmd as administrator

   ```bash
   python .\main.py
   
   ```

3. **Interface Not Found**:
   - Double-check your interface name
   - Ensure the interface is active and connected

4. **No Packets Appearing**:
   - Verify Wireshark/TShark installation
   - Check if your IPinfo token is valid
   - Ensure you have active internet traffic

5. **Map Template Not Found**:
   - Verify `map_template.html` is in the same directory as `main.py`

## Security and Legal Considerations

⚠️ **Important**: This application monitors network traffic. Please ensure:

- You only monitor networks you own or have explicit permission to monitor
- Compliance with local laws and regulations regarding network monitoring
- Appropriate security measures for any captured data
- Understanding of privacy implications

## Dependencies

- `pyshark` - Network packet analysis
- `ipinfo` - IP geolocation services
- `netifaces` - Network interface information
- `pywebview` - Desktop web application framework
- `requests` - HTTP library
- `ipaddress` - IP address manipulation

## License

This project is intended for educational and authorized network monitoring purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.

## Support

For issues and support:
- Check the troubleshooting section above
- Ensure all prerequisites are properly installed
- Verify your configuration matches the requirements
