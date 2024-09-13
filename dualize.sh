#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status

# Variables
APP_DIR="/opt/dualize"
SERVICE_NAME="dualize"
GO_VERSION="1.20.5"
GO_TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"
GO_URL="https://dl.google.com/go/${GO_TARBALL}"
IP_ADDRESS=$(hostname -I | awk '{print $1}')
INSTALL_DIR="/usr/local/bin"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# Function to install Go
install_go() {
    echo "Installing Go..."
    wget -q $GO_URL
    sudo tar -C /usr/local -xzf $GO_TARBALL
    rm $GO_TARBALL
    export PATH=/usr/local/go/bin:$PATH
    if ! grep -q "/usr/local/go/bin" "$HOME/.profile"; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> "$HOME/.profile"
    fi
    echo "Go installed successfully."
}

# Check if Go is installed and version is correct
if ! command -v go &> /dev/null || [[ "$(go version)" != *"go${GO_VERSION}"* ]]; then
    echo "Go is not installed or version is incorrect."
    install_go
else
    echo "Go is already installed and up-to-date."
fi

# Ensure Go path is in current session
export PATH=/usr/local/go/bin:$PATH

# Create application directory
sudo mkdir -p "$APP_DIR/templates"
sudo chown -R "$USER":"$USER" "$APP_DIR"

# Navigate to application directory
cd "$APP_DIR"

# Create main Go file
cat > dualize.go <<'EOL'
package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
	psNet "github.com/shirou/gopsutil/net"
	"golang.org/x/crypto/ssh"
)

// Struct for storing API data for Datacenter info
type GeoIP struct {
	Org string `json:"org"`
}

// Check if username and password are correct using SSH
func validateUser(username, password string) bool {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	// Try to connect to SSH on localhost
	client, err := ssh.Dial("tcp", "localhost:22", config)
	if err != nil {
		return false
	}
	defer client.Close()
	return true
}

// Format bytes to KB, MB, GB, etc.
func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// Function to get datacenter information from IP API
func getDatacenterInfo() string {
	resp, err := http.Get("https://ipinfo.io/json")
	if err != nil {
		return "Unknown"
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "Unknown"
	}

	var geoIP GeoIP
	if err := json.Unmarshal(body, &geoIP); err != nil {
		return "Unknown"
	}
	return strings.TrimSpace(geoIP.Org)
}

// Function to get system info
func getSystemInfo() map[string]interface{} {
	info := make(map[string]interface{})

	// CPU usage and information
	cpuUsage, _ := cpu.Percent(0, true)
	cpuCores, _ := cpu.Counts(true)
	cpuInfo, _ := cpu.Info()

	// Check if we have at least one CPU
	cpuModel := "Unknown"
	if len(cpuInfo) > 0 {
		cpuModel = cpuInfo[0].ModelName
	}

	info["cpu"] = map[string]interface{}{
		"model": cpuModel,
		"cores": cpuCores,
		"usage": cpuUsage,
	}

	// Memory usage
	vmStat, _ := mem.VirtualMemory()
	info["memory"] = map[string]interface{}{
		"total":        vmStat.Total / 1024 / 1024, // MB
		"free":         vmStat.Free / 1024 / 1024,  // MB
		"used_percent": vmStat.UsedPercent,
	}

	// Network stats
	netStat, _ := psNet.IOCounters(true)
	mainIface, mainIP := getMainInterface()
	for _, iface := range netStat {
		if iface.Name == mainIface {
			info["network"] = map[string]interface{}{
				"name":          iface.Name,
				"bytes_sent":    formatBytes(iface.BytesSent),
				"bytes_recv":    formatBytes(iface.BytesRecv),
				"total_traffic": formatBytes(iface.BytesSent + iface.BytesRecv),
				"ip":            mainIP,
			}
			break
		}
	}

	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "Unknown"
	}

	// Get Datacenter info
	datacenter := getDatacenterInfo()

	// Add hostname and datacenter to info
	info["host"] = map[string]interface{}{
		"hostname":   hostname,
		"datacenter": datacenter,
	}

	return info
}

// Get main network interface and IP address
func getMainInterface() (string, string) {
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if strings.HasPrefix(iface.Name, "lo") || strings.HasPrefix(iface.Name, "docker") {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.To4() != nil {
				return iface.Name, ip.String()
			}
		}
	}
	return "", ""
}

func main() {
	r := gin.Default()

	// Basic Authentication middleware with SSH validation
	r.Use(func(c *gin.Context) {
		username, password, hasAuth := c.Request.BasicAuth()
		if !hasAuth || !validateUser(username, password) {
			c.Header("WWW-Authenticate", `Basic realm="Restricted"`)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	})

	// Route to serve system information
	r.GET("/", func(c *gin.Context) {
		systemInfo := getSystemInfo()
		c.HTML(http.StatusOK, "index.html", gin.H{
			"cpu":     systemInfo["cpu"],
			"memory":  systemInfo["memory"],
			"network": systemInfo["network"],
			"host":    systemInfo["host"],
		})
	})

	// HTML template for displaying system information
	r.LoadHTMLGlob("templates/*")

	// Start the web server on port 1880
	r.Run(":1880")
}

EOL

# Create HTML template file
cat > templates/index.html <<'EOL'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DUALIZE - System Info</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <script>
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(function() {
                alert('IP address copied to clipboard: ' + text);
            }, function() {
                alert('Failed to copy IP address');
            });
        }
        
        setInterval(() => {
            location.reload();
        }, 5000);  // Reload every 5 seconds for live updates
    </script>
</head>
<body class="bg-gray-100 text-gray-800">
    <div class="container mx-auto p-4">
        <h1 class="text-4xl font-bold text-center mb-2">DUALIZE</h1>
        <h2 class="text-xl text-center mb-4">system information</h2>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <!-- CPU Info -->
            <div class="bg-white shadow-md rounded-lg p-4">
                <h2 class="text-xl font-semibold mb-2">CPU Usage</h2>
                <ul>
                    <li>Model: {{ .cpu.model }}</li>
                    <li>Cores: {{ .cpu.cores }}</li>
                    {{ range $index, $value := .cpu.usage }}
                    <li class="mb-1">Core {{ $index }}: {{ printf "%.2f" $value }}%</li>
                    <div class="w-full bg-gray-200 rounded-full h-2.5 mt-2">
                        <div class="bg-blue-500 h-2.5 rounded-full" style="width: {{ printf "%.2f" $value }}%"></div>
                    </div>
                    {{ end }}
                </ul>
            </div>

            <!-- Memory Info -->
            <div class="bg-white shadow-md rounded-lg p-4">
                <h2 class="text-xl font-semibold mb-2">Memory Usage</h2>
                <ul>
                    <li>Total: {{ .memory.total }} MB</li>
                    <li>Free: {{ .memory.free }} MB</li>
                    <li>Used: {{ printf "%.2f" .memory.used_percent }}%</li>
                </ul>
                <div class="w-full bg-gray-200 rounded-full h-2.5 mt-2">
                    <div class="bg-blue-500 h-2.5 rounded-full" style="width: {{ printf "%.2f" .memory.used_percent }}%"></div>
                </div>
            </div>

            <!-- Network Info -->
            <div class="bg-white shadow-md rounded-lg p-4">
                <h2 class="text-xl font-semibold mb-2">Network Interface (Main)</h2>
                <ul>
                    <li>Interface: {{ .network.name }}</li>
                    <li>IP Address: <span class="text-blue-500 underline cursor-pointer" onclick="copyToClipboard('{{ .network.ip }}')">{{ .network.ip }}</span></li>
                    <li>Bytes Sent: {{ .network.bytes_sent }}</li>
                    <li>Bytes Received: {{ .network.bytes_recv }}</li>
                    <li>Total Traffic: {{ .network.total_traffic }}</li>
                </ul>
            </div>

            <!-- Hostname and Datacenter Info -->
            <div class="bg-white shadow-md rounded-lg p-4">
                <h2 class="text-xl font-semibold mb-2">Host Information</h2>
                <ul>
                    <li>Hostname: {{ .host.hostname }}</li>
                    <li>Datacenter: {{ .host.datacenter }}</li>
                </ul>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <footer class="text-center p-4 mt-4 bg-gray-200 text-gray-600">
        <p>Version 0.0.1 - Created by Pasha Ghomi</p>
    </footer>
</body>
</html>

EOL

# Initialize Go module
go mod init dualize || true
go mod tidy

# Build the application
echo "Building the application..."
if ! go build -o dualize dualize.go; then
    echo "Error: Failed to build the application."
    exit 1
fi

# Move the binary to installation directory
sudo mv dualize "$INSTALL_DIR/"

# Create systemd service file
echo "Creating systemd service..."
sudo bash -c "cat > $SERVICE_FILE <<EOL
[Unit]
Description=Dualize Service
After=network.target

[Service]
ExecStart=$INSTALL_DIR/dualize
Restart=always
User=root
WorkingDirectory=$APP_DIR

[Install]
WantedBy=multi-user.target
EOL"

# Reload systemd and enable the service
echo "Enabling and starting the service..."
sudo systemctl daemon-reload
sudo systemctl enable $SERVICE_NAME
sudo systemctl start $SERVICE_NAME

# Check service status
if systemctl is-active --quiet $SERVICE_NAME; then
    echo "Service is running."
else
    echo "Error: Service failed to start."
    journalctl -u $SERVICE_NAME --no-pager
    exit 1
fi

# Firewall reminder
echo "Please ensure that port 1880 is open in your firewall settings."
echo "You can access the application at: http://$IP_ADDRESS:1880"
