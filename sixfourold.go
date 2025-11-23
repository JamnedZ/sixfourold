package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	localPort      string
	targetHost     string
	targetPort     string
	listenAddr     string
	enableTCP      bool
	enableUDP      bool
	fullTargetAddr string
	onlyV6Target   bool
)

var (
	sessions = make(map[string]*net.UDPConn)
	mu       sync.Mutex
)

const sessionTimeout = 5 * time.Minute

func cleanupSessions() {
	for {
		time.Sleep(sessionTimeout)
		mu.Lock()

		var toDelete []string
		for clientAddr, conn := range sessions {
			conn.Close()
			toDelete = append(toDelete, clientAddr)
		}

		for _, clientAddr := range toDelete {
			delete(sessions, clientAddr)
			fmt.Printf("[-] Cleaned up idle UDP session for %s\n", clientAddr)
		}

		mu.Unlock()
	}
}

func handleUDPClientPacket(pc net.PacketConn, n int, addr net.Addr, buf []byte) {
	clientAddr := addr.String()

	mu.Lock()
	conn, ok := sessions[clientAddr]
	mu.Unlock()

	if !ok {
		targetAddrP, err := netip.ParseAddrPort(fullTargetAddr)
		if err != nil {
			fmt.Printf("[-] Failed to parse target address %s: %v\n", fullTargetAddr, err)
			return
		}
		targetUDP := net.UDPAddrFromAddrPort(targetAddrP)

		conn, err = net.DialUDP("udp", nil, targetUDP)
		if err != nil {
			fmt.Printf("[-] Failed to dial UDP target %s: %v\n", fullTargetAddr, err)
			return
		}
		fmt.Printf("[+] Established new UDP session for client %s to target %s\n", clientAddr, conn.RemoteAddr())

		mu.Lock()
		sessions[clientAddr] = conn
		mu.Unlock()

		go func() {
			defer conn.Close()
			defer func() {
				mu.Lock()
				delete(sessions, clientAddr)
				mu.Unlock()
				fmt.Printf("[-] Closed UDP session for client %s\n", clientAddr)
			}()

			targetBuf := make([]byte, 4096)
			for {
				conn.SetReadDeadline(time.Now().Add(sessionTimeout))
				rn, _, err := conn.ReadFrom(targetBuf)
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						fmt.Printf("[-] UDP session timeout for client %s\n", clientAddr)
					} else {
						fmt.Printf("[-] Target read error for client %s: %v\n", clientAddr, err)
					}
					return
				}

				pc.WriteTo(targetBuf[:rn], addr)
			}
		}()
	}

	if _, err := conn.Write(buf[:n]); err != nil {
		fmt.Printf("[-] Error forwarding UDP packet to target: %v\n", err)
	}
}

func startUDPProxy(wg *sync.WaitGroup) {
	defer wg.Done()

	listen := net.JoinHostPort(listenAddr, localPort)
	pc, err := net.ListenPacket("udp", listen)
	if err != nil {
		fmt.Printf("FATAL ERROR: Could not start UDP listener on %s: %v\n", listen, err)
		return
	}
	defer pc.Close()

	fmt.Printf("\n[*] UDP Proxy listening on %s\n", listen)

	// Start the cleanup routine
	go cleanupSessions()

	// Main loop to receive UDP packets
	buffer := make([]byte, 4096)
	for {
		n, addr, err := pc.ReadFrom(buffer)
		if err != nil {
			if strings.Contains(err.Error(), "closed network connection") {
				return
			}
			fmt.Printf("Error reading UDP packet: %v\n", err)
			continue
		}
		go handleUDPClientPacket(pc, n, addr, append([]byte{}, buffer[:n]...))
	}
}

func handleTCPConnection(client net.Conn) {
	defer client.Close()

	clientAddr := client.RemoteAddr()
	fmt.Printf("[+] Incoming TCP connection from %s\n", clientAddr)

	// Dial to the target server
	fullTargetAddr := net.JoinHostPort(targetHost, targetPort)
	server, err := net.Dial("tcp", fullTargetAddr)
	if err != nil {
		fmt.Printf("[-] Failed to connect to TCP target %s: %v\n", fullTargetAddr, err)
		return
	}
	defer server.Close()
	fmt.Printf("[+] Connected to TCP target %s\n", server.RemoteAddr())

	go func() {
		io.Copy(server, client)
		server.Close()
	}()

	io.Copy(client, server)

	fmt.Printf("[-] TCP connection closed for %s\n", clientAddr)
}

func startTCPProxy(wg *sync.WaitGroup) {
	defer wg.Done()

	listen := net.JoinHostPort(listenAddr, localPort)
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		fmt.Printf("FATAL ERROR: Could not start TCP listener on %s: %v\n", listen, err)
		return
	}
	defer listener.Close()

	fmt.Printf("\n[*] TCP Proxy listening on %s\n", listen)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "closed network connection") {
				return
			}
			fmt.Printf("Error accepting TCP connection: %v\n", err)
			continue
		}
		go handleTCPConnection(conn)
	}
}

func resolveTarget() error {
	if targetHost == "" {
		return fmt.Errorf("target host cannot be empty")
	}

	targetHost = strings.Trim(targetHost, "[]")

	network := "ip"
	if onlyV6Target {
		network = "ip6"
	}

	addrs, err := net.DefaultResolver.LookupNetIP(context.Background(), network, targetHost)
	if err != nil {
		return fmt.Errorf("failed to resolve target host '%s': %v", targetHost, err)
	}

	fmt.Printf("[*] Target host '%s' resolved to: %v\n", targetHost, addrs)
	fullTargetAddr = net.JoinHostPort(targetHost, targetPort)
	return nil
}

func promptForInput() {
	reader := bufio.NewReader(os.Stdin)

	if localPort == "" {
		fmt.Print("Enter local port to listen on (e.g., 7777): ")
		text, _ := reader.ReadString('\n')
		localPort = strings.TrimSpace(text)
	}

	if targetHost == "" {
		fmt.Print("Enter target IP or Hostname (e.g., 1234:5678::ef2 or mygame.ddns.net): ")
		text, _ := reader.ReadString('\n')
		targetHost = strings.TrimSpace(text)
		if strings.Contains(targetHost, ":") {
			fmt.Print("Ignore IPv4 on lookup? (Y/n): ")
			reader := bufio.NewReader(os.Stdin)
			text, _ := reader.ReadString('\n')
			input := strings.TrimSpace(strings.ToLower(text))
			if input == "" || input == "y" {
				onlyV6Target = true
			}
		}
	}

	if targetPort == "" {
		fmt.Print("Enter target port: ")
		text, _ := reader.ReadString('\n')
		targetPort = strings.TrimSpace(text)
	}

	if listenAddr == "" {
		fmt.Print("Enter local listen IP (e.g., 127.0.0.1 or 0.0.0.0): ")
		text, _ := reader.ReadString('\n')
		listenAddr = strings.TrimSpace(text)
	}
}

func main() {
	flag.StringVar(&localPort, "lp", "", "Local port the proxy will listen on (e.g., 7777)")
	flag.StringVar(&targetHost, "ta", "", "Target IP or hostname (e.g., 1234:5678::ef2 or myhost.ddns.net)")
	flag.StringVar(&targetPort, "tp", "", "Target port (e.g., 7777)")
	flag.BoolVar(&onlyV6Target, "6", false, "Use only IPv6 for target (when using hostname)")
	flag.StringVar(&listenAddr, "la", "127.0.0.1", "Local IP address to bind to (e.g., 0.0.0.0 for all interfaces)")
	flag.BoolVar(&enableTCP, "tcp", false, "Enable the TCP proxy listener")
	flag.BoolVar(&enableUDP, "udp", false, "Enable the UDP proxy listener")
	flag.Usage = func() {
		fmt.Printf("sixfourold: a tcp/udp proxy\n\n")
		fmt.Printf("Usage:\n\n$ sixfourold\n- interactive mode\n\n")
		fmt.Printf("$ sixfourold -lp 10800 -ta 1234:2345:5f3::2 -tp 10800 -tcp -udp\n")
		fmt.Printf("- proxy tcp and udp traffic from localhost:10800 (127.0.0.1:10800) to [1234:2345:5f3::2]:10800\n\n")
		fmt.Printf("$ sixfourold -lp 25565 -ta smth.dynv6.com -tp 11037 -tcp -6\n")
		fmt.Printf("- proxy tcp traffic from localhost:25565 to smth.dynv6.com:11037, explicitly to IPv6\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if (localPort == "" || targetHost == "" || targetPort == "") || (!enableTCP && !enableUDP) {
		fmt.Println("\n--- Missing required arguments or protocol flag. Running interactive setup. ---")

		if !enableTCP && !enableUDP {
			fmt.Print("Run TCP Proxy? (Y/n): ")
			reader := bufio.NewReader(os.Stdin)
			text, _ := reader.ReadString('\n')
			input := strings.TrimSpace(strings.ToLower(text))
			if input == "" || input == "y" {
				enableTCP = true
			}

			fmt.Print("Run UDP Proxy? (Y/n): ")
			text, _ = reader.ReadString('\n')
			input = strings.TrimSpace(strings.ToLower(text))
			if input == "" || input == "y" {
				enableUDP = true
			}
		}

		if !enableTCP && !enableUDP {
			fmt.Println("ERROR: No proxy protocol (TCP or UDP) was enabled. Exiting.")
			return
		}

		promptForInput()
	}

	if !enableTCP && !enableUDP {
		fmt.Println("ERROR: No proxy protocol (TCP or UDP) was enabled. Exiting.")
		return
	}

	if err := resolveTarget(); err != nil {
		fmt.Printf("ERROR: %v\n", err)
		return
	}

	fmt.Printf("\n[*] Forwarding traffic from **%s:%s** to **%s**\n", listenAddr, localPort, fullTargetAddr)
	fmt.Printf("\n--- Game clients should connect to **%s:%s** ---\n\n", listenAddr, localPort)

	var wg sync.WaitGroup

	if enableTCP {
		wg.Add(1)
		go startTCPProxy(&wg)
	}

	if enableUDP {
		wg.Add(1)
		go startUDPProxy(&wg)
	}

	wg.Wait()
	fmt.Println("\nProxy shut down.")
}
