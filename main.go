package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	mdnsAddr = "224.0.0.251:5353"
)

type HostnameConflict struct {
	Name   string
	Number int
}

func main() {
	timeout := flag.Duration("timeout", 5*time.Second, "Discovery timeout duration (e.g., 10s, 30s, 1m)")
	verboseFlag := flag.Bool("verbose", false, "Enable verbose logging")
	metricsPath := flag.String("write-metrics", "", "Write conflict count as Prometheus gauge to '-' for stdout or a file path")
	flag.Parse()

	if *verboseFlag {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	} else {
		slog.SetLogLoggerLevel(slog.LevelWarn)
	}

	slog.Debug("Scanning network for Apple devices", "timeout", *timeout)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	hostnameConflicts, err := scanBonjourConflicts(ctx)
	if err != nil {
		slog.Error("failed to scan for conflicts", "error", err)
		return
	}

	if *metricsPath != "" {
		hostCount := len(hostnameConflicts)
		bucketBounds := []int{0, 1, 3, 5, 10, 100}
		bucketCounts := make([]int, len(bucketBounds))
		sumConflicts := 0

		for _, numbers := range hostnameConflicts {
			conflicts := 0
			for num := range numbers {
				if num == 0 {
					continue
				}
				conflicts += num
			}
			sumConflicts += conflicts
			for i, bound := range bucketBounds {
				if conflicts <= bound {
					bucketCounts[i]++
				}
			}
		}

		metrics := "# HELP bugjour_conflicts Bonjour hostname conflicts\n# TYPE bugjour_conflicts histogram\n"
		for i, bound := range bucketBounds {
			metrics += fmt.Sprintf("bugjour_conflicts_bucket{le=\"%d\"} %d\n", bound, bucketCounts[i])
		}
		metrics += fmt.Sprintf("bugjour_conflicts_bucket{le=\"+Inf\"} %d\n", hostCount)
		metrics += fmt.Sprintf("bugjour_conflicts_sum %d\n", sumConflicts)
		metrics += fmt.Sprintf("bugjour_conflicts_count %d\n", hostCount)

		if *metricsPath == "-" {
			fmt.Print(metrics)
		} else {
			if err := os.WriteFile(*metricsPath, []byte(metrics), 0644); err != nil {
				slog.Error("failed to write metrics", "error", err)
			}
		}
		return
	}

	if len(hostnameConflicts) > 0 {
		var sortedNames []string
		for baseName := range hostnameConflicts {
			sortedNames = append(sortedNames, baseName)
		}
		sort.Strings(sortedNames)

		for _, baseName := range sortedNames {
			numbers := hostnameConflicts[baseName]
			var numberSlice []int
			for num := range numbers {
				numberSlice = append(numberSlice, num)
			}
			sort.Ints(numberSlice)

			var numberStrs []string
			for _, num := range numberSlice {
				numberStrs = append(numberStrs, fmt.Sprintf("%d", num))
			}

			fmt.Printf("%s (%s)\n", baseName, strings.Join(numberStrs, ", "))
		}
	}
}

func scanBonjourConflicts(ctx context.Context) (map[string]map[int]bool, error) {
	hostnameConflicts := make(map[string]map[int]bool)

	addr, err := net.ResolveUDPAddr("udp4", mdnsAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve IPv4 address: %w", err)
	}

	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on IPv4 multicast: %w", err)
	}
	defer conn.Close()

	slog.Debug("Scanning for all services")

	conflicts := make(chan HostnameConflict, 100)
	go collectHostnames(ctx, conn, conflicts)
	queryServices(conn)

	for {
		select {
		case <-ctx.Done():
			slog.Debug("Discovery timeout reached")
			return hostnameConflicts, nil
		case conflict, ok := <-conflicts:
			if !ok {
				slog.Debug("All service discovery completed")
				return hostnameConflicts, nil
			}
			if hostnameConflicts[conflict.Name] == nil {
				hostnameConflicts[conflict.Name] = make(map[int]bool)
			}
			hostnameConflicts[conflict.Name][conflict.Number] = true
			slog.Debug("Found conflicted hostname", "name", conflict.Name, "number", conflict.Number)
		}
	}
}

func cleanDeviceName(instanceName string) (baseName string, conflictNumber int) {
	name := strings.TrimSuffix(instanceName, ".")
	parts := strings.Split(name, ".")
	var instance string
	if len(parts) > 0 {
		instance = parts[0]
	} else {
		instance = name
	}

	instance = strings.ReplaceAll(instance, `\`, "")
	instance = strings.ReplaceAll(instance, "'", "'")

	if regexp.MustCompile(`^\d+(-\d+)*$`).MatchString(instance) {
		return "", 0
	}

	pattern := regexp.MustCompile(`^(?:[A-F0-9]{12}@|\d+-\d+-\d+-\d+\.\d+\s+)?(.+?)(?:\s+\[[^\]]+\]| series)?\s*(?:\((\d+)\)|-(\d+))?$`)
	matches := pattern.FindStringSubmatch(instance)

	if len(matches) >= 2 && matches[1] != "" {
		baseName = strings.TrimSpace(matches[1])
		if len(matches) >= 3 {
			if matches[2] != "" {
				fmt.Sscanf(matches[2], "%d", &conflictNumber)
			} else if len(matches) >= 4 && matches[3] != "" {
				fmt.Sscanf(matches[3], "%d", &conflictNumber)
				baseName = strings.ReplaceAll(baseName, "-", " ")
			}
		}
		return baseName, conflictNumber
	}

	return strings.TrimSpace(instance), 0
}

var serviceNames = []string{
	"_adisk._tcp.local.",
	"_afpovertcp._tcp.local.",
	"_airdrop._tcp.local.",
	"_airplay._tcp.local.",
	"_airplay._udp.local.",
	"_airport._tcp.local.",
	"_apple-mobdev2._tcp.local.",
	"_apple-tv._tcp.local.",
	"_companion-link._tcp.local.",
	"_dacp._tcp.local.",
	"_device-info._tcp.local.",
	"_dmap._tcp.local.",
	"_hap._tcp.local.",
	"_homekit._tcp.local.",
	"_homepod._tcp.local.",
	"_http._tcp.local.",
	"_matter._tcp.local.",
	"_mediaremotetv._tcp.local.",
	"_raop._tcp.local.",
	"_raop._udp.local.",
	"_rfb._tcp.local.",
	"_sleep-proxy._udp.local.",
	"_smb._tcp.local.",
	"_soundbar._tcp.local.",
	"_touch-able._tcp.local.",
	"_workstation._tcp.local.",
}

func queryServices(conn *net.UDPConn) {
	for _, serviceName := range serviceNames {

		m := new(dns.Msg)
		m.SetQuestion(serviceName, dns.TypePTR)
		m.RecursionDesired = false

		buf, err := m.Pack()
		if err != nil {
			panic(fmt.Sprintf("failed to pack DNS message: %v", err))
		}

		addr, _ := net.ResolveUDPAddr("udp4", mdnsAddr)
		if conn != nil {
			_, err := conn.WriteTo(buf, addr)
			if err != nil {
				slog.Error("failed to send IPv4 query", "error", err)
			}
		}
	}
}

func collectHostnames(ctx context.Context, conn *net.UDPConn, conflicts chan<- HostnameConflict) {
	defer close(conflicts)
	buf := make([]byte, 65536)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil {
			continue
		}

		sections := append(msg.Answer, msg.Ns...)
		sections = append(sections, msg.Extra...)

		for _, rr := range sections {
			var name string
			if ptr, ok := rr.(*dns.PTR); ok {
				name = ptr.Ptr
				slog.Debug("dns ptr record", "type", rr.Header().Rrtype, "name", name)
			} else {
				name = rr.Header().Name
				slog.Debug("dns record", "type", rr.Header().Rrtype, "name", name)
			}

			baseName, conflictNumber := cleanDeviceName(name)
			conflict := HostnameConflict{
				Name:   baseName,
				Number: conflictNumber,
			}

			if baseName != "" && conflictNumber > 0 {
				select {
				case conflicts <- conflict:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}
