package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/ipc"
	"github.com/amnezia-vpn/amneziawg-go/tun"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const serviceName = "KitoFtorVPNTunnel"
const tunnelInterfaceName = "KitoFtorVPN"

// ─── Control channel (loopback TCP) ───────────────────────
//
// Why this exists: previously every "connect"/"disconnect" from the UI
// created a brand-new Windows service via the Service Control Manager,
// then deleted it again on the next action. Creating/deleting a service
// and waiting for SCM to settle is what made the whole flow take 10-15
// seconds (and made the "status" poll race with that, occasionally
// surfacing a raw Go/Windows error string in the UI).
//
// Now the Windows service is created once and left running permanently
// in the background (it does nothing while no tunnel is up — near-zero
// CPU). All "connect/disconnect/status" actions go through a tiny local
// TCP control channel directly to that already-running service, so they
// only need to do the actual WireGuard device up/down work, which is
// fast (well under a second).
// SECURITY: this used to be a plain TCP listener on 127.0.0.1:47291 with no
// authentication whatsoever. Because the service runs as LocalSystem and is
// registered StartAutomatic, that meant *any* process on the machine —
// including one running as an unprivileged user — could connect and send a
// CONNECT command with an attacker-supplied WireGuard config, and the service
// would dutifully route the whole machine's traffic through it. DISCONNECT
// was equally reachable, so hostile software could also silently drop the
// user's VPN while the tray icon still showed "connected".
//
// A loopback TCP socket has no way to find out who is on the other end, so
// there was nothing to bolt authentication onto. A named pipe does: the
// pipe is created with an explicit DACL, and the OS itself refuses the
// connection for anyone not on it, before a single byte is exchanged. This
// is the same mechanism wireguard-windows uses for its own IPC.
//
// D:P  — protected DACL, do not inherit ACEs from anywhere
// (A;;GA;;;SY) — GENERIC_ALL for NT AUTHORITY\SYSTEM (the service itself)
// (A;;GA;;;BA) — GENERIC_ALL for BUILTIN\Administrators (the elevated app)
const pipeName = `\\.\pipe\KitoFtorVPNTunnel`
const pipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"

// Win32 constants declared locally rather than taken from x/sys/windows, so
// this keeps compiling regardless of which of them that package happens to
// export in a given version.
const (
	pipeAccessDuplex        = 0x00000003
	pipeTypeByte            = 0x00000000
	pipeReadmodeByte        = 0x00000000
	pipeWait                = 0x00000000
	pipeRejectRemoteClients = 0x00000008
	pipeUnlimitedInstances  = 255

	errPipeBusy      = syscall.Errno(231)
	errPipeConnected = syscall.Errno(535)
)

type parsedConfig struct {
	address      string
	dns          []string
	endpointHost string
	allowedIPs   []string
	uapi         string
}

// ─── DPAPI ───────────────────────────────────────────────

var (
	dllCrypt32  = syscall.NewLazyDLL("crypt32.dll")
	dllKernel32 = syscall.NewLazyDLL("kernel32.dll")

	procEncryptData = dllCrypt32.NewProc("CryptProtectData")
	procDecryptData = dllCrypt32.NewProc("CryptUnprotectData")
	procLocalFree   = dllKernel32.NewProc("LocalFree")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func dpapiBytesToBlob(b []byte) *dataBlob {
	blob := &dataBlob{cbData: uint32(len(b))}
	if len(b) > 0 {
		blob.pbData = &b[0]
	}
	return blob
}

func dpapiEncrypt(data []byte) ([]byte, error) {
	in := dpapiBytesToBlob(data)
	var out dataBlob
	r, _, err := procEncryptData.Call(
		uintptr(unsafe.Pointer(in)), 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptProtectData failed: %v", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	enc := make([]byte, out.cbData)
	copy(enc, unsafe.Slice(out.pbData, out.cbData))
	return enc, nil
}

func dpapiDecrypt(data []byte) ([]byte, error) {
	in := dpapiBytesToBlob(data)
	var out dataBlob
	r, _, err := procDecryptData.Call(
		uintptr(unsafe.Pointer(in)), 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed: %v", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	dec := make([]byte, out.cbData)
	copy(dec, unsafe.Slice(out.pbData, out.cbData))
	return dec, nil
}

// ─── Main ────────────────────────────────────────────────

func main() {
	exePath, _ := os.Executable()
	// debug.log used to be opened O_APPEND and never touched again. With the
	// WireGuard device logger writing every handshake into it, it grew without
	// bound — hundreds of MB after a few months of daily use. Rotate at 5 MB,
	// keeping exactly one previous file so support can still ask for a log.
	logPath := filepath.Join(filepath.Dir(exePath), "debug.log")
	if st, serr := os.Stat(logPath); serr == nil && st.Size() > 5*1024*1024 {
		os.Remove(logPath + ".old")
		os.Rename(logPath, logPath+".old")
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		log.SetOutput(logFile)
		defer logFile.Close()
	}
	log.Printf("Started with args: %v", os.Args)

	// Internal entry point: runs as the long-lived Windows service.
	// No longer takes a config path — the service starts idle and waits
	// for "connect" commands on the control channel.
	if len(os.Args) >= 2 && os.Args[1] == "service" {
		svc.Run(serviceName, &vpnService{})
		return
	}

	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  kitoftor-tunnel.exe start-stdin")
		fmt.Println("  kitoftor-tunnel.exe stop")
		fmt.Println("  kitoftor-tunnel.exe service-stop")
		fmt.Println("  kitoftor-tunnel.exe status")
		fmt.Println("  kitoftor-tunnel.exe dpapi-encrypt")
		fmt.Println("  kitoftor-tunnel.exe dpapi-decrypt")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "start-stdin":
		confData, err := io.ReadAll(os.Stdin)
		if err != nil || len(confData) == 0 {
			fmt.Fprintf(os.Stderr, "ERROR: cannot read config from stdin\n")
			os.Exit(1)
		}
		reply, err := sendCommand("CONNECT", string(confData))
		if err != nil {
			log.Printf("start-stdin error: %v", err)
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		if !strings.HasPrefix(reply, "OK") {
			fmt.Fprintf(os.Stderr, "ERROR: %s\n", reply)
			os.Exit(1)
		}
		fmt.Println("OK")

	case "start":
		if len(os.Args) < 3 {
			fmt.Println("Usage: kitoftor-tunnel.exe start <config.conf>")
			os.Exit(1)
		}
		data, err := os.ReadFile(os.Args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: config not found: %v\n", err)
			os.Exit(1)
		}
		reply, err := sendCommand("CONNECT", string(data))
		if err != nil {
			log.Printf("start error: %v", err)
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		if !strings.HasPrefix(reply, "OK") {
			fmt.Fprintf(os.Stderr, "ERROR: %s\n", reply)
			os.Exit(1)
		}
		fmt.Println("OK")

	case "stop":
		reply, err := sendCommand("DISCONNECT", "")
		if err != nil {
			log.Printf("stop error: %v", err)
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		if !strings.HasPrefix(reply, "OK") {
			fmt.Fprintf(os.Stderr, "ERROR: %s\n", reply)
			os.Exit(1)
		}
		fmt.Println("OK")

	case "service-stop":
		// Stops the persistent background Windows service entirely (not just
		// the tunnel inside it). Used when the user fully exits the app via
		// tray "Выход" — otherwise kitoftor-tunnel.exe keeps running in
		// Task Manager / Services even after the app window and tray icon
		// are gone. A normal "stop" only sends DISCONNECT, which tears down
		// the VPN tunnel but intentionally leaves the service process alive
		// (that's what makes the next "Подключиться" fast). This command is
		// the deliberate, explicit way to also stop that background process.
		if err := stopWindowsService(); err != nil {
			log.Printf("service-stop error: %v", err)
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("OK")

	case "status":
		fmt.Print(tunnelStatus())

	case "dpapi-encrypt":
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		enc, err := dpapiEncrypt(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(base64.StdEncoding.EncodeToString(enc))

	case "dpapi-decrypt":
		b64, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		enc, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b64)))
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: invalid base64: %v\n", err)
			os.Exit(1)
		}
		dec, err := dpapiDecrypt(enc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(string(dec))

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

// ─── Config parsing ──────────────────────────────────────

func b64toHex(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

var supportedAWGKeys = map[string]bool{
	"jc": true, "jmin": true, "jmax": true,
	"s1": true, "s2": true, "s3": true, "s4": true,
	"h1": true, "h2": true, "h3": true, "h4": true,
	"i1": true, "i2": true, "i3": true, "i4": true, "i5": true,
}

func parseWgQuickStringToUAPI(confStr string) (*parsedConfig, error) {
	return parseWgQuickReaderToUAPI(strings.NewReader(confStr))
}

func parseWgQuickReaderToUAPI(reader io.Reader) (*parsedConfig, error) {
	pc := &parsedConfig{}
	var uapiLines []string
	section := ""
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		if lower == "[interface]" {
			section = "interface"
			continue
		}
		if lower == "[peer]" {
			section = "peer"
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		keyLower := strings.ToLower(key)

		if section == "interface" {
			switch {
			case keyLower == "privatekey":
				h, err := b64toHex(val)
				if err == nil {
					uapiLines = append(uapiLines, "private_key="+h)
				}
			case keyLower == "listenport":
				uapiLines = append(uapiLines, "listen_port="+val)
			case keyLower == "address":
				pc.address = val
			case keyLower == "dns":
				for _, d := range strings.Split(val, ",") {
					d = strings.TrimSpace(d)
					if d != "" {
						pc.dns = append(pc.dns, d)
					}
				}
			case keyLower == "mtu":
			case supportedAWGKeys[keyLower]:
				uapiLines = append(uapiLines, keyLower+"="+val)
			default:
				log.Printf("parseConfig: skipping key: %s", keyLower)
			}
		} else if section == "peer" {
			switch keyLower {
			case "publickey":
				h, err := b64toHex(val)
				if err == nil {
					uapiLines = append(uapiLines, "public_key="+h)
				}
			case "presharedkey":
				h, err := b64toHex(val)
				if err == nil {
					uapiLines = append(uapiLines, "preshared_key="+h)
				}
			case "allowedips":
				for _, a := range strings.Split(val, ",") {
					a = strings.TrimSpace(a)
					if a != "" {
						uapiLines = append(uapiLines, "allowed_ip="+a)
						pc.allowedIPs = append(pc.allowedIPs, a)
					}
				}
			case "endpoint":
				uapiLines = append(uapiLines, "endpoint="+val)
				host := val
				if idx := strings.LastIndex(host, ":"); idx >= 0 {
					host = host[:idx]
				}
				pc.endpointHost = host
			case "persistentkeepalive":
				uapiLines = append(uapiLines, "persistent_keepalive_interval="+val)
			}
		}
	}
	pc.uapi = strings.Join(uapiLines, "\n") + "\n"
	return pc, nil
}

// ─── Network helpers ─────────────────────────────────────

func getDefaultGateway() string {
	cmd := exec.Command("cmd", "/C", "route print 0.0.0.0")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		log.Printf("getDefaultGateway error: %v", err)
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			log.Printf("getDefaultGateway: %s", fields[2])
			return fields[2]
		}
	}
	return ""
}

// ─── VPN Service ─────────────────────────────────────────
//
// The service itself is now long-running and idle by default. It opens
// the local control listener as soon as it starts, and only does the
// actual WireGuard device work in response to CONNECT/DISCONNECT
// commands. This is what makes connect/disconnect fast: no SCM calls
// are on the hot path anymore, only WireGuard device + a handful of
// "route"/"netsh" calls, same as before.

type vpnService struct{}

// tunnelState holds everything needed to tear a running tunnel down.
// nil when no tunnel is up.
type tunnelState struct {
	dev          *device.Device
	wgDev        tun.Device
	uapi         net.Listener
	pc           *parsedConfig
	defaultGW    string
	connectStart time.Time
}

func (s *vpnService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}

	var current *tunnelState // nil = no tunnel running

	listener, err := newPipeListener()
	if err != nil {
		log.Printf("vpnService: control listener failed: %v", err)
		return false, 1
	}
	log.Printf("vpnService: control channel listening on %s (SYSTEM + Administrators only)", pipeName)

	type cmdResult struct {
		conn net.Conn
		cmd  string
		body string
	}
	cmdCh := make(chan cmdResult)

	// Accept loop runs in its own goroutine so the main Execute loop can
	// still react to Windows service-control requests (Stop/Shutdown)
	// promptly even while handling a command.
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return // listener closed -> service stopping
			}
			go func() {
				cmd, body, ok := readCommand(c)
				if !ok {
					c.Close()
					return
				}
				cmdCh <- cmdResult{conn: c, cmd: cmd, body: body}
			}()
		}
	}()

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	log.Println("vpnService: RUNNING (idle, waiting for commands)")

	teardown := func() {
		if current == nil {
			return
		}
		log.Println("vpnService: tearing down active tunnel")
		cleanupRoutes(current.pc, current.defaultGW, current.wgDev)
		if current.uapi != nil {
			current.uapi.Close()
		}
		current.dev.Close()
		current = nil
	}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				log.Println("vpnService: service stopping")
				changes <- svc.Status{State: svc.StopPending}
				listener.Close()
				teardown()
				return false, 0
			case svc.Interrogate:
				changes <- c.CurrentStatus
			}

		case res := <-cmdCh:
			switch res.cmd {
			case "CONNECT":
				// Always tear down any previous tunnel first — this
				// mirrors the old "stop then start" behaviour (e.g.
				// reconnect with a different whitelist), but now it's
				// just closing a WireGuard device, which is fast.
				teardown()

				pc, err := parseWgQuickStringToUAPI(res.body)
				if err != nil {
					writeReply(res.conn, "ERROR: parse failed: "+err.Error())
					res.conn.Close()
					continue
				}

				// getDefaultGateway spawns "cmd /C route print" — independent
				// of TUN/device setup below, so run it concurrently instead
				// of blocking on it before we even create the adapter.
				gwCh := make(chan string, 1)
				go func() { gwCh <- getDefaultGateway() }()

				wintun, err := tun.CreateTUN(tunnelInterfaceName, 0)
				if err != nil {
					writeReply(res.conn, "ERROR: CreateTUN failed: "+err.Error())
					res.conn.Close()
					continue
				}

				bind := conn.NewDefaultBind()
				dev := device.NewDevice(wintun, bind, &device.Logger{Verbosef: verbosef, Errorf: log.Printf})

				if err := dev.IpcSet(pc.uapi); err != nil {
					dev.Close()
					writeReply(res.conn, "ERROR: IpcSet failed: "+err.Error())
					res.conn.Close()
					continue
				}

				dev.Up()

				var uapiListener net.Listener
				if l, err := ipc.UAPIListen(tunnelInterfaceName); err != nil {
					log.Printf("vpnService: UAPIListen error: %v", err)
				} else {
					uapiListener = l
					go func(l net.Listener) {
						for {
							c, err := l.Accept()
							if err != nil {
								return
							}
							go dev.IpcHandle(c)
						}
					}(uapiListener)
				}

				defaultGW := <-gwCh
				configureNetwork(pc, defaultGW, wintun)

				current = &tunnelState{
					dev:          dev,
					wgDev:        wintun,
					uapi:         uapiListener,
					pc:           pc,
					defaultGW:    defaultGW,
					connectStart: time.Now(),
				}
				log.Println("vpnService: tunnel UP")
				writeReply(res.conn, "OK")
				res.conn.Close()

			case "DISCONNECT":
				teardown()
				writeReply(res.conn, "OK")
				res.conn.Close()

			case "STATUS":
				if current != nil {
					writeReply(res.conn, "RUNNING "+fmt.Sprintf("%d", current.connectStart.Unix()))
				} else {
					writeReply(res.conn, "STOPPED")
				}
				res.conn.Close()

			default:
				writeReply(res.conn, "ERROR: unknown command")
				res.conn.Close()
			}
		}
	}
}

// ─── Control channel protocol ────────────────────────────
//
// Tiny line-based protocol over loopback TCP:
//   client -> "<COMMAND> <base64-body>\n"
//   server -> "<REPLY>\n"
// The body is base64-encoded so the WireGuard config (which contains
// newlines) can travel as a single line.

func sendCommand(cmd string, body string) (string, error) {
	// Try the already-running service first — this is the fast path that
	// makes connect/disconnect near-instant once the service exists.
	reply, err := tryCommand(cmd, body)
	if err == nil {
		return reply, nil
	}

	// Service not reachable: it's either not installed yet (first run
	// after install) or was stopped externally. Install/start it once,
	// then retry. This still has to go through the SCM, but only ever
	// happens once per machine — not on every connect/disconnect.
	log.Printf("sendCommand: control channel unreachable (%v), ensuring service is running", err)
	if err := ensureServiceRunning(); err != nil {
		return "", err
	}

	reply, err = tryCommand(cmd, body)
	if err != nil {
		return "", fmt.Errorf("service started but control channel still unreachable: %v", err)
	}
	return reply, nil
}

func tryCommand(cmd string, body string) (string, error) {
	c, err := dialPipe(2 * time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()

	c.SetDeadline(time.Now().Add(15 * time.Second))
	encoded := base64.StdEncoding.EncodeToString([]byte(body))
	if _, err := fmt.Fprintf(c, "%s %s\n", cmd, encoded); err != nil {
		return "", err
	}

	reader := bufio.NewReader(c)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// readCommand parses one line sent by sendCommand. ok=false means the
// connection was garbage/closed before a full line arrived.
func readCommand(c net.Conn) (cmd string, body string, ok bool) {
	c.SetDeadline(time.Now().Add(15 * time.Second))
	reader := bufio.NewReader(c)
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		return "", "", false
	}
	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, " ", 2)
	cmd = parts[0]
	if len(parts) == 2 {
		if decoded, err := base64.StdEncoding.DecodeString(parts[1]); err == nil {
			body = string(decoded)
		}
	}
	return cmd, body, true
}

func writeReply(c net.Conn, reply string) {
	fmt.Fprintf(c, "%s\n", reply)
}

// ensureServiceRunning installs the Windows service if it doesn't exist
// yet, and starts it if it isn't running. This is the only place that
// still talks to the Service Control Manager directly, and it only runs
// when the persistent service isn't already up (normally: once, right
// after installing the app, or after a reboot before autostart kicks in).
func ensureServiceRunning() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot get exe path: %v", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("SCM connect failed (need admin): %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		// Doesn't exist yet — create it once, set to auto-start so it
		// also comes back up after a reboot without the app needing to
		// do anything.
		s, err = m.CreateService(serviceName, exePath, mgr.Config{
			ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
			StartType:    mgr.StartAutomatic,
			ErrorControl: mgr.ErrorNormal,
			DisplayName:  "KitoFtorVPN Tunnel",
			Description:  "KitoFtorVPN AmneziaWG tunnel (background service)",
		}, "service")
		if err != nil {
			return fmt.Errorf("CreateService failed: %v", err)
		}
	}
	defer s.Close()

	st, err := s.Query()
	if err == nil && st.State == svc.Running {
		return nil // already running, nothing to do
	}

	if err := s.Start(); err != nil {
		// "service already running" races are harmless here.
		if !strings.Contains(err.Error(), "already") {
			return fmt.Errorf("Start failed: %v", err)
		}
	}

	for i := 0; i < 30; i++ {
		st, err := s.Query()
		if err == nil {
			if st.State == svc.Running {
				return nil
			}
			if st.State == svc.Stopped {
				return fmt.Errorf("service stopped unexpectedly")
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for service to start")
}

// stopWindowsService stops the persistent background Windows service via
// the Service Control Manager. Used only on full app exit ("Выход" in the
// tray menu) — a normal connect/disconnect never calls this, since keeping
// the service alive between tunnel up/down is what makes those fast.
//
// The service's own Execute loop (svc.Stop case) already tears down any
// active tunnel/routes before it actually stops, so this is also safe to
// call while a VPN connection is up.
func stopWindowsService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("SCM connect failed (need admin): %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		// Not installed / already gone — nothing to stop.
		return nil
	}
	defer s.Close()

	st, err := s.Query()
	if err == nil && st.State == svc.Stopped {
		return nil // already stopped
	}

	if _, err := s.Control(svc.Stop); err != nil {
		if !strings.Contains(err.Error(), "already") {
			return fmt.Errorf("Control(Stop) failed: %v", err)
		}
	}

	for i := 0; i < 30; i++ {
		st, err := s.Query()
		if err == nil && st.State == svc.Stopped {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for service to stop")
}

// ─── Network config ──────────────────────────────────────

// configureNetwork applies the tunnel's IP/DNS/routes after the WireGuard
// device is up.
//
// PERFORMANCE NOTE (route table): a whitelist with many domains expands the
// single "0.0.0.0/0" AllowedIPs line into a "subtract the excluded blocks"
// CIDR list — with ~30 whitelisted domains this can legitimately be 300-600
// separate CIDRs (that's just what's mathematically needed to carve holes
// out of 0.0.0.0/0). The previous version added every single one of those
// with its own "route add" process spawn. Even run concurrently via
// goroutines, spawning hundreds of OS processes at once does not parallelize
// for free — Windows process creation itself becomes the bottleneck (worse
// with AV/EDR hooking CreateProcess), which is what produced the ~30s
// connect/disconnect times once the whitelist had enough entries.
//
// Fix: routes are now added via the same Windows routing-table API that
// wireguard-windows itself uses (winipcfg / NetioCreateIpForwardEntry2),
// through routesLUID.AddRoutes(). This is in-process — no child process per
// route, no OS process-table contention — so hundreds of routes add in
// milliseconds instead of seconds, regardless of whitelist size.
//
// DNS still goes through netsh (there are only ever 1-3 DNS entries, never
// whitelist-sized, so it was never the bottleneck and is left as-is).
func configureNetwork(pc *parsedConfig, defaultGW string, wgDev tun.Device) {
	ip, ipNet, err := net.ParseCIDR(pc.address)
	if err != nil {
		log.Printf("configureNetwork: ParseCIDR error: %v", err)
		return
	}
	mask := fmt.Sprintf("%d.%d.%d.%d", ipNet.Mask[0], ipNet.Mask[1], ipNet.Mask[2], ipNet.Mask[3])

	// The address must be set first: routes below are added against this
	// same adapter, so the adapter needs to exist with an address first.
	runNetsh("interface", "ip", "set", "address", "name="+tunnelInterfaceName, "source=static", "addr="+ip.String(), "mask="+mask)

	luid := tunnelLUID(wgDev)
	tunIPAddr, _ := netipAddrFromString(ip.String())

	var wg sync.WaitGroup

	// DNS entries don't depend on routes or vice versa — run alongside.
	if len(pc.dns) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runNetsh("interface", "ip", "set", "dns", "name="+tunnelInterfaceName, "source=static", "addr="+pc.dns[0])
			for i := 1; i < len(pc.dns); i++ {
				idx := i
				runNetsh("interface", "ip", "add", "dns", "name="+tunnelInterfaceName, "addr="+pc.dns[idx], fmt.Sprintf("index=%d", idx+1))
			}
		}()
	}

	if pc.endpointHost != "" && defaultGW != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runCmd("route", "add", pc.endpointHost+"/32", defaultGW, "metric", "1")
		}()
	}

	// Build the full route list (could be 1 entry, could be 600+ with a big
	// whitelist) and add them all in one API batch call instead of one
	// process per route.
	if luid != 0 && tunIPAddr.IsValid() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addAllowedIPRoutes(winipcfg.LUID(luid), pc.allowedIPs, tunIPAddr)
		}()
	} else {
		log.Printf("configureNetwork: missing LUID or tunnel IP, falling back to route.exe")
		addAllowedIPRoutesViaRouteExe(pc.allowedIPs, ip.String(), getInterfaceIndex())
	}

	wg.Wait()
}

// addAllowedIPRoutes adds every allowedIP as a route via the Windows
// routing-table API (one in-process call per route, no child processes).
// This is what makes connect fast even with a whitelist-expanded route list.
func addAllowedIPRoutes(luid winipcfg.LUID, allowedIPs []string, tunIP netip.Addr) {
	var routes []*winipcfg.RouteData
	for _, a := range allowedIPs {
		if a == "0.0.0.0/0" {
			routes = append(routes,
				&winipcfg.RouteData{Destination: netip.MustParsePrefix("0.0.0.0/1"), NextHop: tunIP, Metric: 5},
				&winipcfg.RouteData{Destination: netip.MustParsePrefix("128.0.0.0/1"), NextHop: tunIP, Metric: 5},
			)
			continue
		}
		prefix, err := netip.ParsePrefix(a)
		if err != nil {
			// Bare IP without "/nn" — treat as /32.
			if addr, aerr := netip.ParseAddr(a); aerr == nil {
				prefix = netip.PrefixFrom(addr, 32)
			} else {
				continue
			}
		}
		routes = append(routes, &winipcfg.RouteData{Destination: prefix, NextHop: tunIP, Metric: 5})
	}
	if len(routes) == 0 {
		return
	}
	if err := luid.AddRoutes(routes); err != nil {
		log.Printf("addAllowedIPRoutes: AddRoutes failed (%d routes): %v", len(routes), err)
	} else {
		log.Printf("addAllowedIPRoutes: added %d routes via winipcfg", len(routes))
	}
}

// addAllowedIPRoutesViaRouteExe is the old process-spawning path, kept only
// as a fallback for the unexpected case where we can't get the adapter LUID.
func addAllowedIPRoutesViaRouteExe(allowedIPs []string, tunIP string, ifIndex string) {
	var wg sync.WaitGroup
	for _, a := range allowedIPs {
		a := a
		if a == "0.0.0.0/0" {
			wg.Add(2)
			go func() {
				defer wg.Done()
				runCmd("route", "add", "0.0.0.0", "mask", "128.0.0.0", tunIP, "metric", "5", "if", ifIndex)
			}()
			go func() {
				defer wg.Done()
				runCmd("route", "add", "128.0.0.0", "mask", "128.0.0.0", tunIP, "metric", "5", "if", ifIndex)
			}()
		} else if strings.Contains(a, "/") {
			_, n, err := net.ParseCIDR(a)
			if err != nil {
				continue
			}
			m := fmt.Sprintf("%d.%d.%d.%d", n.Mask[0], n.Mask[1], n.Mask[2], n.Mask[3])
			wg.Add(1)
			go func() {
				defer wg.Done()
				runCmd("route", "add", n.IP.String(), "mask", m, tunIP, "metric", "5", "if", ifIndex)
			}()
		}
	}
	wg.Wait()
}

func cleanupRoutes(pc *parsedConfig, defaultGW string, wgDev tun.Device) {
	var wg sync.WaitGroup

	luid := tunnelLUID(wgDev)
	tunIPAddr := netip.Addr{}
	if pc.address != "" {
		if ip, _, err := net.ParseCIDR(pc.address); err == nil {
			tunIPAddr, _ = netipAddrFromString(ip.String())
		}
	}

	if luid != 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			removeAllowedIPRoutes(winipcfg.LUID(luid), pc.allowedIPs, tunIPAddr)
		}()
	}

	if pc.endpointHost != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runCmd("route", "delete", pc.endpointHost+"/32")
		}()
	}

	wg.Wait()
}

// removeAllowedIPRoutes mirrors addAllowedIPRoutes but for teardown. Deleting
// is per-route via the API (DeleteRoute has no batch form), but this is still
// an in-process syscall per route, not a child process per route, so it's
// still fast even for a few hundred entries.
func removeAllowedIPRoutes(luid winipcfg.LUID, allowedIPs []string, tunIP netip.Addr) {
	if !tunIP.IsValid() {
		return
	}
	var wg sync.WaitGroup
	del := func(prefix netip.Prefix) {
		defer wg.Done()
		if err := luid.DeleteRoute(prefix, tunIP); err != nil {
			log.Printf("removeAllowedIPRoutes: DeleteRoute(%s) failed: %v", prefix, err)
		}
	}
	for _, a := range allowedIPs {
		if a == "0.0.0.0/0" {
			wg.Add(2)
			go del(netip.MustParsePrefix("0.0.0.0/1"))
			go del(netip.MustParsePrefix("128.0.0.0/1"))
			continue
		}
		prefix, err := netip.ParsePrefix(a)
		if err != nil {
			if addr, aerr := netip.ParseAddr(a); aerr == nil {
				prefix = netip.PrefixFrom(addr, 32)
			} else {
				continue
			}
		}
		wg.Add(1)
		go del(prefix)
	}
	wg.Wait()
}

// tunnelLUID extracts the adapter LUID from the WireGuard tun.Device. On
// Windows this is backed by wintun and exposes LUID() uint64; we use an
// interface assertion instead of importing the concrete type so this still
// builds cleanly if the underlying implementation changes its exact type.
func tunnelLUID(wgDev tun.Device) uint64 {
	if wgDev == nil {
		return 0
	}
	if l, ok := wgDev.(interface{ LUID() uint64 }); ok {
		return l.LUID()
	}
	log.Printf("tunnelLUID: device does not expose LUID()")
	return 0
}

func netipAddrFromString(s string) (netip.Addr, error) {
	return netip.ParseAddr(s)
}

// getInterfaceIndex returns the Windows interface index of the tunnel
// adapter using a direct syscall lookup (net.InterfaceByName). Kept only for
// the route.exe fallback path.
func getInterfaceIndex() string {
	iface, err := net.InterfaceByName(tunnelInterfaceName)
	if err != nil {
		log.Printf("getInterfaceIndex: InterfaceByName failed: %v", err)
		return ""
	}
	return fmt.Sprintf("%d", iface.Index)
}

func runNetsh(args ...string) {
	cmd := exec.Command("netsh", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	log.Printf("netsh %s -> %s (err=%v)", strings.Join(args, " "), strings.TrimSpace(string(out)), err)
}

func runCmd(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	log.Printf("%s %s -> %s (err=%v)", name, strings.Join(args, " "), strings.TrimSpace(string(out)), err)
}

// ─── Status (CLI side) ───────────────────────────────────

func tunnelStatus() string {
	reply, err := tryCommand("STATUS", "")
	if err != nil {
		// Control channel unreachable: either the service was never
		// installed, or it's not running. Either way, from the UI's
		// point of view that's simply "not connected" — no error text,
		// no English exception strings leaking into the tray/UI.
		return "STOPPED"
	}
	if strings.HasPrefix(reply, "RUNNING") {
		return "RUNNING"
	}
	return "STOPPED"
}

// ─── Named-pipe control channel ─────────────────────────
//
// Replaces the old unauthenticated loopback TCP socket. Access control is
// done by the OS via the pipe's DACL (see pipeSDDL) rather than by anything
// in this file — an unprivileged caller fails at CreateFile with
// ERROR_ACCESS_DENIED and never gets to send a command.
//
// The rest of the code still speaks net.Listener / net.Conn, so the service
// loop and the command protocol are unchanged.

// verbosef is the WireGuard device's verbose logger. It is a no-op unless
// KITOFTOR_DEBUG=1 is set in the environment: at verbose level the device
// logs every handshake, which is what used to bloat debug.log.
var verbosef = func(format string, args ...any) {}

func init() {
	if os.Getenv("KITOFTOR_DEBUG") == "1" {
		verbosef = log.Printf
	}
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return pipeName }

// pipeConn adapts a pipe HANDLE to net.Conn.
//
// Deadlines are implemented by closing the handle on a timer rather than by
// the socket layer (a synchronous pipe handle has no deadline support). The
// effect on the calling code is the same: a stuck peer cannot hold the
// connection open forever.
type pipeConn struct {
	f      *os.File
	server bool

	mu    sync.Mutex
	timer *time.Timer
}

func (c *pipeConn) Read(b []byte) (int, error)  { return c.f.Read(b) }
func (c *pipeConn) Write(b []byte) (int, error) { return c.f.Write(b) }

func (c *pipeConn) Close() error {
	c.mu.Lock()
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	c.mu.Unlock()
	if c.server {
		// Let the client observe end-of-file before the handle goes away.
		windows.DisconnectNamedPipe(windows.Handle(c.f.Fd()))
	}
	return c.f.Close()
}

func (c *pipeConn) LocalAddr() net.Addr  { return pipeAddr{} }
func (c *pipeConn) RemoteAddr() net.Addr { return pipeAddr{} }

func (c *pipeConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	if t.IsZero() {
		return nil
	}
	d := time.Until(t)
	if d <= 0 {
		d = time.Millisecond
	}
	f := c.f
	c.timer = time.AfterFunc(d, func() { f.Close() })
	return nil
}

func (c *pipeConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *pipeConn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

// pipeListener creates one pipe instance per Accept, which is the standard
// Win32 pattern: the instance is handed to the client that connects to it,
// and the next Accept creates a fresh one.
type pipeListener struct {
	sa     *windows.SecurityAttributes
	closed chan struct{}
	once   sync.Once
}

func newPipeListener() (*pipeListener, error) {
	sd, err := windows.SecurityDescriptorFromString(pipeSDDL)
	if err != nil {
		return nil, fmt.Errorf("bad pipe SDDL: %v", err)
	}
	sa := &windows.SecurityAttributes{
		SecurityDescriptor: sd,
		InheritHandle:      0,
	}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	return &pipeListener{sa: sa, closed: make(chan struct{})}, nil
}

func (l *pipeListener) Accept() (net.Conn, error) {
	namePtr, err := windows.UTF16PtrFromString(pipeName)
	if err != nil {
		return nil, err
	}

	h, err := windows.CreateNamedPipe(
		namePtr,
		pipeAccessDuplex,
		pipeTypeByte|pipeReadmodeByte|pipeWait|pipeRejectRemoteClients,
		pipeUnlimitedInstances,
		4096,  // out buffer
		65536, // in buffer — a whitelist-expanded config can be large
		0,
		l.sa,
	)
	if err != nil {
		return nil, fmt.Errorf("CreateNamedPipe failed: %v", err)
	}

	// Blocks until a permitted client connects. Close() unblocks this by
	// connecting to the pipe itself.
	err = windows.ConnectNamedPipe(h, nil)
	if err != nil && err != errPipeConnected {
		windows.CloseHandle(h)
		select {
		case <-l.closed:
			return nil, io.EOF
		default:
		}
		return nil, err
	}

	select {
	case <-l.closed:
		windows.CloseHandle(h)
		return nil, io.EOF
	default:
	}

	return &pipeConn{f: os.NewFile(uintptr(h), pipeName), server: true}, nil
}

func (l *pipeListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
		// Wake up the Accept currently parked in ConnectNamedPipe. Without
		// this the service would hang on stop until some client happened to
		// connect — including during a machine shutdown.
		if h, err := dialPipeRaw(500 * time.Millisecond); err == nil {
			windows.CloseHandle(h)
		}
	})
	return nil
}

func (l *pipeListener) Addr() net.Addr { return pipeAddr{} }

// dialPipeRaw opens the control pipe, retrying while all instances are busy.
// ERROR_ACCESS_DENIED here means the caller is not SYSTEM or an
// administrator, and is returned as-is.
func dialPipeRaw(timeout time.Duration) (windows.Handle, error) {
	namePtr, err := windows.UTF16PtrFromString(pipeName)
	if err != nil {
		return 0, err
	}
	deadline := time.Now().Add(timeout)
	for {
		h, err := windows.CreateFile(
			namePtr,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			0, nil,
			windows.OPEN_EXISTING,
			0, 0,
		)
		if err == nil {
			return h, nil
		}
		if err != errPipeBusy || time.Now().After(deadline) {
			return 0, err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func dialPipe(timeout time.Duration) (net.Conn, error) {
	h, err := dialPipeRaw(timeout)
	if err != nil {
		return nil, err
	}
	return &pipeConn{f: os.NewFile(uintptr(h), pipeName), server: false}, nil
}
