package service

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/load"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/net"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
	"x-ui/logger"
	"x-ui/util/sys"
	"x-ui/xray"
)

type ProcessState string

const (
	Running ProcessState = "running"
	Stop    ProcessState = "stop"
	Error   ProcessState = "error"
)

type Status struct {
	T   time.Time `json:"-"`
	Cpu float64   `json:"cpu"`
	Mem struct {
		Current uint64 `json:"current"`
		Total   uint64 `json:"total"`
	} `json:"mem"`
	Swap struct {
		Current uint64 `json:"current"`
		Total   uint64 `json:"total"`
	} `json:"swap"`
	Disk struct {
		Current uint64 `json:"current"`
		Total   uint64 `json:"total"`
	} `json:"disk"`
	Xray struct {
		State    ProcessState `json:"state"`
		ErrorMsg string       `json:"errorMsg"`
		Version  string       `json:"version"`
	} `json:"xray"`
	Uptime   uint64    `json:"uptime"`
	Loads    []float64 `json:"loads"`
	TcpCount int       `json:"tcpCount"`
	UdpCount int       `json:"udpCount"`
	NetIO    struct {
		Up   uint64 `json:"up"`
		Down uint64 `json:"down"`
	} `json:"netIO"`
	NetTraffic struct {
		Sent uint64 `json:"sent"`
		Recv uint64 `json:"recv"`
	} `json:"netTraffic"`
}

type Release struct {
	TagName string `json:"tag_name"`
}

type ServerService struct {
	xrayService XrayService
}

func parseXrayKeyPairOutput(output string) (string, string, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) < 2 {
		return "", "", fmt.Errorf("unexpected xray key generator output")
	}
	first := strings.SplitN(lines[0], ":", 2)
	second := strings.SplitN(lines[1], ":", 2)
	if len(first) != 2 || len(second) != 2 {
		return "", "", fmt.Errorf("unexpected xray key generator output")
	}
	return strings.TrimSpace(first[1]), strings.TrimSpace(second[1]), nil
}

func (s *ServerService) GetNewX25519Cert() (map[string]string, error) {
	output, err := exec.Command(xray.GetBinaryPath(), "x25519").Output()
	if err != nil {
		return nil, err
	}
	privateKey, publicKey, err := parseXrayKeyPairOutput(string(output))
	if err != nil {
		return nil, err
	}
	return map[string]string{"privateKey": privateKey, "publicKey": publicKey}, nil
}

func (s *ServerService) GetNewMldsa65() (map[string]string, error) {
	output, err := exec.Command(xray.GetBinaryPath(), "mldsa65").Output()
	if err != nil {
		return nil, err
	}
	seed, verify, err := parseXrayKeyPairOutput(string(output))
	if err != nil {
		return nil, err
	}
	return map[string]string{"seed": seed, "verify": verify}, nil
}

func (s *ServerService) GetNewVlessEnc() ([]map[string]string, error) {
	output, err := exec.Command(xray.GetBinaryPath(), "vlessenc").Output()
	if err != nil {
		return nil, err
	}
	auths := parseVlessEncAuths(string(output))
	if len(auths) == 0 {
		return nil, fmt.Errorf("unexpected xray vlessenc output")
	}
	auths = append(auths, deriveVlessEncModes(auths)...)
	return auths, nil
}

func deriveVlessEncModes(auths []map[string]string) []map[string]string {
	var extra []map[string]string
	for _, auth := range auths {
		for _, mode := range []string{"xorpub", "random"} {
			decryption := strings.Replace(auth["decryption"], ".native.", "."+mode+".", 1)
			encryption := strings.Replace(auth["encryption"], ".native.", "."+mode+".", 1)
			if decryption == auth["decryption"] && encryption == auth["encryption"] {
				continue
			}
			extra = append(extra, map[string]string{
				"id":         auth["id"] + "_" + mode,
				"label":      auth["label"] + " (" + mode + ")",
				"decryption": decryption,
				"encryption": encryption,
			})
		}
	}
	return extra
}

func parseVlessEncAuths(output string) []map[string]string {
	var auths []map[string]string
	var current map[string]string
	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "Authentication:") {
			if current != nil {
				auths = append(auths, current)
			}
			label := strings.TrimSpace(strings.TrimPrefix(line, "Authentication:"))
			normalized := strings.NewReplacer("-", "", "_", "", " ", "").Replace(strings.ToLower(label))
			id := normalized
			if strings.Contains(normalized, "mlkem768") {
				id = "mlkem768"
			} else if strings.Contains(normalized, "x25519") {
				id = "x25519"
			}
			current = map[string]string{"id": id, "label": label}
			continue
		}
		if current == nil || (!strings.HasPrefix(line, `"decryption"`) && !strings.HasPrefix(line, `"encryption"`)) {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.Trim(parts[0], `" `)
		value := strings.Trim(strings.TrimSuffix(strings.TrimSpace(parts[1]), ","), `" `)
		current[key] = value
	}
	if current != nil {
		auths = append(auths, current)
	}
	return auths
}

func (s *ServerService) GetStatus(lastStatus *Status) *Status {
	now := time.Now()
	status := &Status{
		T: now,
	}

	percents, err := cpu.Percent(0, false)
	if err != nil {
		logger.Warning("get cpu percent failed:", err)
	} else {
		status.Cpu = percents[0]
	}

	upTime, err := host.Uptime()
	if err != nil {
		logger.Warning("get uptime failed:", err)
	} else {
		status.Uptime = upTime
	}

	memInfo, err := mem.VirtualMemory()
	if err != nil {
		logger.Warning("get virtual memory failed:", err)
	} else {
		status.Mem.Current = memInfo.Used
		status.Mem.Total = memInfo.Total
	}

	swapInfo, err := mem.SwapMemory()
	if err != nil {
		logger.Warning("get swap memory failed:", err)
	} else {
		status.Swap.Current = swapInfo.Used
		status.Swap.Total = swapInfo.Total
	}

	distInfo, err := disk.Usage("/")
	if err != nil {
		logger.Warning("get dist usage failed:", err)
	} else {
		status.Disk.Current = distInfo.Used
		status.Disk.Total = distInfo.Total
	}

	avgState, err := load.Avg()
	if err != nil {
		logger.Warning("get load avg failed:", err)
	} else {
		status.Loads = []float64{avgState.Load1, avgState.Load5, avgState.Load15}
	}

	ioStats, err := net.IOCounters(false)
	if err != nil {
		logger.Warning("get io counters failed:", err)
	} else if len(ioStats) > 0 {
		ioStat := ioStats[0]
		status.NetTraffic.Sent = ioStat.BytesSent
		status.NetTraffic.Recv = ioStat.BytesRecv

		if lastStatus != nil {
			duration := now.Sub(lastStatus.T)
			seconds := float64(duration) / float64(time.Second)
			up := uint64(float64(status.NetTraffic.Sent-lastStatus.NetTraffic.Sent) / seconds)
			down := uint64(float64(status.NetTraffic.Recv-lastStatus.NetTraffic.Recv) / seconds)
			status.NetIO.Up = up
			status.NetIO.Down = down
		}
	} else {
		logger.Warning("can not find io counters")
	}

	status.TcpCount, err = sys.GetTCPCount()
	if err != nil {
		logger.Warning("get tcp connections failed:", err)
	}

	status.UdpCount, err = sys.GetUDPCount()
	if err != nil {
		logger.Warning("get udp connections failed:", err)
	}

	if s.xrayService.IsXrayRunning() {
		status.Xray.State = Running
		status.Xray.ErrorMsg = ""
	} else {
		err := s.xrayService.GetXrayErr()
		if err != nil {
			status.Xray.State = Error
		} else {
			status.Xray.State = Stop
		}
		status.Xray.ErrorMsg = s.xrayService.GetXrayResult()
	}
	status.Xray.Version = s.xrayService.GetXrayVersion()

	return status
}

func (s *ServerService) GetXrayVersions() ([]string, error) {
	url := "https://api.github.com/repos/XTLS/Xray-core/releases"
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	buffer := bytes.NewBuffer(make([]byte, 8192))
	buffer.Reset()
	_, err = buffer.ReadFrom(resp.Body)
	if err != nil {
		return nil, err
	}

	releases := make([]Release, 0)
	err = json.Unmarshal(buffer.Bytes(), &releases)
	if err != nil {
		return nil, err
	}
	versions := make([]string, 0, len(releases))
	for _, release := range releases {
		versions = append(versions, release.TagName)
	}
	return versions, nil
}

func (s *ServerService) downloadXRay(version string) (string, error) {
	osName := runtime.GOOS
	arch := runtime.GOARCH

	switch osName {
	case "darwin":
		osName = "macos"
	}

	switch arch {
	case "amd64":
		arch = "64"
	case "arm64":
		arch = "arm64-v8a"
	}

	fileName := fmt.Sprintf("Xray-%s-%s.zip", osName, arch)
	url := fmt.Sprintf("https://github.com/XTLS/Xray-core/releases/download/%s/%s", version, fileName)
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	os.Remove(fileName)
	file, err := os.Create(fileName)
	if err != nil {
		return "", err
	}
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return "", err
	}

	return fileName, nil
}

func (s *ServerService) UpdateXray(version string) error {
	zipFileName, err := s.downloadXRay(version)
	if err != nil {
		return err
	}

	zipFile, err := os.Open(zipFileName)
	if err != nil {
		return err
	}
	defer func() {
		zipFile.Close()
		os.Remove(zipFileName)
	}()

	stat, err := zipFile.Stat()
	if err != nil {
		return err
	}
	reader, err := zip.NewReader(zipFile, stat.Size())
	if err != nil {
		return err
	}

	s.xrayService.StopXray()
	defer func() {
		err := s.xrayService.RestartXray(true)
		if err != nil {
			logger.Error("start xray failed:", err)
		}
	}()

	copyZipFile := func(zipName string, fileName string) error {
		zipFile, err := reader.Open(zipName)
		if err != nil {
			return err
		}
		os.Remove(fileName)
		file, err := os.OpenFile(fileName, os.O_CREATE|os.O_RDWR|os.O_TRUNC, fs.ModePerm)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.Copy(file, zipFile)
		return err
	}

	err = copyZipFile("xray", xray.GetBinaryPath())
	if err != nil {
		return err
	}
	err = copyZipFile("geosite.dat", xray.GetGeositePath())
	if err != nil {
		return err
	}
	err = copyZipFile("geoip.dat", xray.GetGeoipPath())
	if err != nil {
		return err
	}

	return nil

}
