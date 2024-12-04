package cgroup

import (
	"bufio"
	"bytes"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Stats contains metrics and limits from each of the cgroup subsystems.
type Stats struct {
	Metadata
	CPU           *CPUSubsystem           `json:"cpu"`
	CPUAccounting *CPUAccountingSubsystem `json:"cpuacct"`
	Memory        *MemorySubsystem        `json:"memory"`
	BlockIO       *BlockIOSubsystem       `json:"blkio"`
}

// Metadata contains metadata associated with cgroup stats.
type Metadata struct {
	ID   string `json:"id,omitempty"`   // ID of the cgroup.
	Path string `json:"path,omitempty"` // Path to the cgroup relative to the cgroup subsystem's mountpoint.
}

type mount struct {
	subsystem  string // Subsystem name (e.g. cpuacct).
	mountpoint string // Mountpoint of the subsystem (e.g. /cgroup/cpuacct).
	path       string // Relative path to the cgroup (e.g. /docker/<id>).
	id         string // ID of the cgroup.
	fullPath   string // Absolute path to the cgroup. It's the mountpoint joined with the path.
}

// Reader reads cgroup metrics and limits.
type Reader struct {
	// Mountpoint of the root filesystem. Defaults to / if not set. This can be
	// useful for example if you mount / as /rootfs inside of a container.
	rootfsMountpoint         string
	ignoreRootCgroups        bool // Ignore a cgroup when its path is "/".
	cgroupsHierarchyOverride string
	cgroupMountpoints        map[string]string // Mountpoints for each subsystem (e.g. cpu, cpuacct, memory, blkio).
}

// ReaderOptions holds options for NewReaderOptions.
type ReaderOptions struct {
	// RootfsMountpoint holds the mountpoint of the root filesystem.
	//
	// If unspecified, "/" is assumed.
	RootfsMountpoint string

	// IgnoreRootCgroups ignores cgroup subsystem with the path "/".
	IgnoreRootCgroups bool

	// CgroupsHierarchyOverride is an optional path override for cgroup
	// subsystem paths. If non-empty, this will be used instead of the
	// paths specified in /proc/<pid>/cgroup.
	//
	// This should be set to "/" when running within a Docker container,
	// where the paths in /proc/<pid>/cgroup do not correspond to any
	// paths under /sys/fs/cgroup.
	CgroupsHierarchyOverride string
}

// NewReader creates and returns a new Reader.
func NewReader(rootfsMountpoint string, ignoreRootCgroups bool) (*Reader, error) {
	return NewReaderOptions(ReaderOptions{
		RootfsMountpoint:  rootfsMountpoint,
		IgnoreRootCgroups: ignoreRootCgroups,
	})
}

// NewReaderOptions creates and returns a new Reader with the given options.
func NewReaderOptions(opts ReaderOptions) (*Reader, error) {
	if opts.RootfsMountpoint == "" {
		opts.RootfsMountpoint = "/"
	}

	// Determine what subsystems are supported by the kernel.
	subsystems, err := SupportedSubsystems(opts.RootfsMountpoint)
	if err != nil {
		return nil, err
	}

	// Locate the mountpoints of those subsystems.
	mountpoints, err := SubsystemMountpoints(opts.RootfsMountpoint, subsystems)
	if err != nil {
		return nil, err
	}

	return &Reader{
		rootfsMountpoint:         opts.RootfsMountpoint,
		ignoreRootCgroups:        opts.IgnoreRootCgroups,
		cgroupsHierarchyOverride: opts.CgroupsHierarchyOverride,
		cgroupMountpoints:        mountpoints,
	}, nil
}

// GetStatsForProcess returns cgroup metrics and limits associated with a process.
func (r *Reader) GetStatsForProcess(pid int) (*Stats, error) {
	// Read /proc/[pid]/cgroup to get the paths to the cgroup metrics.
	paths, err := ProcessCgroupPaths(r.rootfsMountpoint, pid)
	if err != nil {
		return nil, err
	}

	// Build the full path for the subsystems we are interested in.
	mounts := map[string]mount{}
	for _, interestedSubsystem := range []string{"blkio", "cpu", "cpuacct", "memory"} {
		path, found := paths[interestedSubsystem]
		if !found {
			continue
		}

		if path == "/" && r.ignoreRootCgroups {
			continue
		}

		subsystemMount, found := r.cgroupMountpoints[interestedSubsystem]
		if !found {
			continue
		}

		id := filepath.Base(path)
		if r.cgroupsHierarchyOverride != "" {
			path = r.cgroupsHierarchyOverride
		}
		fullPath := filepath.Join(subsystemMount, path)
		if !Exists(fullPath) {
			fullPath = subsystemMount
		}
		mounts[interestedSubsystem] = mount{
			subsystem:  interestedSubsystem,
			mountpoint: subsystemMount,
			id:         id,
			path:       path,
			fullPath:   fullPath,
		}
	}

	stats := Stats{Metadata: getCommonCgroupMetadata(mounts)}

	// Collect stats from each cgroup subsystem associated with the task.
	if mount, found := mounts["blkio"]; found {
		stats.BlockIO = &BlockIOSubsystem{}
		err := stats.BlockIO.get(mount.fullPath)
		if err != nil {
			return nil, err
		}
		stats.BlockIO.Metadata.ID = mount.id
		stats.BlockIO.Metadata.Path = mount.path
	}
	if mount, found := mounts["cpu"]; found {
		stats.CPU = &CPUSubsystem{}
		err := stats.CPU.get(mount.fullPath)
		if err != nil {
			return nil, err
		}
		stats.CPU.Metadata.ID = mount.id
		stats.CPU.Metadata.Path = mount.path
	}
	if mount, found := mounts["cpuacct"]; found {
		stats.CPUAccounting = &CPUAccountingSubsystem{}
		err := stats.CPUAccounting.get(mount.fullPath)
		if err != nil {
			return nil, err
		}
		stats.CPUAccounting.Metadata.ID = mount.id
		stats.CPUAccounting.Metadata.Path = mount.path
	}
	if mount, found := mounts["memory"]; found {
		stats.Memory = &MemorySubsystem{}
		err := stats.Memory.get(mount.fullPath)
		if err != nil {
			return nil, err
		}
		stats.Memory.Metadata.ID = mount.id
		stats.Memory.Metadata.Path = mount.path
	}

	// Return nil if no metrics were collected.
	if stats.BlockIO == nil && stats.CPU == nil && stats.CPUAccounting == nil && stats.Memory == nil {
		return nil, nil
	}

	return &stats, nil
}

// getCommonCgroupMetadata returns Metadata containing the cgroup path and ID
// iff all subsystems share a common path and ID. This is common for
// containerized processes. If there is no common path and ID then the returned
// values are empty strings.
func getCommonCgroupMetadata(mounts map[string]mount) Metadata {
	var path string
	for _, m := range mounts {
		if path == "" {
			path = m.path
		} else if path != m.path {
			// All paths are not the same.
			return Metadata{}
		}
	}

	return Metadata{Path: path, ID: filepath.Base(path)}
}

func GetCPUAcctStats(pid int) (CPUAccountingSubsystem, error) {
	return getCPUAcctStats("/", pid)
}

func GetCPUStats(pid int) (CPUSubsystem, error) {
	return getCPUStats("/", pid)
}

func GetMemLimit(pid int) (int64, error) {
	return getMemLimit("/", pid)
}

func GetMemUsage(pid int) (int64, error) {
	return getMemUsage("/", pid)
}

func getCPUAcctStats(root string, pid int) (CPUAccountingSubsystem, error) {
	vms, path, err := getVersionMountAndPath(root, pid, "cpu,cpuacct")
	if err != nil {
		return CPUAccountingSubsystem{}, err
	}

	var cpuAcct CPUAccountingSubsystem
	if len(vms) == 2 { // there are two versions in the system, we use v2 by priority.
		err := cpuAcct.getV2(filepath.Join(root, vms[1].mountPoint, path))
		if err != nil {
			err = cpuAcct.get(filepath.Join(root, vms[0].mountPoint))
		}
		if err != nil {
			return CPUAccountingSubsystem{}, nil
		}
	} else {
		if len(vms) != 1 {
			return CPUAccountingSubsystem{}, errors.New("failed to get cpu cgroup mount info")
		}
		if vms[0].version == 1 {
			if err = cpuAcct.get(filepath.Join(root, vms[0].mountPoint)); err != nil {
				return CPUAccountingSubsystem{}, err
			}
		} else if vms[0].version == 2 {
			if err = cpuAcct.getV2(filepath.Join(root, vms[0].mountPoint, path)); err != nil {
				return CPUAccountingSubsystem{}, err
			}
		}
	}
	return cpuAcct, nil
}

func getCPUStats(root string, pid int) (CPUSubsystem, error) {
	vms, path, err := getVersionMountAndPath(root, pid, "cpu,cpuacct")
	if err != nil {
		return CPUSubsystem{}, err
	}

	var cpu CPUSubsystem
	if len(vms) == 2 { // there are two versions in the system, we use v2 by priority.
		err := cpu.getV2(filepath.Join(root, vms[1].mountPoint, path))
		if err != nil {
			err = cpu.get(filepath.Join(root, vms[0].mountPoint))
		}
		if err != nil {
			return CPUSubsystem{}, nil
		}
	} else {
		if len(vms) != 1 {
			return CPUSubsystem{}, errors.New("failed to get cgroup mount info")
		}
		if vms[0].version == 1 {
			if err = cpu.get(filepath.Join(root, vms[0].mountPoint)); err != nil {
				return CPUSubsystem{}, err
			}
		} else if vms[0].version == 2 {
			if err = cpu.getV2(filepath.Join(root, vms[0].mountPoint, path)); err != nil {
				return CPUSubsystem{}, err
			}
		}
	}
	return cpu, nil
}

func getMemLimit(root string, pid int) (int64, error) {
	vms, path, err := getVersionMountAndPath(root, pid, "memory")
	if err != nil {
		return 0, err
	}

	var limit int64
	if len(vms) == 2 {
		limit, err = getMemLimitV2(filepath.Join(root, vms[1].mountPoint, path))
		if err != nil {
			limit, err = getMemLimitV1(filepath.Join(root, vms[0].mountPoint))
		}
	} else {
		if len(vms) != 1 {
			return 0, errors.New("failed to get cgroup mount info")
		}
		if vms[0].version == 1 {
			limit, err = getMemLimitV1(filepath.Join(root, vms[0].mountPoint))
			if err != nil {
				return 0, err
			}
		} else if vms[0].version == 2 {
			limit, err = getMemLimitV2(filepath.Join(root, vms[0].mountPoint, path))
			if err != nil {
				return 0, err
			}
		}
	}
	return limit, nil
}

func getMemUsage(root string, pid int) (int64, error) {
	vms, path, err := getVersionMountAndPath(root, pid, "memory")
	if err != nil {
		return 0, err
	}

	var usage int64
	if len(vms) == 2 {
		usage, err = getMemUsageV2(filepath.Join(root, vms[1].mountPoint, path))
		if err != nil {
			usage, err = getMemUsageV1(filepath.Join(root, vms[0].mountPoint))
		}
	} else {
		if len(vms) != 1 {
			return 0, errors.New("failed to get cgroup mount info")
		}
		if vms[0].version == 1 {
			usage, err = getMemUsageV1(filepath.Join(root, vms[0].mountPoint))
			if err != nil {
				return 0, err
			}
		} else if vms[0].version == 2 {
			usage, err = getMemUsageV2(filepath.Join(root, vms[0].mountPoint, path))
			if err != nil {
				return 0, err
			}
		}
	}
	return usage, nil
}

func getMemLimitV1(root string) (int64, error) {
	return readInt64Value(root, "memory.stat", "hierarchical_memory_limit")
}

func getMemLimitV2(root string) (int64, error) {
	v, err := readInt64Value(root, "memory.max", "")
	if err != nil {
		return 0, err
	}
	if v == math.MaxInt64 {
		v, err = readInt64Value("/proc", "meminfo", "MemTotal:")
		if err != nil {
			return 0, err
		}
		return v * 1024, nil // convert kb to bytes
	}
	return v, nil
}

func getMemUsageV1(root string) (int64, error) {
	return readInt64Value(root, "memory.usage_in_bytes", "")
}

func getMemUsageV2(root string) (int64, error) {
	return readInt64Value(root, "memory.current", "")
}

type versionMount struct {
	version    int
	mountPoint string
}

func getCgroupVersion(fields [][]byte, controller string) (int, bool) {
	if len(fields) < 10 {
		return 0, false
	}
	var pos = 6
	for pos < len(fields) {
		if bytes.Equal(fields[pos], []byte{'-'}) {
			break
		}
		pos++
	}
	if (len(fields) - pos - 1) < 3 {
		return 0, false
	}
	pos++
	if bytes.Equal(fields[pos], []byte("cgroup")) &&
		controllerCompare(string(fields[pos+2]), controller, true) {
		return 1, true
	} else if bytes.Equal(fields[pos], []byte("cgroup2")) {
		return 2, true
	}
	return 0, false
}

func getCgroupMount(mountInfoFilePath string, controllerPath string, controller string) ([]versionMount, error) {
	info, err := os.Open(mountInfoFilePath)
	if err != nil {
		return []versionMount{}, err
	}
	defer func() { _ = info.Close() }()

	var foundV1, foundV2 = false, false
	var mountPointV1, mountPointV2 string

	sc := bufio.NewScanner(info)
	for sc.Scan() {
		fields := bytes.Fields(sc.Bytes())
		if len(fields) < 10 {
			continue
		}
		ver, ok := getCgroupVersion(fields, controller)
		if ok {
			mountPoint := string(fields[4])
			if ver == 2 {
				foundV2 = true
				mountPointV2 = mountPoint
				continue
			}
			nsRelativePath := string(fields[3])
			if !strings.Contains(nsRelativePath, "..") {
				if relPath, err := filepath.Rel(nsRelativePath, controllerPath); err == nil {
					mountPointV1 = filepath.Join(mountPoint, relPath)
					foundV1 = true
				}
			}
		}
	}
	if foundV1 && foundV2 {
		return []versionMount{
			{version: 1, mountPoint: mountPointV1},
			{version: 2, mountPoint: mountPointV2},
		}, nil
	}
	if foundV1 {
		return []versionMount{
			{version: 1, mountPoint: mountPointV1},
		}, nil
	}
	if foundV2 {
		return []versionMount{
			{version: 2, mountPoint: mountPointV2},
		}, nil
	}
	return []versionMount{}, errors.New("failed to detect cgroup root mount and version")
}

func processControllerPath(cgroupFilePath string, controller string) (string, error) {
	cgroup, err := os.Open(cgroupFilePath)
	if err != nil {
		return "", err
	}
	defer func() { _ = cgroup.Close() }()

	var unifiedPath string
	sc := bufio.NewScanner(cgroup)
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Split(line, ":")
		if len(fields) != 3 {
			continue
		}
		if fields[0] == "0" && fields[1] == "" {
			unifiedPath = fields[2]
		} else if controllerCompare(fields[1], controller, false) {
			return fields[2], nil
		}
	}
	return unifiedPath, nil
}

func getVersionMountAndPath(root string, pid int, controller string) ([]versionMount, string, error) {
	path, err := processControllerPath(filepath.Join(root, "proc", strconv.Itoa(pid), "cgroup"), controller)
	if err != nil {
		return nil, "", err
	}
	if path == "" {
		return nil, "", errors.New("cpu controller not found")
	}
	vms, err := getCgroupMount(filepath.Join(root, "proc", strconv.Itoa(pid), "mountinfo"), path, controller)
	if err != nil {
		return nil, "", err
	}
	return vms, path, nil
}

func readInt64Value(root, filename, key string) (int64, error) {
	filePath := filepath.Join(root, filename)
	f, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	var value int64
	for sc.Scan() {
		if key == "" {
			data := sc.Bytes()
			trimmed := string(bytes.TrimSpace(data))
			if trimmed == "max" {
				return math.MaxInt64, nil
			}
			value, err = strconv.ParseInt(trimmed, 10, 64)
			if err != nil {
				return 0, err
			}
			return value, nil
		} else {
			fields := bytes.Fields(sc.Bytes())
			if len(fields) < 2 || string(fields[0]) != key {
				continue
			}
			trimmed := string(bytes.TrimSpace(fields[1]))
			value, err = strconv.ParseInt(trimmed, 10, 64)
			if err != nil {
				return 0, err
			}
			return value, nil
		}
	}
	return value, nil
}

func controllerCompare(content, controller string, contain bool) bool {
	if content == "" || controller == "" {
		return false
	}
	controllerItems := strings.Split(controller, ",")
	contentItems := strings.Split(content, ",")
	if !contain {
		if len(contentItems) != len(controllerItems) {
			return false
		}
	}
	contentItemMap := make(map[string]struct{}, len(contentItems))
	for _, contentItem := range contentItems {
		contentItemMap[contentItem] = struct{}{}
	}
	for _, controllerItem := range controllerItems {
		if _, ok := contentItemMap[controllerItem]; !ok {
			return false
		}
	}
	return true
}
