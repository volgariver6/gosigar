package cgroup

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// CPUSubsystem contains metrics and limits from the "cpu" subsystem. This
// subsystem is used to guarantee a minimum number of cpu shares to the cgroup
// when the system is busy. This subsystem does not track CPU usage, for that
// information see the "cpuacct" subsystem.
type CPUSubsystem struct {
	Metadata
	// Completely Fair Scheduler (CFS) settings.
	CFS CFS `json:"cfs,omitempty"`
	// Real-time (RT) Scheduler settings.
	RT RT `json:"rt,omitempty"`
	// CPU time statistics for tasks in this cgroup.
	Stats ThrottleStats `json:"stats,omitempty"`
}

// RT contains the tunable parameters for the real-time scheduler.
type RT struct {
	// Period of time in microseconds for how regularly the cgroup's access to
	// CPU resources should be reallocated.
	PeriodMicros uint64 `json:"period_us"`
	// Period of time in microseconds for the longest continuous period in which
	// the tasks in the cgroup have access to CPU resources.
	RuntimeMicros uint64 `json:"quota_us"`
}

// CFS contains the tunable parameters for the completely fair scheduler.
type CFS struct {
	// Period of time in microseconds for how regularly the cgroup's access to
	// CPU resources should be reallocated.
	PeriodMicros uint64 `json:"period_us"`
	// Total amount of time in microseconds for which all tasks in the cgroup
	// can run during one period.
	QuotaMicros uint64 `json:"quota_us"`
	// Relative share of CPU time available to tasks the cgroup. The value is
	// an integer greater than or equal to 2.
	Shares uint64 `json:"shares"`
}

// ThrottleStats contains stats that indicate the extent to which this cgroup's
// CPU usage was throttled.
type ThrottleStats struct {
	// Number of periods with throttling active.
	Periods uint64 `json:"periods,omitempty"`
	// Number of periods when the cgroup hit its throttling limit.
	ThrottledPeriods uint64 `json:"throttled_periods,omitempty"`
	// Aggregate time the cgroup was throttled for in nanoseconds.
	ThrottledTimeNanos uint64 `json:"throttled_nanos,omitempty"`
}

// get reads metrics from the "cpu" subsystem. path is the filepath to the
// cgroup hierarchy to read.
func (cpu *CPUSubsystem) get(path string) error {
	if err := cpuCFS(path, cpu); err != nil {
		return err
	}

	if err := cpuRT(path, cpu); err != nil {
		return err
	}

	if err := cpuStat(path, cpu); err != nil {
		return err
	}

	return nil
}

func (cpu *CPUSubsystem) getV2(path string) error {
	if err := cpuCFSV2(path, cpu); err != nil {
		return err
	}
	return nil
}

func cpuStat(path string, cpu *CPUSubsystem) error {
	f, err := os.Open(filepath.Join(path, "cpu.stat"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		t, v, err := parseCgroupParamKeyValue(sc.Text())
		if err != nil {
			return err
		}
		switch t {
		case "nr_periods":
			cpu.Stats.Periods = v

		case "nr_throttled":
			cpu.Stats.ThrottledPeriods = v

		case "throttled_time":
			cpu.Stats.ThrottledTimeNanos = v
		}
	}

	return sc.Err()
}

func cpuCFS(path string, cpu *CPUSubsystem) error {
	var err error
	cpu.CFS.PeriodMicros, err = parseUintFromFile(path, "cpu.cfs_period_us")
	if err != nil {
		return err
	}

	cpu.CFS.QuotaMicros, err = parseUintFromFile(path, "cpu.cfs_quota_us")
	if err != nil {
		return err
	}

	cpu.CFS.Shares, err = parseUintFromFile(path, "cpu.shares")
	if err != nil {
		return err
	}

	return nil
}

func cpuCFSV2(path string, cpu *CPUSubsystem) error {
	fp := filepath.Join(path, "cpu.max")
	f, err := os.Open(fp)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	contents, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	fields := strings.Fields(string(contents))
	if len(fields) > 2 || len(fields) == 0 {
		return fmt.Errorf("error format of file %s: %s", fp, contents)
	}
	if fields[0] == "max" {
		cpu.CFS.QuotaMicros = 0
	} else {
		cpu.CFS.QuotaMicros, err = parseUint([]byte(fields[0]))
		if err != nil {
			return err
		}
	}
	if len(fields) == 2 {
		cpu.CFS.PeriodMicros, err = parseUint([]byte(fields[1]))
		if err != nil {
			return err
		}
	}
	return nil
}

func cpuRT(path string, cpu *CPUSubsystem) error {
	var err error
	cpu.RT.PeriodMicros, err = parseUintFromFile(path, "cpu.rt_period_us")
	if err != nil {
		return err
	}

	cpu.RT.RuntimeMicros, err = parseUintFromFile(path, "cpu.rt_runtime_us")
	if err != nil {
		return err
	}

	return nil
}
