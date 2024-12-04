package cgroup

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	path = "/docker/b29faf21b7eff959f64b4192c34d5d67a707fe8561e9eaa608cb27693fba4242"
	id   = "b29faf21b7eff959f64b4192c34d5d67a707fe8561e9eaa608cb27693fba4242"
)

func TestReaderGetStats(t *testing.T) {
	reader, err := NewReader("testdata/docker", true)
	if err != nil {
		t.Fatal(err)
	}

	stats, err := reader.GetStatsForProcess(985)
	if err != nil {
		t.Fatal(err)
	}
	if stats == nil {
		t.Fatal("no cgroup stats found")
	}

	assert.Equal(t, id, stats.ID)
	assert.Equal(t, id, stats.BlockIO.ID)
	assert.Equal(t, id, stats.CPU.ID)
	assert.Equal(t, id, stats.CPUAccounting.ID)
	assert.Equal(t, id, stats.Memory.ID)

	assert.Equal(t, path, stats.Path)
	assert.Equal(t, path, stats.BlockIO.Path)
	assert.Equal(t, path, stats.CPU.Path)
	assert.Equal(t, path, stats.CPUAccounting.Path)
	assert.Equal(t, path, stats.Memory.Path)

	json, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(json))
}

func TestReaderGetStatsHierarchyOverride(t *testing.T) {
	// In testdata/docker, process 1's cgroup paths have
	// no corresponding paths under /sys/fs/cgroup/<subsystem>.
	//
	// Setting CgroupsHierarchyOverride means that we use
	// the root cgroup path instead. This is intended to test
	// the scenario where we're reading cgroup metrics from
	// within a Docker container.

	reader, err := NewReaderOptions(ReaderOptions{
		RootfsMountpoint:         "testdata/docker",
		IgnoreRootCgroups:        true,
		CgroupsHierarchyOverride: "/",
	})
	if err != nil {
		t.Fatal(err)
	}

	stats, err := reader.GetStatsForProcess(1)
	if err != nil {
		t.Fatal(err)
	}
	if stats == nil {
		t.Fatal("no cgroup stats found")
	}

	require.NotNil(t, stats.CPU)
	assert.NotZero(t, stats.CPU.CFS.Shares)
}

func TestControllerCompare(t *testing.T) {
	cases := []struct {
		content    string
		controller string
		contain    bool
		expected   bool
	}{
		{
			content:    "cpu",
			controller: "cpu",
			contain:    true,
			expected:   true,
		},
		{
			content:    "nothing",
			controller: "cpu",
			contain:    true,
			expected:   false,
		},
		{
			content:    "rw,seclabel,cpuacct,cpu",
			controller: "cpuacct,cpu",
			contain:    true,
			expected:   true,
		},
		{
			content:    "rw,seclabel,cpuacct,cpu",
			controller: "cpu,cpuacct",
			contain:    true,
			expected:   true,
		},
		{
			content:    "cpuacct,cpu",
			controller: "cpu,cpuacct",
			contain:    true,
			expected:   true,
		},
		{
			content:    "cpuacct",
			controller: "cpu,cpuacct",
			contain:    true,
			expected:   false,
		},
		{
			content:    "cpuacct,cpu",
			controller: "cpuacct",
			contain:    true,
			expected:   true,
		},
		{
			content:    "cpuacct",
			controller: "cpuacct",
			contain:    false,
			expected:   true,
		},
		{
			content:    "cpuacct,cpu",
			controller: "cpuacct,cpu",
			contain:    false,
			expected:   true,
		},
		{
			content:    "cpuacct,cpu",
			controller: "cpu,cpuacct",
			contain:    false,
			expected:   true,
		},
		{
			content:    "cpuacct,cpu",
			controller: "cpuacct,cpu1",
			contain:    false,
			expected:   false,
		},
		{
			content:    "cpuacct,cpu1",
			controller: "cpuacct,cpu",
			contain:    false,
			expected:   false,
		},
		{
			content:    "cpuacct,cpuacct",
			controller: "cpu,cpuacct",
			contain:    false,
			expected:   false,
		},
		{
			content:    "cpuacct,cpuacct",
			controller: "cpuacct",
			contain:    false,
			expected:   false,
		},
	}

	for i, c := range cases {
		if c.expected != controllerCompare(c.content, c.controller, c.contain) {
			t.Errorf("%d: expected %v, got %v", i, c.expected, controllerCompare(c.content, c.controller, c.contain))
		}
	}
}
