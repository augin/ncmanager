package main

import (
	"testing"
	"time"
)

// setTrafficPoints напрямую записывает точки в буфер (тесты в том же пакете).
func setTrafficPoints(name string, points []amneziaTrafficSnapshot) {
	amneziaTrafficBuf.mu.Lock()
	amneziaTrafficBuf.entries[name] = &amneziaTrafficEntry{points: points}
	amneziaTrafficBuf.mu.Unlock()
}

func resetTrafficBuf() {
	amneziaTrafficBuf.mu.Lock()
	amneziaTrafficBuf.entries = make(map[string]*amneziaTrafficEntry)
	amneziaTrafficBuf.mu.Unlock()
}

func TestFeedAmneziaTrafficDedupSameSecond(t *testing.T) {
	resetTrafficBuf()
	defer resetTrafficBuf()

	now := time.Now().Unix()
	setTrafficPoints("wg0", []amneziaTrafficSnapshot{{TS: now - 5, Rx: 100, Tx: 100}})

	feedAmneziaTraffic("wg0", 200, 200)
	feedAmneziaTraffic("wg0", 300, 300) // тот же TS — пропускается

	amneziaTrafficBuf.mu.RLock()
	n := len(amneziaTrafficBuf.entries["wg0"].points)
	amneziaTrafficBuf.mu.RUnlock()
	if n != 2 {
		t.Errorf("points = %d, want 2 (dedup within same second)", n)
	}
}

func TestFeedAmneziaTrafficTrimsBuffer(t *testing.T) {
	resetTrafficBuf()
	defer resetTrafficBuf()

	now := time.Now().Unix()
	points := make([]amneziaTrafficSnapshot, amneziaMaxTrafficPoints)
	for i := range points {
		points[i] = amneziaTrafficSnapshot{TS: int64(i), Rx: int64(i), Tx: int64(i)}
	}
	setTrafficPoints("wg0", points)

	feedAmneziaTraffic("wg0", 999999, 999999)

	amneziaTrafficBuf.mu.RLock()
	stored := amneziaTrafficBuf.entries["wg0"].points
	amneziaTrafficBuf.mu.RUnlock()

	if len(stored) != amneziaMaxTrafficPoints {
		t.Fatalf("len = %d, want %d", len(stored), amneziaMaxTrafficPoints)
	}
	if stored[len(stored)-1].Rx != 999999 {
		t.Errorf("newest point must be kept, got Rx=%d", stored[len(stored)-1].Rx)
	}
	_ = now
}

func TestFeedAmneziaTrafficNewEntry(t *testing.T) {
	resetTrafficBuf()
	defer resetTrafficBuf()

	feedAmneziaTraffic("fresh", 1, 2)

	amneziaTrafficBuf.mu.RLock()
	entry := amneziaTrafficBuf.entries["fresh"]
	amneziaTrafficBuf.mu.RUnlock()

	if entry == nil || len(entry.points) != 1 {
		t.Fatalf("entry must contain exactly one point: %+v", entry)
	}
	if entry.points[0].Rx != 1 || entry.points[0].Tx != 2 {
		t.Errorf("point = %+v", entry.points[0])
	}
}

func TestGetAmneziaTrafficPointsRates(t *testing.T) {
	resetTrafficBuf()
	defer resetTrafficBuf()

	now := time.Now().Unix()
	setTrafficPoints("wg0", []amneziaTrafficSnapshot{
		{TS: now - 10, Rx: 0, Tx: 0},
		{TS: now - 5, Rx: 1000, Tx: 500}, // +1000 rx за 5с = 200 B/s
		{TS: now, Rx: 2000, Tx: 1500},    // +1000 rx / +1000 tx за 5с = 200 B/s
	})

	snaps, stats := getAmneziaTrafficPoints("wg0", 3600)
	if len(snaps) != 3 {
		t.Fatalf("points = %d, want 3", len(snaps))
	}
	if stats.Points != 3 {
		t.Errorf("stats.Points = %d, want 3", stats.Points)
	}
	if stats.PeakRate < 199 || stats.PeakRate > 201 {
		t.Errorf("PeakRate = %v, want ~200", stats.PeakRate)
	}
	if stats.AvgRx < 199 || stats.AvgRx > 201 {
		t.Errorf("AvgRx = %v, want ~200", stats.AvgRx)
	}
	if stats.CurrentRx < 199 || stats.CurrentRx > 201 {
		t.Errorf("CurrentRx = %v, want ~200", stats.CurrentRx)
	}
}

func TestGetAmneziaTrafficPointsSkipsCounterRollback(t *testing.T) {
	resetTrafficBuf()
	defer resetTrafficBuf()

	now := time.Now().Unix()
	setTrafficPoints("wg0", []amneziaTrafficSnapshot{
		{TS: now - 10, Rx: 5000, Tx: 5000},
		{TS: now - 5, Rx: 100, Tx: 100}, // откат счётчиков (рестарт) — интервал пропускается
		{TS: now, Rx: 1100, Tx: 1100},
	})

	_, stats := getAmneziaTrafficPoints("wg0", 3600)
	// Учитывается только последний интервал: 1000/5 = 200 B/s.
	// Примечание: пропущенные из-за отката интервалы всё равно входят в
	// знаменатель среднего (n-1), поэтому AvgRx = 200/2 = 100.
	if stats.AvgRx < 99 || stats.AvgRx > 101 {
		t.Errorf("AvgRx = %v, want ~100 (rollback interval skipped but counted in denominator)", stats.AvgRx)
	}
	if stats.CurrentRx < 199 || stats.CurrentRx > 201 {
		t.Errorf("CurrentRx = %v, want ~200", stats.CurrentRx)
	}
}

func TestGetAmneziaTrafficPointsFiltersByDuration(t *testing.T) {
	resetTrafficBuf()
	defer resetTrafficBuf()

	now := time.Now().Unix()
	setTrafficPoints("wg0", []amneziaTrafficSnapshot{
		{TS: now - 7200, Rx: 0, Tx: 0}, // старше часа
		{TS: now - 60, Rx: 0, Tx: 0},
		{TS: now, Rx: 100, Tx: 100},
	})

	snaps, _ := getAmneziaTrafficPoints("wg0", 3600)
	if len(snaps) != 2 {
		t.Errorf("filtered points = %d, want 2", len(snaps))
	}
}

func TestGetAmneziaTrafficPointsUnknownName(t *testing.T) {
	resetTrafficBuf()
	defer resetTrafficBuf()

	snaps, stats := getAmneziaTrafficPoints("missing", 3600)
	if len(snaps) != 0 {
		t.Errorf("points = %d, want 0", len(snaps))
	}
	if stats.Points != 0 || stats.PeakRate != 0 {
		t.Errorf("stats must be zero: %+v", stats)
	}
}
