package core

import (
	"bytes"
	"testing"
)

// TestPacketImplementation tests the basic functionality of the Packet implementation.
func TestPacketImplementation(t *testing.T) {
	// Test in both debug and non-debug modes
	testModes := []bool{true, false}

	for _, debug := range testModes {
		t.Run("DebugMode="+boolToString(debug), func(t *testing.T) {
			// Set debug mode
			SetDebugMode(debug)

			// Create test data
			testData := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

			// Create a packet
			packet := NewPacket(testData)

			// Test Data() method
			data := packet.Data()
			if !bytes.Equal(data, testData) {
				t.Errorf("Expected packet data to be %v, got %v", testData, data)
			}

			// Test Length() method
			length := packet.Length()
			if length != len(testData) {
				t.Errorf("Expected packet length to be %d, got %d", len(testData), length)
			}
		})
	}
}

// TestPacketCopy tests that the packet data is properly copied in debug mode
// and not copied in non-debug mode.
func TestPacketCopy(t *testing.T) {
	// Test in debug mode (should copy)
	t.Run("DebugMode=true", func(t *testing.T) {
		SetDebugMode(true)

		// Create test data
		testData := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

		// Create a packet
		packet := NewPacket(testData)

		// Modify the original data
		testData[0] = 0xFF

		// Check that the packet data is not affected (should be copied)
		data := packet.Data()
		if data[0] == 0xFF {
			t.Error("Packet data was not copied, it's still referencing the original data")
		}

		// Modify the data returned by Data()
		data[1] = 0xFF

		// Check that the packet's internal data is not affected (should be copied)
		data2 := packet.Data()
		if data2[1] == 0xFF {
			t.Error("Data() did not return a copy of the packet data")
		}
	})

	// Test in non-debug mode (should not copy)
	t.Run("DebugMode=false", func(t *testing.T) {
		SetDebugMode(false)

		// Create test data
		testData := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

		// Create a packet
		packet := NewPacket(testData)

		// Modify the original data
		testData[0] = 0xFF

		// Check that the packet data is affected (should not be copied)
		data := packet.Data()
		if data[0] != 0xFF {
			t.Error("Packet data was copied, but it shouldn't be in non-debug mode")
		}

		// Modify the data returned by Data()
		data[1] = 0xFF

		// Check that the packet's internal data is affected (should not be copied)
		data2 := packet.Data()
		if data2[1] != 0xFF {
			t.Error("Data() returned a copy, but it shouldn't in non-debug mode")
		}
	})
}

// TestEmptyPacket tests creating and using an empty packet.
func TestEmptyPacket(t *testing.T) {
	// Test in both debug and non-debug modes
	testModes := []bool{true, false}

	for _, debug := range testModes {
		t.Run("DebugMode="+boolToString(debug), func(t *testing.T) {
			// Set debug mode
			SetDebugMode(debug)

			// Create an empty packet
			packet := NewPacket([]byte{})

			// Test Data() method
			data := packet.Data()
			if len(data) != 0 {
				t.Errorf("Expected empty packet data, got %v", data)
			}

			// Test Length() method
			length := packet.Length()
			if length != 0 {
				t.Errorf("Expected packet length to be 0, got %d", length)
			}
		})
	}
}

// TestNilPacket tests creating and using a nil packet.
func TestNilPacket(t *testing.T) {
	// Test in both debug and non-debug modes
	testModes := []bool{true, false}

	for _, debug := range testModes {
		t.Run("DebugMode="+boolToString(debug), func(t *testing.T) {
			// Set debug mode
			SetDebugMode(debug)

			// Create a nil packet
			packet := NewPacket(nil)

			// Test Data() method
			data := packet.Data()
			if data == nil || len(data) != 0 {
				t.Errorf("Expected empty packet data, got %v", data)
			}

			// Test Length() method
			length := packet.Length()
			if length != 0 {
				t.Errorf("Expected packet length to be 0, got %d", length)
			}
		})
	}
}

// TestLargePacket tests creating and using a large packet.
func TestLargePacket(t *testing.T) {
	// Test in both debug and non-debug modes
	testModes := []bool{true, false}

	for _, debug := range testModes {
		t.Run("DebugMode="+boolToString(debug), func(t *testing.T) {
			// Set debug mode
			SetDebugMode(debug)

			// Create a large packet (64KB)
			size := 64 * 1024
			testData := make([]byte, size)
			for i := 0; i < size; i++ {
				testData[i] = byte(i % 256)
			}

			// Create a packet
			packet := NewPacket(testData)

			// Test Length() method
			length := packet.Length()
			if length != size {
				t.Errorf("Expected packet length to be %d, got %d", size, length)
			}

			// Test Data() method - check a few values
			data := packet.Data()
			for i := 0; i < size; i += 1000 {
				if data[i] != byte(i%256) {
					t.Errorf("Expected data[%d] to be %d, got %d", i, byte(i%256), data[i])
				}
			}
		})
	}
}

// TestDebugModeToggle tests toggling debug mode on and off.
func TestDebugModeToggle(t *testing.T) {
	// Start with debug mode on
	SetDebugMode(true)
	if !IsDebugMode() {
		t.Error("Debug mode should be on")
	}

	// Toggle debug mode off
	SetDebugMode(false)
	if IsDebugMode() {
		t.Error("Debug mode should be off")
	}

	// Toggle debug mode on again
	SetDebugMode(true)
	if !IsDebugMode() {
		t.Error("Debug mode should be on again")
	}
}

// Helper function to convert bool to string
func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func TestPacketBufferSizeTracksCapacityWithDebugCopies(t *testing.T) {
	original := IsDebugMode()
	defer SetDebugMode(original)
	data := make([]byte, 20, 4096)
	simple := &SimplePacket{data: data}
	pooled := NewPooledPacket(data, func([]byte) {})
	for _, debug := range []bool{false, true} {
		SetDebugMode(debug)
		if PacketBufferSize(simple) != 4096 || PacketBufferSize(pooled) != 4096 {
			t.Fatal("retained backing capacity was not counted")
		}
	}
	ReleasePacket(pooled)
	if PacketBufferSize(pooled) != 0 {
		t.Fatal("released packet still retains storage")
	}
}

func TestBorrowedPacketViewAndEmptyRelease(t *testing.T) {
	original := IsDebugMode()
	defer SetDebugMode(original)
	SetDebugMode(true)
	p := NewPacket([]byte{1, 2, 3})
	view := BorrowPacketData(p)
	copied := p.Data()
	if &view[0] == &copied[0] {
		t.Fatal("public debug Data stopped copying")
	}
	if testing.AllocsPerRun(100, func() { _ = BorrowPacketData(p) }) != 0 {
		t.Fatal("borrowed view allocated")
	}
	releases := 0
	empty := NewPooledPacket(nil, func([]byte) { releases++ })
	ReleasePacket(empty)
	ReleasePacket(empty)
	if releases != 1 {
		t.Fatalf("empty release calls=%d", releases)
	}
}
