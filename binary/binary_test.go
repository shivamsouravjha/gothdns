package binary

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestQname(t *testing.T) {
	// letters to binary representation: https://www.eso.org/~ndelmott/ascii.html
	exampleLen := "00000111" // 7 for 7 letters in "example"
	example := "01100101 01111000 01100001 01101101 01110000 01101100 01100101"
	comLen := "00000011" // 3 for 3 letters in "com"
	com := "01100011 01101111 01101101"
	null := "00000000"

	assert.Equal(t, exampleLen+" "+example+" "+comLen+" "+com+" "+null, Qname("example.com."))
}

func TestUint16(t *testing.T) {
	assert.Equal(t, "00000000 00000001", Uint16(1))
	assert.Equal(t, "00000000 00000011", Uint16(3))
	assert.Equal(t, "00000000 01111001", Uint16(121))
	assert.Equal(t, "00000011 11101000", Uint16(1000))
}

// Test generated using Keploy
func TestQname_RootDomain(t *testing.T) {
	expected := "00000000"
	result := Qname(".")
	if result != expected {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

// Test generated using Keploy
func TestUint32(t *testing.T) {
	expected := "00000000 00000000 00000000 00000001"
	result := Uint32(1)
	if result != expected {
		t.Errorf("Expected %v, got %v", expected, result)
	}

	expected = "00000000 00000000 00000011 11101000"
	result = Uint32(1000)
	if result != expected {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}
