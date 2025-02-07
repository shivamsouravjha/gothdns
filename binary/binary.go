package binary

import (
	"fmt"
	"strings"
)

func Qname(name string) string {
	if name == "." {
		return "00000000"
	}

	var b string

	name = strings.TrimSuffix(name, ".")
	for _, label := range strings.Split(name, ".") {
		b += fmt.Sprintf("%.8b ", len(label)) + ""

		var s string
		for _, c := range label {
			s = fmt.Sprintf("%s%.8b ", s, c)
		}
		b += s
	}
	// The domain name terminates with the zero length octet for the null label of the root
	b += "00000000"

	return b
}

func Uint32(t uint16) string {
	b := fmt.Sprintf("%.32b", t)

	return b[:8] + " " + b[8:16] + " " + b[16:24] + " " + b[24:]
}

func Uint16(t uint16) string {
	b := fmt.Sprintf("%.16b", t)

	return b[:8] + " " + b[8:]
}
