package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2/hpack"
)

func main() {
	var (
		buf     bytes.Buffer
		oriSize int
	)
	henc := hpack.NewEncoder(&buf)
	headers := []hpack.HeaderField{
		{Name: ":authority", Value: "dss0.bdstatic.com"},
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/5aV1bjqh_Q23odCf/static/superman/img/topnav/baiduyun@2x-e0be79e69e.png"},
		{Name: ":scheme", Value: "https"},
		{Name: "accept-encoding", Value: "gzip"},
		{Name: "user-agent", Value: "Go-http-client/2.0"},
		{Name: "custom-header", Value: "custom-value"},
	}
	for _, header := range headers {
		oriSize += len(header.Name) + len(header.Value)
		henc.WriteField(header)
	}
	fmt.Printf("ori size: %v, encoded size: %v\n", oriSize, buf.Len())

	var (
		invalid    error
		sawRegular bool
		// 16 << 20 from fr.maxHeaderListSize() from
		remainSize uint32 = 16 << 20
	)
	hdec := hpack.NewDecoder(4096, nil)
	// 16 << 20 from fr.maxHeaderStringLen() from fr.maxHeaderListSize()
	hdec.SetMaxStringLength(int(remainSize))
	hdec.SetEmitFunc(func(hf hpack.HeaderField) {
		if !httpguts.ValidHeaderFieldValue(hf.Value) {
			invalid = fmt.Errorf("invalid header field value %q", hf.Value)
		}
		isPseudo := strings.HasPrefix(hf.Name, ":")
		if isPseudo {
			if sawRegular {
				invalid = errors.New("pseudo header field after regular")
			}
		} else {
			sawRegular = true
			// if !http2validWireHeaderFieldName(hf.Name) {
			// 	invliad = fmt.Sprintf("invalid header field name %q", hf.Name)
			// }
		}

		if invalid != nil {
			fmt.Println(invalid)
			hdec.SetEmitEnabled(false)
			return
		}

		size := hf.Size()
		if size > remainSize {
			hdec.SetEmitEnabled(false)
			// mh.Truncated = true
			return
		}
		remainSize -= size
		fmt.Printf("%+v\n", hf)
		// mh.Fields = append(mh.Fields, hf)
	})
	defer hdec.SetEmitFunc(func(hf hpack.HeaderField) {})
	fmt.Println(hdec.Write(buf.Bytes()))

	// try again
	fmt.Println("try again: ")
	buf.Reset()
	henc.WriteField(hpack.HeaderField{Name: "custom-header", Value: "custom-value"})
	fmt.Println(hdec.Write(buf.Bytes()))

}
