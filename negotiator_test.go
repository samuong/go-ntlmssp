package ntlmssp

import (
	"bytes"
	"os/exec"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func handler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("WWW-Authenticate", "NTLM")
	scheme, authz, ok := strings.Cut(req.Header.Get("Authorization"), " ")
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "access denied: no authorization header\n")
		return
	} else if scheme != "Negotiate" && scheme != "NTLM" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "access denied: unsupported auth scheme %q\n", scheme)
		return
	}
	data, err := base64.StdEncoding.DecodeString(authz)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "access denied: %v\n", err)
		return
	}
	r := bytes.NewReader(data)
	var h messageHeader
	if err := binary.Read(r, binary.LittleEndian, &h); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "access denied: %v\n", err)
		return
	}
	if !h.IsValid() {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "access denied: invalid ntlm message header\n")
		return
	}
	switch h.MessageType {
	case 1:
		// Got NTLM type 1 message; respond with example challenge from
		// <https://davenport.sourceforge.net/ntlm.html#type2MessageExample>.
		challenge, err := hex.DecodeString("4e544c4d53535000020000000c000c0030000000010281000123456789abcdef0000000000000000620062003c00000044004f004d00410049004e0002000c0044004f004d00410049004e0001000c005300450052005600450052000400140064006f006d00610069006e002e0063006f006d00030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d0000000000")
		if err != nil {
			panic(err)
		}
		authn := base64.StdEncoding.EncodeToString(challenge)
		w.Header().Set("WWW-Authenticate", "NTLM "+authn)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "challenge sent\n")
		return
	case 3:
		// Got an NTLM type 3 message; extract domain and username and send it back.
		domain, user, err := unmarshal(data)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, "access denied: %v\n", err)
		}
		fmt.Fprintf(w, "access granted to %s\\%s\n", domain, user)
	default:
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "access denied: unknown message type: %d\n", h.MessageType)
		return
	}
}

func unmarshal(data []byte) (string, string, error) {
	var f authenticateMessageFields
	r := bytes.NewReader(data)
	if err := binary.Read(r, binary.LittleEndian, &f); err != nil {
		return "", "", fmt.Errorf("unmarshal fields: %w", err)
	}
	target, err := f.TargetName.ReadStringFrom(data, true)
	if err != nil {
		return "", "", fmt.Errorf("unmarshal target name: %w", err)
	}
	user, err := f.UserName.ReadStringFrom(data, true)
	if err != nil {
		return "", "", fmt.Errorf("unmarshal user name: %w", err)
	}
	return target, user, nil
}

func TestNegotiator(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()
	var negotiator Negotiator
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("isis\\malory", "guest")
	req.Header.Set("WWW-Authenticate", "NTLM")
	resp, err := negotiator.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)
	want := "access granted to isis\\malory\n"
	if want != got {
		t.Fatalf("want %q, got %q", want, got)
	}
}

func TestCurl(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()
	cmd := exec.Command("curl", "--ntlm", "-u", "isis\\malory:guest", server.URL)
	output, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	got := string(output)
	want := "access granted to isis\\malory\n"
	if want != got {
		t.Fatalf("want %q, got %q", want, got)
	}
}
