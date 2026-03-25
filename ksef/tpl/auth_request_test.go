package tpl

import (
	"strings"
	"testing"
)

func TestRenderAuthRequestXML(t *testing.T) {
	tests := []struct {
		name    string
		data    AuthRequestData
		wantHas []string
		wantNot []string
	}{
		{
			name: "without policy",
			data: AuthRequestData{
				Challenge:             "abc",
				Identifier:            "1234567890",
				SubjectIdentifierType: "NIP",
			},
			wantHas: []string{
				"<Challenge>abc</Challenge>",
				"<Nip>1234567890</Nip>",
				"<SubjectIdentifierType>NIP</SubjectIdentifierType>",
			},
			wantNot: []string{
				"<AuthorizationPolicy>",
				"<Ip4Address>",
			},
		},
		{
			name: "with policy",
			data: AuthRequestData{
				Challenge:             "abc",
				Identifier:            "1234567890",
				SubjectIdentifierType: "NIP",
				AllowedIPs: []string{
					"192.168.12.42",
				},
			},
			wantHas: []string{
				"<AuthorizationPolicy>",
				"<AllowedIps>",
				"<Ip4Address>192.168.12.42</Ip4Address>",
			},
			wantNot: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RenderAuthRequestXML(tt.data)
			if err != nil {
				t.Fatalf("RenderAuthRequestXML() error = %v", err)
			}

			s := string(got)

			for _, part := range tt.wantHas {
				if !strings.Contains(s, part) {
					t.Errorf("brak fragmentu %q w wyniku:\n%s", part, s)
				}
			}

			for _, part := range tt.wantNot {
				if strings.Contains(s, part) {
					t.Errorf("fragment %q nie powinien wystąpić w wyniku:\n%s", part, s)
				}
			}
		})
	}
}
