package events

import (
	"testing"
)

func TestParseCloudTrailS3Key(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		wantValid bool
		wantAcct  string
		wantRegion string
	}{
		{
			name:      "organization trail",
			key:       "AWSLogs/o-f4709b1n6a/655631470870/CloudTrail/us-east-1/2025/12/01/655631470870_CloudTrail_us-east-1_20251201T0005Z_abc123.json.gz",
			wantValid: true,
			wantAcct:  "655631470870",
			wantRegion: "us-east-1",
		},
		{
			name:      "single account trail",
			key:       "AWSLogs/123456789012/CloudTrail/us-west-2/2024/12/01/123456789012_CloudTrail_us-west-2_20241201T0005Z_xyz789.json.gz",
			wantValid: true,
			wantAcct:  "123456789012",
			wantRegion: "us-west-2",
		},
		{
			name:      "invalid format - missing parts",
			key:       "AWSLogs/123456789012/CloudTrail/",
			wantValid: false,
		},
		{
			name:      "invalid format - not cloudtrail",
			key:       "AWSLogs/123456789012/S3/us-west-2/2024/12/01/file.log",
			wantValid: false,
		},
		{
			name:      "invalid filename format",
			key:       "AWSLogs/123456789012/CloudTrail/us-west-2/2024/12/01/invalid.json",
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := ParseCloudTrailS3Key(tt.key)
			if err != nil {
				t.Fatalf("ParseCloudTrailS3Key() error = %v", err)
			}

			if info.IsValid != tt.wantValid {
				t.Errorf("ParseCloudTrailS3Key() IsValid = %v, want %v", info.IsValid, tt.wantValid)
			}

			if tt.wantValid {
				if info.AccountID != tt.wantAcct {
					t.Errorf("ParseCloudTrailS3Key() AccountID = %v, want %v", info.AccountID, tt.wantAcct)
				}
				if info.Region != tt.wantRegion {
					t.Errorf("ParseCloudTrailS3Key() Region = %v, want %v", info.Region, tt.wantRegion)
				}
			}
		})
	}
}

func TestExtractAccountRegionFromKey(t *testing.T) {
	tests := []struct {
		name        string
		key         string
		wantAcct    string
		wantRegion  string
		wantErr     bool
	}{
		{
			name:       "valid organization trail",
			key:        "AWSLogs/o-f4709b1n6a/655631470870/CloudTrail/us-east-1/2025/12/01/655631470870_CloudTrail_us-east-1_20251201T0005Z_abc123.json.gz",
			wantAcct:   "655631470870",
			wantRegion: "us-east-1",
			wantErr:    false,
		},
		{
			name:       "valid single account",
			key:        "AWSLogs/123456789012/CloudTrail/us-west-2/2024/12/01/123456789012_CloudTrail_us-west-2_20241201T0005Z_xyz789.json.gz",
			wantAcct:   "123456789012",
			wantRegion: "us-west-2",
			wantErr:    false,
		},
		{
			name:    "invalid key",
			key:     "invalid/key/path",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acct, region, err := ExtractAccountRegionFromKey(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractAccountRegionFromKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if acct != tt.wantAcct {
					t.Errorf("ExtractAccountRegionFromKey() AccountID = %v, want %v", acct, tt.wantAcct)
				}
				if region != tt.wantRegion {
					t.Errorf("ExtractAccountRegionFromKey() Region = %v, want %v", region, tt.wantRegion)
				}
			}
		})
	}
}
