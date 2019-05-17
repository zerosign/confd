package vault

import (
	"time"
)

//
// Note: format time from vault
//
// 2017-04-30T10:18:11.228946471-04:00
//
type leaseMetadata struct {
	Id              string        `json:"id"`
	IssueTime       time.Time     `json:"issue_time"`
	ExpireTime      time.Time     `json:"expire_time"`
	LastRenewalTime time.Time     `json:"last_renewal_time,omitempty"`
	Renewable       bool          `json:"renewable"`
	Ttl             time.Duration `json:"ttl"`
}
