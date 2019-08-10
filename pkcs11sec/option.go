package pkcs11sec

import (
	"github.com/choria-io/go-config"
	"github.com/sirupsen/logrus"
)

type Option func(*Pkcs11Security) error

func WithChoriaConfig(c *config.Config) Option {
	return func(p *Pkcs11Security) error {
		cfg := Config{
			AllowList:            c.Choria.CertnameWhitelist,
			DisableTLSVerify:     c.DisableTLSVerify,
			PrivilegedUsers:      c.Choria.PrivilegedUsers,
			CAFile:               c.Choria.FileSecurityCA,
			CertCacheDir:         c.Choria.FileSecurityCache,
			AlwaysOverwriteCache: c.Choria.SecurityAlwaysOverwriteCache,
		}

		p.conf = &cfg

		return nil
	}
}

// TODO: manage these options in WithChoriaConfig
// Only reason this is here is because, since pkcs11 module's feasibility is still being proven, I don't want to merge
// pkcs11 config options into upstream config package. Will remove this before merging and update upstream config.
func WithPKCSConfigOptions(c *Config) Option {
	return func(p *Pkcs11Security) error {
		if c.PKCS11DriverFile != "" {
			p.conf.PKCS11DriverFile = c.PKCS11DriverFile
		}
		if c.PKCS11Slot != 0 {
			p.conf.PKCS11Slot = c.PKCS11Slot
		}
		return nil
	}
}

func WithLog(l *logrus.Entry) Option {
	return func(p *Pkcs11Security) error {
		p.log = l.WithFields(logrus.Fields{"ssl": "pkcs11"})

		return nil
	}
}

func WithPin(pin string) Option {
	return func(p *Pkcs11Security) error {
		p.pin = &pin

		return nil
	}
}
