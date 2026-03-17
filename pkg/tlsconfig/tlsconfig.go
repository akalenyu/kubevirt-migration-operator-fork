package tlsconfig

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync/atomic"

	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	migrationsv1alpha1 "kubevirt.io/kubevirt-migration-operator/api/v1alpha1"
)

var log = logf.Log.WithName("tls-config")

// openSSLToGo maps OpenSSL cipher suite names to Go crypto/tls cipher suite IDs.
// Ciphers not supported by Go (e.g. DHE-RSA-*) are omitted and will be silently skipped.
var openSSLToGo = map[string]uint16{
	"ECDHE-ECDSA-AES128-GCM-SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"ECDHE-RSA-AES128-GCM-SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"ECDHE-ECDSA-AES256-GCM-SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"ECDHE-RSA-AES256-GCM-SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"ECDHE-ECDSA-CHACHA20-POLY1305": tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	"ECDHE-RSA-CHACHA20-POLY1305":   tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	"ECDHE-ECDSA-AES128-SHA256":     tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	"ECDHE-RSA-AES128-SHA256":       tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	"ECDHE-ECDSA-AES128-SHA":        tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	"ECDHE-RSA-AES128-SHA":          tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"ECDHE-ECDSA-AES256-SHA":        tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	"ECDHE-RSA-AES256-SHA":          tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"AES128-GCM-SHA256":             tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	"AES256-GCM-SHA384":             tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	"AES128-SHA256":                  tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	"AES128-SHA":                     tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"AES256-SHA":                     tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"DES-CBC3-SHA":                   tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

var tlsVersions = map[migrationsv1alpha1.TLSProtocolVersion]uint16{
	migrationsv1alpha1.VersionTLS10: tls.VersionTLS10,
	migrationsv1alpha1.VersionTLS11: tls.VersionTLS11,
	migrationsv1alpha1.VersionTLS12: tls.VersionTLS12,
	migrationsv1alpha1.VersionTLS13: tls.VersionTLS13,
}

type profileConfig struct {
	cipherSuites []uint16
	minVersion   uint16
}

// Watcher watches MigController CRs via the controller-runtime informer and
// keeps a precomputed TLS profile config updated atomically. It implements
// manager.Runnable and manager.LeaderElectionRunnable.
type Watcher struct {
	config atomic.Pointer[profileConfig]
	cache  cache.Cache
}

// NewWatcher creates a Watcher. Use SetCache to wire the controller-runtime
// cache before the manager is started.
func NewWatcher() *Watcher {
	return &Watcher{}
}

// SetCache sets the controller-runtime cache used to obtain the MigController
// informer. Must be called before Start.
func (w *Watcher) SetCache(c cache.Cache) {
	w.cache = c
}

// NeedLeaderElection implements manager.LeaderElectionRunnable.
// TLS config must be applied on every replica, not just the leader.
func (w *Watcher) NeedLeaderElection() bool { return false }

// Start implements manager.Runnable. It registers an event handler on the
// MigController informer to update the TLS config when the CR changes, then
// blocks until ctx is cancelled.
func (w *Watcher) Start(ctx context.Context) error {
	if w.cache == nil {
		return fmt.Errorf("cache not set, call SetCache before starting")
	}
	informer, err := w.cache.GetInformer(ctx, &migrationsv1alpha1.MigController{})
	if err != nil {
		return fmt.Errorf("failed to get MigController informer: %w", err)
	}

	if _, err := informer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			w.onCRChange(obj.(*migrationsv1alpha1.MigController))
		},
		UpdateFunc: func(_, newObj interface{}) {
			w.onCRChange(newObj.(*migrationsv1alpha1.MigController))
		},
		DeleteFunc: func(_ interface{}) {
			log.Info("MigController deleted, clearing TLS profile config")
			w.config.Store(nil)
		},
	}); err != nil {
		return fmt.Errorf("failed to add event handler: %w", err)
	}

	<-ctx.Done()
	return nil
}

func (w *Watcher) onCRChange(cr *migrationsv1alpha1.MigController) {
	spec := ProfileSpec(cr.Spec.TLSSecurityProfile)
	if spec == nil {
		w.config.Store(nil)
		return
	}
	log.Info("Updating TLS profile config", "minVersion", spec.MinTLSVersion, "ciphers", len(spec.Ciphers))
	w.config.Store(&profileConfig{
		cipherSuites: CipherIDs(spec.Ciphers),
		minVersion:   MinVersion(spec.MinTLSVersion),
	})
}

// TLSOpt returns a function suitable for metricsserver.Options.TLSOpts that
// installs a GetConfigForClient callback. The callback reads the precomputed
// config from the atomic pointer — zero work per handshake.
func (w *Watcher) TLSOpt() func(*tls.Config) {
	return func(baseCfg *tls.Config) {
		baseCfg.GetConfigForClient = func(_ *tls.ClientHelloInfo) (*tls.Config, error) {
			pc := w.config.Load()
			if pc == nil {
				return nil, nil
			}
			cfg := baseCfg.Clone()
			cfg.GetConfigForClient = nil
			cfg.CipherSuites = pc.cipherSuites
			cfg.MinVersion = pc.minVersion
			return cfg, nil
		}
	}
}

// ProfileSpec resolves a TLSSecurityProfile to its concrete TLSProfileSpec.
// Returns nil if no profile is configured.
func ProfileSpec(profile *migrationsv1alpha1.TLSSecurityProfile) *migrationsv1alpha1.TLSProfileSpec {
	if profile == nil {
		return nil
	}
	switch profile.Type {
	case migrationsv1alpha1.TLSProfileCustomType:
		if profile.Custom != nil {
			return &profile.Custom.TLSProfileSpec
		}
	default:
		if spec, ok := migrationsv1alpha1.TLSProfiles[profile.Type]; ok {
			return spec
		}
	}
	return migrationsv1alpha1.TLSProfiles[migrationsv1alpha1.TLSProfileIntermediateType]
}

// CipherIDs converts OpenSSL-style cipher names to Go tls cipher suite IDs.
// Ciphers not supported by Go are silently skipped.
func CipherIDs(ciphers []string) []uint16 {
	var ids []uint16
	for _, name := range ciphers {
		if id, ok := openSSLToGo[name]; ok {
			ids = append(ids, id)
		}
	}
	return ids
}

// MinVersion converts a TLSProtocolVersion to a Go tls version constant.
func MinVersion(v migrationsv1alpha1.TLSProtocolVersion) uint16 {
	if ver, ok := tlsVersions[v]; ok {
		return ver
	}
	return tls.VersionTLS12
}
