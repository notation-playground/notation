package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/notaryproject/notation-go/log"
	notationregistry "github.com/notaryproject/notation-go/registry"
	notationerrors "github.com/notaryproject/notation/cmd/notation/internal/errors"
	notationauth "github.com/notaryproject/notation/internal/auth"
	"github.com/notaryproject/notation/internal/trace"
	"github.com/notaryproject/notation/internal/version"
	"github.com/notaryproject/notation/pkg/configutil"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	credentials "github.com/oras-project/oras-credentials-go"
	"github.com/sirupsen/logrus"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/errcode"
)

// inputType denotes the user input type
type inputType int

const (
	inputTypeRegistry  inputType = 1 + iota // inputType remote registry
	inputTypeOCILayout                      // inputType oci-layout
)

const (
	zeroDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

// getRepository returns a notationregistry.Repository given user input type and
// user input reference
func getRepository(ctx context.Context, inputType inputType, reference string, opts *SecureFlagOpts) (notationregistry.Repository, error) {
	switch inputType {
	case inputTypeRegistry:
		return getRemoteRepository(ctx, opts, reference)
	case inputTypeOCILayout:
		layoutPath, _, err := parseOCILayoutReference(reference)
		if err != nil {
			return nil, err
		}
		return notationregistry.NewOCIRepository(layoutPath, notationregistry.RepositoryOptions{})
	default:
		return nil, errors.New("unsupported input type")
	}
}

// getRepositoryForSign returns a notationregistry.Repository given user input
// type and user input reference during Sign process
func getRepositoryForSign(ctx context.Context, inputType inputType, reference string, opts *SecureFlagOpts, ociImageManifest bool) (notationregistry.Repository, error) {
	switch inputType {
	case inputTypeRegistry:
		return getRemoteRepositoryForSign(ctx, opts, reference, ociImageManifest)
	case inputTypeOCILayout:
		layoutPath, _, err := parseOCILayoutReference(reference)
		if err != nil {
			return nil, err
		}
		return notationregistry.NewOCIRepository(layoutPath, notationregistry.RepositoryOptions{OCIImageManifest: ociImageManifest})
	default:
		return nil, errors.New("unsupported input type")
	}
}

func getRemoteRepository(ctx context.Context, opts *SecureFlagOpts, reference string) (notationregistry.Repository, error) {
	ref, err := registry.ParseReference(reference)
	if err != nil {
		return nil, err
	}

	// generate notation repository
	remoteRepo, err := getRepositoryClient(ctx, opts, ref)
	if err != nil {
		return nil, err
	}
	return notationregistry.NewRepository(remoteRepo), nil
}

// getRemoteRepositoryForSign returns a registry.Repository for Sign.
// ociImageManifest denotes the type of manifest used to store signatures during
// Sign process.
// Setting ociImageManifest to true means using OCI image manifest and the
// Referrers tag schema.
// Otherwise, use OCI artifact manifest and requires the Referrers API.
func getRemoteRepositoryForSign(ctx context.Context, opts *SecureFlagOpts, reference string, ociImageManifest bool) (notationregistry.Repository, error) {
	logger := log.GetLogger(ctx)
	ref, err := registry.ParseReference(reference)
	if err != nil {
		return nil, err
	}

	// generate notation repository
	remoteRepo, err := getRepositoryClient(ctx, opts, ref)
	if err != nil {
		return nil, err
	}

	// Notation enforces the following two paths during Sign process:
	// 1. OCI artifact manifest uses the Referrers API.
	// Reference: https://github.com/opencontainers/distribution-spec/blob/v1.1.0-rc1/spec.md#listing-referrers
	// 2. OCI image manifest uses the Referrers API and automatically fallback
	// 	  to Referrers Tag Schema if Referrers API is not supported.
	// Reference: https://github.com/opencontainers/distribution-spec/blob/v1.1.0-rc1/spec.md#referrers-tag-schema
	if !ociImageManifest {
		logger.Info("Use OCI artifact manifest to store signature")
		// ping Referrers API
		if err := pingReferrersAPI(ctx, remoteRepo); err != nil {
			return nil, err
		}
		logger.Info("Successfully pinged Referrers API on target registry")
	}
	repositoryOpts := notationregistry.RepositoryOptions{
		OCIImageManifest: ociImageManifest,
	}
	return notationregistry.NewRepositoryWithOptions(remoteRepo, repositoryOpts), nil
}

func getRepositoryClient(ctx context.Context, opts *SecureFlagOpts, ref registry.Reference) (*remote.Repository, error) {
	authClient, plainHTTP, err := getAuthClient(ctx, opts, ref)
	if err != nil {
		return nil, err
	}

	return &remote.Repository{
		Client:    authClient,
		Reference: ref,
		PlainHTTP: plainHTTP,
	}, nil
}

func getRegistryClient(ctx context.Context, opts *SecureFlagOpts, serverAddress string) (*remote.Registry, error) {
	reg, err := remote.NewRegistry(serverAddress)
	if err != nil {
		return nil, err
	}

	reg.Client, reg.PlainHTTP, err = getAuthClient(ctx, opts, reg.Reference)
	if err != nil {
		return nil, err
	}
	return reg, nil
}

func setHttpDebugLog(ctx context.Context, authClient *auth.Client) {
	if logrusLog, ok := log.GetLogger(ctx).(*logrus.Logger); ok && logrusLog.Level != logrus.DebugLevel {
		return
	}
	if authClient.Client == nil {
		authClient.Client = http.DefaultClient
	}
	if authClient.Client.Transport == nil {
		authClient.Client.Transport = http.DefaultTransport
	}
	authClient.Client.Transport = trace.NewTransport(authClient.Client.Transport)
}

// getAuthClient returns an *auth.Client and a bool indicating if
// plain HTTP should be used.
func getAuthClient(ctx context.Context, opts *SecureFlagOpts, ref registry.Reference) (*auth.Client, bool, error) {
	var plainHTTP bool
	if opts.PlainHTTP {
		plainHTTP = opts.PlainHTTP
	} else {
		plainHTTP = configutil.IsRegistryInsecure(ref.Registry)
		if !plainHTTP {
			if host, _, _ := net.SplitHostPort(ref.Registry); host == "localhost" {
				plainHTTP = true
			}
		}
	}

	// build authClient
	authClient := &auth.Client{
		Cache:    auth.NewCache(),
		ClientID: "notation",
	}
	authClient.SetUserAgent("notation/" + version.GetVersion())
	setHttpDebugLog(ctx, authClient)

	cred := opts.Credential()
	if cred != auth.EmptyCredential {
		// use the specified credential
		authClient.Credential = auth.StaticCredential(ref.Host(), cred)
	} else {
		// use saved credentials
		credsStore, err := notationauth.NewCredentialsStore()
		if err != nil {
			return nil, false, fmt.Errorf("failed to get credentials store: %w", err)
		}
		authClient.Credential = credentials.Credential(credsStore)
	}
	return authClient, plainHTTP, nil
}

func pingReferrersAPI(ctx context.Context, remoteRepo *remote.Repository) error {
	logger := log.GetLogger(ctx)
	if err := remoteRepo.SetReferrersCapability(true); err != nil {
		return err
	}
	var checkReferrerDesc ocispec.Descriptor
	checkReferrerDesc.Digest = zeroDigest
	// core process
	err := remoteRepo.Referrers(ctx, checkReferrerDesc, "", func(referrers []ocispec.Descriptor) error {
		return nil
	})
	if err != nil {
		var errResp *errcode.ErrorResponse
		if !errors.As(err, &errResp) || errResp.StatusCode != http.StatusNotFound {
			return err
		}
		if isErrorCode(errResp, errcode.ErrorCodeNameUnknown) {
			// The repository is not found in the target registry.
			// This is triggered when putting signatures to an empty repository.
			// For notation, this path should never be triggered.
			return err
		}
		// A 404 returned by Referrers API indicates that Referrers API is
		// not supported.
		logger.Infof("failed to ping Referrers API with error: %v", err)
		errMsg := "Target registry does not support the Referrers API. Try removing the flag `--signature-manifest artifact` to store signatures using OCI image manifest"
		return notationerrors.ErrorReferrersAPINotSupported{Msg: errMsg}
	}
	return nil
}

// isErrorCode returns true if err is an Error and its Code equals to code.
func isErrorCode(err error, code string) bool {
	var ec errcode.Error
	return errors.As(err, &ec) && ec.Code == code
}
