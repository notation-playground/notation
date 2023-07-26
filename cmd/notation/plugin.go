// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"text/tabwriter"

	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/notaryproject/notation/internal/cmd"
	"github.com/notaryproject/notation/internal/osutil"
	plugininternal "github.com/notaryproject/notation/internal/plugin"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/cobra"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry"
)

type pluginOpts struct {
	cmd.LoggingFlagOpts
	SecureFlagOpts
	reference  string
	pluginName string
}

func pluginCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugin",
		Short: "Manage plugins",
	}
	cmd.AddCommand(pluginInstallCommand(nil))
	cmd.AddCommand(pluginListCommand())
	return cmd
}

func pluginInstallCommand(opts *pluginOpts) *cobra.Command {
	if opts == nil {
		opts = &pluginOpts{}
	}
	command := &cobra.Command{
		Use:     "install [flags] <plugin reference>",
		Aliases: []string{"import", "add"},
		Short:   "Install a plugin",
		Long: `Install a plugin
		Example - Install a Notation plugin:
			notation plugin install <--name pluginName> <plugin reference in remote registry>
`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("missing reference")
			}
			opts.reference = args[0]
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return installPlugin(cmd, opts)
		},
	}
	opts.LoggingFlagOpts.ApplyFlags(command.Flags())
	opts.SecureFlagOpts.ApplyFlags(command.Flags())
	command.Flags().StringVar(&opts.pluginName, "name", "", "name of the plugin to be installed")
	command.MarkFlagRequired("name")
	return command
}

func installPlugin(command *cobra.Command, opts *pluginOpts) error {
	// set log level
	ctx := opts.LoggingFlagOpts.InitializeLogger(command.Context())

	reference := opts.reference
	ref, err := registry.ParseReference(reference)
	if err != nil {
		return err
	}
	// generate remote repository
	remoteRepo, err := getRepositoryClient(ctx, &opts.SecureFlagOpts, ref)
	if err != nil {
		return err
	}
	// read the reference manifest
	referenceManifestDescriptor, err := remoteRepo.Resolve(ctx, ref.Reference)
	if err != nil {
		return err
	}
	manifestJSON, err := content.FetchAll(ctx, remoteRepo.Manifests(), referenceManifestDescriptor)
	if err != nil {
		return err
	}
	var pluginManifest ocispec.Manifest
	if err := json.Unmarshal(manifestJSON, &pluginManifest); err != nil {
		return err
	}
	pluginBlobDesc := pluginManifest.Layers[0]
	pluginBlob, err := content.FetchAll(ctx, remoteRepo.Blobs(), pluginBlobDesc)
	if err != nil {
		return err
	}

	// install the plugin
	pluginName := opts.pluginName
	pluginFile := path.Join(pluginName, plugininternal.BinName(pluginName))
	pluginPath, err := dir.PluginFS().SysPath(pluginFile)
	if err != nil {
		return err
	}
	err = osutil.WriteFile(pluginPath, pluginBlob)
	if err != nil {
		return err
	}

	// mark the plugin as executable
	err = os.Chmod(pluginPath, 0700)
	if err != nil {
		return err
	}

	// validate the installed plugin
	pluginInstalled, err := plugin.NewCLIPlugin(ctx, pluginName, pluginPath)
	if err != nil {
		if err := os.Remove(pluginPath); err != nil {
			return fmt.Errorf("installed plugin failed validation and cannot be removed, %v", err)
		}
		return fmt.Errorf("plugin failed validation, %v", err)
	}
	_, err = pluginInstalled.GetMetadata(ctx, &proto.GetMetadataRequest{})
	if err != nil {
		if err := os.Remove(pluginPath); err != nil {
			return fmt.Errorf("installed plugin failed to get metadata and cannot be removed, %v", err)
		}
		return fmt.Errorf("plugin failed to get metadata, %v", err)
	}
	return nil
}

func pluginListCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "list [flags]",
		Aliases: []string{"ls"},
		Short:   "List installed plugins",
		Long: `List installed plugins

Example - List installed Notation plugins:
  notation plugin ls
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return listPlugins(cmd)
		},
	}
}

func listPlugins(command *cobra.Command) error {
	mgr := plugin.NewCLIManager(dir.PluginFS())
	pluginNames, err := mgr.List(command.Context())
	if err != nil {
		return err
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(tw, "NAME\tDESCRIPTION\tVERSION\tCAPABILITIES\tERROR\t")

	var pl plugin.Plugin
	var resp *proto.GetMetadataResponse
	for _, n := range pluginNames {
		pl, err = mgr.Get(command.Context(), n)
		metaData := &proto.GetMetadataResponse{}
		if err == nil {
			resp, err = pl.GetMetadata(command.Context(), &proto.GetMetadataRequest{})
			if err == nil {
				metaData = resp
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%v\t%v\t\n",
			n, metaData.Description, metaData.Version, metaData.Capabilities, err)
	}
	return tw.Flush()
}
