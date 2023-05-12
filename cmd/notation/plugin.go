package main

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/opencontainers/go-digest"
	"github.com/spf13/cobra"
)

func pluginCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugin",
		Short: "Manage plugins",
	}
	cmd.AddCommand(pluginListCommand())
	cmd.AddCommand(pluginInstallCommand(nil))
	return cmd
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

type pluginInstallOpts struct {
	url      string
	checksum string
}

func pluginInstallCommand(opts *pluginInstallOpts) *cobra.Command {
	if opts == nil {
		opts = &pluginInstallOpts{}
	}
	command := &cobra.Command{
		Use:     "install [flags]",
		Aliases: []string{"add"},
		Short:   "Install plugin",
		Long: `Install plugin

Example - Install Notation plugin from a remote URL:
  notation plugin install --checksum sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef https://example.com/notation-plugin-example.tar.gz
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.url = args[0]
			return installPlugin(cmd, opts)
		},
	}
	command.Flags().StringVar(&opts.checksum, "checksum", "", "checksum of the plugin")
	return command
}

// TODO: should be implemented in notation-go
func installPlugin(command *cobra.Command, opts *pluginInstallOpts) error {
	// create a temp directory
	tempDir, err := os.MkdirTemp("", "notation-plugin-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)

	// create digester
	checksum := opts.checksum
	if !strings.Contains(checksum, ":") {
		checksum = "sha256:" + checksum
	}
	packageDigest, err := digest.Parse(checksum)
	if err != nil {
		return err
	}

	// download the plugin
	// TODO: should limit the size of the plugin
	// TODO: should configure the http client
	srcPath := filepath.Join(tempDir, "plugin.tar.gz")
	if err := downloadFile(opts.url, packageDigest, srcPath); err != nil {
		return err
	}

	// install the plugin
	// TODO: should support other plugin types
	pluginFilename, pluginFile, err := findPluginExecutable(srcPath)
	if err != nil {
		return err
	}
	defer pluginFile.Close()
	pluginName := strings.TrimSuffix(pluginFilename, filepath.Ext(pluginFilename))
	pluginName = strings.TrimPrefix(pluginName, "notation-")
	pluginDir, err := dir.PluginFS().SysPath(pluginName)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		return err
	}

	// TODO: prompt to overwrite the existing plugin
	destPath := filepath.Join(pluginDir, pluginFilename)
	destFile, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer destFile.Close() // ensure close
	if err := destFile.Chmod(0755); err != nil {
		return err
	}
	if _, err := io.Copy(destFile, pluginFile); err != nil {
		return err
	}
	return destFile.Close()
}

// downloadFile downloads a file from url and verify the checksum
// TODO: add context to cancel the download
func downloadFile(url string, checksum digest.Digest, dest string) error {
	verifier := checksum.Verifier()

	// download the plugin
	// TODO: should limit the size of the plugin
	// TODO: should configure the http client
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	file, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer file.Close() // failsafe close
	writer := io.MultiWriter(file, verifier)
	if _, err := io.Copy(writer, resp.Body); err != nil {
		return err
	}

	// ensure content is written to the file
	if err := file.Close(); err != nil {
		return err
	}

	// verify the checksum
	if !verifier.Verified() {
		return errors.New("checksum mismatch")
	}

	return nil
}

func findPluginExecutable(path string) (string, io.ReadCloser, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", nil, err
	}

	gr, err := gzip.NewReader(file)
	if err != nil {
		file.Close()
		return "", nil, err
	}
	tr := tar.NewReader(gr)
	for {
		header, err := tr.Next()
		if err != nil {
			file.Close()
			if err == io.EOF {
				return "", nil, errors.New("executable not found")
			}
			return "", nil, err
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		if strings.HasPrefix(header.Name, "notation-") {
			return header.Name, struct {
				io.Reader
				io.Closer
			}{
				Reader: tr,
				Closer: file,
			}, nil
		}
	}
}
