package plugin

import "github.com/notaryproject/notation-go/plugin/proto"

func BinName(name string) string {
	return proto.Prefix + name + ".exe"
}
