// wgkey prints a new WireGuard private and public key, so the tests don't need wg(8).
package main

import (
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func main() {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		panic(err)
	}
	fmt.Println(k.String(), k.PublicKey().String())
}
