package main

import (
	"os"
	"flag"
	"fmt"
	"encoding/hex"
)

func main() {

	var path string

	flag.StringVar(&path, "in", "", "path to .ca-bundle file")

	flag.Parse()

	if (path == "") {
		fmt.Printf("-in /path/to/.ca-bundle required\n")
		os.Exit(1)
	}

	dat, err := os.ReadFile(path)

	if (err != nil) {
		panic(err)
	}

	fmt.Printf("%s\n", hex.EncodeToString(dat))

}
