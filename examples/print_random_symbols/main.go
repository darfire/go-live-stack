package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"os"

	live_stack "github.com/darfire/go-live-stack"
)

func getRandomIp(regions []*live_stack.MappedRegion, totalSize uint64) uint64 {
	offset := rand.Uint64() % totalSize

	for _, r := range regions {
		if offset < r.Size() {
			ip := r.Start + offset

			fmt.Printf("Generating random ip: 0x%x from region: %s at offset: 0x%x\n",
				ip, r, offset)

			return ip
		} else {
			offset -= r.Size()
		}
	}
	return 0
}

func main() {
	var pid int
	var n int
	var showDetails bool

	flag.IntVar(&pid, "pid", os.Getpid(), "Process to analyze")
	flag.IntVar(&n, "n", 1, "Number of locations to generate")
	flag.BoolVar(&showDetails, "details", false, "Show details for each generated location")

	flag.Parse()

	pctx, err := live_stack.NewProcessContext(pid)

	if err != nil {
		log.Fatalf("Process with pid=%d not found\n", pid)
	}

	fmt.Printf("Got pctx: %s", pctx.String())

	if showDetails {
		fmt.Printf("%d ELF files:\n", len(pctx.Elfs))

		for _, elf := range pctx.Elfs {
			fmt.Printf("  %s, %d sections, %d symbols\n",
				elf.Pathname, len(elf.File.Sections), len(elf.Symbols))
			fmt.Printf("  Sections:\n")
			for idx, section := range elf.File.Sections {
				fmt.Printf("    %d: %s, addr=0x%x, size=0x%x, offset=0x%x, type=%s\n",
					idx, section.Name, section.Addr, section.Size, section.Offset, section.Type)
			}

			fmt.Printf("  Symbols:\n")
			for idx, symbol := range elf.Symbols {
				section := elf.GetSection(symbol.Section)

				var sectionName string

				if section != nil {
					sectionName = section.Name
				}

				fmt.Printf("    %d: %s, value=0x%x, size=0x%x, section=%s, fileOffset=0x%x\n",
					idx, symbol.Name, symbol.Value, symbol.Size, sectionName, symbol.FileOffset)
			}
		}
	}

	regions := make([]*live_stack.MappedRegion, 0)

	var totalSize uint64

	for _, r := range pctx.Regions {
		if r.IsExecutableFile() {
			regions = append(regions, &r)

			totalSize += r.Size()
		}
	}

	fmt.Printf("Generating %d random ips from %d regions totalling %d(0x%x) bytes\n",
		n, len(regions), totalSize, totalSize)

	ips := make([]uint64, 0, n)

	for i := 0; i < n; i++ {
		ip := getRandomIp(regions, totalSize)

		ips = append(ips, ip)
	}

	stackFrame := pctx.GetStackTrace(ips)

	for i, f := range stackFrame {
		fmt.Print(f.Describe(i))
	}
}
