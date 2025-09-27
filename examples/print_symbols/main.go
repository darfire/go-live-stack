package main

import (
	"log"
	"flag"
	"debug/elf"
	"os"
	"fmt"
)

func describeSymbol(symbol *elf.Symbol) {
	sbind := elf.ST_BIND(symbol.Info)
	stype := elf.ST_TYPE(symbol.Info)

	fmt.Printf("%s: 0x%x(0x%x) %s:%s\n",
		symbol.Name, symbol.Value, symbol.Size, sbind, stype,
	)
}

func describeSection(section *elf.Section) {
	sh := section.SectionHeader
	fmt.Printf(
		"%s: %s, %s, addr=0x%x, offset=0x%x, size=0x%x, link=0x%x, info=0x%x, addralign=0x%x, entsize=0x%x\n",
		sh.Name, sh.Type, sh.Flags, sh.Addr, sh.Offset, sh.Size, sh.Link,
		sh.Info, sh.Addralign, sh.Entsize,
	)
}


func main() {
	var fname string
	
	flag.StringVar(&fname, "fname", "", "The file to inspect")
	
	flag.Parse()
	
	file, err := os.Open(fname)
	
	if err != nil {
		log.Fatalf("Could not open file: %s", err)
	}
	
	elfFile, err := elf.NewFile(file)
	
	if err != nil {
		log.Fatalf("Could not parse ELF file: %s", err)
	}
	
	symbols, err := elfFile.Symbols()
	
	if err != nil {
		log.Fatalf("Could not fetch symbols")
	}
	
	fmt.Printf("Sections:\n");
	
	for _, s := range elfFile.Sections {
		describeSection(s);
	}
	
	fmt.Printf("Symbols:\n")
	
	for _, s := range symbols {
		describeSymbol(&s)
	}
}
