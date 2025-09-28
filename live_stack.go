package live_stack

import (
	"bufio"
	"cmp"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
)

type Permissions uint32

const (
	READ    = 1
	WRITE   = 2
	EXECUTE = 4
	SHARED  = 8
	PRIVATE = 16
)

func (perm Permissions) String() string {
	var sb strings.Builder

	if (perm & READ) != 0 {
		sb.WriteString("r")
	} else {
		sb.WriteString("-")
	}

	if (perm & WRITE) != 0 {
		sb.WriteString("w")
	} else {
		sb.WriteString("-")
	}

	if (perm & EXECUTE) != 0 {
		sb.WriteString("x")
	} else {
		sb.WriteString("-")
	}

	if (perm & SHARED) != 0 {
		sb.WriteString("s")
	} else if (perm & PRIVATE) != 0 {
		sb.WriteString("p")
	} else {
		sb.WriteString("-")
	}

	return sb.String()
}

// Parse a line from /proc/<pid>/maps

// Each MappedRegion corresponds to a single line in /proc/<pid>/maps. It describes
// a memory area mapped into the process's virtual memory space.
type MappedRegion struct {
	// Start of the virtual memory region
	Start uint64
	// End of the virtual memory region
	End uint64
	// Permissions of the memory region; can be a combination of READ, WRITE, EXECUTE and zero or one of SHARED or PRIVATE
	Permissions Permissions
	// Offset in the associated file
	Offset uint64
	// The device where the associated file is stored
	Device string
	// The inode associated with the mapped file
	Inode uint64
	// The full path to the mapped file, or the memory segment like [stack], [heap], etc.
	Pathname string
	// Whether Pathname points to a file
	IsFile bool
}

// Check if the memory is executable
func (region *MappedRegion) IsExecutable() bool {
	return (region.Permissions & EXECUTE) != 0
}

// Check if it's mapped from a file and executable
func (region *MappedRegion) IsExecutableFile() bool {
	return region.IsExecutable() && region.IsFile
}

// The size of the memory region
func (region *MappedRegion) Size() uint64 {
	return region.End - region.Start
}

// A wrapper objects around the data on a running process and it's consituend ELF binaries
type ProcessContext struct {
	// The process id
	Pid int

	// Mapped regions from /proc/<pid>/maps
	Regions []MappedRegion

	// The parsed ELF files for the executable and shared libraries
	Elfs map[string]ElfContext
}

func (ctx *ProcessContext) String() string {
	return fmt.Sprintf("ProcessContext(pid=%d, regions=%d)\n", ctx.Pid, len(ctx.Regions))
}

// A StackFrame, possibly resolved
type StackFrame struct {
	// The instruction pointer in the running process's memory
	InstructionPointer uint64
	// The resolved symbol
	Symbol *Symbol
	// The offset inside the symbol
	Offset uint64
	// The mapped region where this address resides
	Region *MappedRegion
	// The error, if resolving the symbol failed
	Error error
}

// All the information related to a symbol from the symbol table of an ELF file
type Symbol struct {
	// The original ELF-file symbol in the symbol table
	elf.Symbol
	// The offset inside the file where this symbol resides
	FileOffset uint64
}

func (frame *StackFrame) Describe(idx int) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "Index: %d, Instruction Pointer: 0x%0x\n", idx, frame.InstructionPointer)

	if frame.Error != nil {
		fmt.Fprintf(&sb, "\tError: %s\n", frame.Error)
	} else if frame.Symbol != nil {
		fmt.Fprintf(&sb, "\tSymbol: %s (base=0x%x, size=0x%x), offset=0x%x\n",
			frame.Symbol.Name, frame.Symbol.Value, frame.Symbol.Size, frame.Offset)
		fmt.Fprintf(&sb, "\tFile Offset: 0x%x\n", frame.Symbol.FileOffset)
	}
	return sb.String()
}

// A parsed ELF file
type ElfContext struct {
	// The path of the ELF file
	Pathname string
	// The ELF file handle
	File *elf.File
	// The complete symbol table, sorted by FileOffset
	Symbols []Symbol
}

// Parse an ELF file
func NewElfContext(pathname string) (ElfContext, error) {
	file, err := os.Open(pathname)

	if err != nil {
		return ElfContext{}, err
	}
	defer file.Close()

	elfFile, err := elf.NewFile(file)

	if err != nil {
		return ElfContext{}, err
	}

	elfSymbols, err := elfFile.Symbols()

	if err != nil {
		return ElfContext{}, err
	}

	symbols := make([]Symbol, 0, len(elfSymbols))

	nSections := len(elfFile.Sections)

	for _, s := range elfSymbols {
		fileOffset := 0

		if int(s.Section) < nSections {
			section := elfFile.Sections[s.Section]
			fileOffset = int(s.Value-section.Addr) + int(section.Offset)
		}

		symbols = append(symbols, Symbol{
			Symbol:     s,
			FileOffset: uint64(fileOffset),
		})
	}

	slices.SortFunc(symbols, func(a, b Symbol) int {
		return cmp.Compare(a.FileOffset, b.FileOffset)
	})

	ctx := ElfContext{
		Pathname: pathname,
		Symbols:  symbols,
		File:     elfFile,
	}

	/*
	   fmt.Printf("Describing elf file: %s\n", pathname)

	   fmt.Printf("Sections: %d\n", len(ctx.File.Sections))

	   for idx, section := range ctx.File.Sections {
	   fmt.Printf("Section %d: %s (base=0x%x, size=0x%x, offset=0x%x), type=%s\n",
	   idx, section.Name, section.Addr, section.Size, section.Offset, section.Type)
	   }

	   fmt.Printf("Symbols: %d\n", len(symbols))
	   for _, symbol := range ctx.Symbols {
	   section := ctx.GetSection(symbol.Section)

	   fmt.Printf(
	   "Symbol: %s (base=0x%x, size=0x%x) sectionIdx=%s",
	   symbol.Name, symbol.Value, symbol.Size, symbol.Section)

	   if section != nil {
	   fileOffset := (symbol.Value - section.Addr) + section.Offset
	   fmt.Printf(
	   ", section: %s (base=0x%x, size=0x%x, offset=0x%x), fileOffset=0x%x",
	   section.Name, section.Addr, section.Size, section.Offset, fileOffset)
	   }

	   fmt.Println()
	   }
	*/

	return ctx, nil
}

func parseAddress(str string) (uint64, uint64, error) {
	tokens := strings.Split(str, "-")

	if len(tokens) != 2 {
		return 0, 0, errors.New("invalid address format")
	}

	start, err := strconv.ParseUint(tokens[0], 16, 64)

	if err != nil {
		return 0, 0, err
	}

	end, err := strconv.ParseUint(tokens[1], 16, 64)

	if err != nil {
		return 0, 0, err
	}

	return start, end, nil
}

func parsePermissions(str string) (Permissions, error) {
	if len(str) != 4 {
		return 0, errors.New("invalid permissions format")
	}

	var val Permissions = 0

	for _, c := range str {
		switch c {
		case 'r':
			val = val | READ
		case 'w':
			val = val | WRITE
		case 'x':
			val = val | EXECUTE
		case 's':
			val = val | SHARED
		case 'p':
			val = val | PRIVATE
		case '-':
			continue
		default:
			return 0, errors.New("invalid permission flag")
		}
	}

	return val, nil
}

func parseMappedRegion(line string) (MappedRegion, error) {
	tokens := strings.Fields(line)

	if len(tokens) < 5 || len(tokens) > 6 {
		return MappedRegion{}, errors.New("invalid mapped region format")
	}

	start, end, err := parseAddress(tokens[0])

	if err != nil {
		return MappedRegion{}, err
	}

	permissions, err := parsePermissions(tokens[1])

	if err != nil {
		return MappedRegion{}, err
	}

	offset, err := strconv.ParseUint(tokens[2], 16, 64)

	if err != nil {
		return MappedRegion{}, err
	}

	device := tokens[3]

	inode, err := strconv.ParseUint(tokens[4], 10, 64)

	if err != nil {
		return MappedRegion{}, err
	}

	var pathname string

	if len(tokens) == 6 {
		pathname = tokens[5]
	}

	isFile := len(pathname) > 0 && pathname[0] != '['

	region := MappedRegion{
		Start:       start,
		End:         end,
		Permissions: permissions,
		Offset:      offset,
		Device:      device,
		Inode:       inode,
		Pathname:    pathname,
		IsFile:      isFile,
	}

	return region, nil
}

func (region *MappedRegion) String() string {
	return fmt.Sprintf("MappedRegion(start=0x%x, end=0x%x, permissions=%s, offset=0x%x, device=%s, inode=%d, pathname=%s, isFile=%t)",
		region.Start, region.End, region.Permissions, region.Offset, region.Device, region.Inode, region.Pathname, region.IsFile)
}

// Create a ProcessContext for a running process
func NewProcessContext(pid int) (ProcessContext, error) {
	maps_path := fmt.Sprintf("/proc/%d/maps", pid)

	file, err := os.Open(maps_path)

	if err != nil {
		return ProcessContext{}, err
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	regions := make([]MappedRegion, 0)

	for scanner.Scan() {
		line := scanner.Text()

		region, err := parseMappedRegion(line)

		if err != nil {
			continue
		}

		regions = append(regions, region)
	}

	slices.SortFunc(regions, func(a, b MappedRegion) int {
		return cmp.Compare(a.Start, b.Start)
	})

	elfFiles := map[string]ElfContext{}

	for _, r := range regions {
		if !(r.IsExecutable() && r.IsFile) {
			continue
		}

		if _, ok := elfFiles[r.Pathname]; !ok {
			elfCtx, err := NewElfContext(r.Pathname)

			if err != nil {
				continue
			}

			elfFiles[r.Pathname] = elfCtx
		}
	}

	/*
	   fmt.Printf("Regions: %d\n", len(regions))

	   for i, r := range regions {
	   fmt.Printf("%d: %s\n", i, r.String())
	   }
	*/

	ctx := ProcessContext{
		Pid:     pid,
		Regions: regions,
		Elfs:    elfFiles,
	}

	return ctx, nil
}

// Fetch a section from an ELF file, based on the section index
func (ctx *ElfContext) GetSection(idx elf.SectionIndex) *elf.Section {
	if idx == 0 || int(idx) > len(ctx.File.Sections) {
		return nil
	}

	return ctx.File.Sections[idx]
}

// Fetch a symbol from an ELF file, based on the file offset
func (ctx *ElfContext) GetSymbol(offset uint64) (*Symbol, error) {
	idx, ok := slices.BinarySearchFunc(ctx.Symbols, offset, func(symbol Symbol, offset uint64) int {
		if symbol.FileOffset > offset {
			return 1
		} else if symbol.FileOffset+symbol.Size < offset {
			return -1
		} else {
			return 0
		}
	})

	if !ok {
		return nil, fmt.Errorf("symbol not found at offset 0x%x", offset)
	}

	return &ctx.Symbols[idx], nil
}

// Resolve a StackFrame from a running process, based on the instruction pointer
func (ctx *ProcessContext) ResolveFrame(ip uint64) StackFrame {
	frame := StackFrame{
		InstructionPointer: ip,
	}

	idx, ok := slices.BinarySearchFunc(ctx.Regions, ip, func(region MappedRegion, ip uint64) int {
		if region.Start > ip {
			return 1
		} else if region.End < ip {
			return -1
		} else {
			return 0
		}
	})

	if !ok {
		frame.Error = errors.New("instruction pointer does not match any region")

		return frame
	}

	region := ctx.Regions[idx]

	if !(region.IsExecutable() && region.IsFile) {
		frame.Error = errors.New("region should be executable and a file")

		return frame
	}

	frame.Region = &region

	elfFile, ok := ctx.Elfs[region.Pathname]

	if !ok {
		frame.Error = fmt.Errorf("elf file %s not found", region.Pathname)

		return frame
	}

	// identify the corresponding symbol
	fileOffset := (ip - region.Start) + region.Offset

	symbol, err := elfFile.GetSymbol(fileOffset)

	if err != nil {
		frame.Error = err

		return frame
	}

	offset := fileOffset - symbol.FileOffset

	frame.Symbol = symbol

	frame.Offset = offset

	return frame
}

// Resolve a stack trace from a running process, given the list of instruction pointers on the stack
func (ctx *ProcessContext) GetStackTrace(stack []uint64) []StackFrame {
	frames := make([]StackFrame, 0, len(stack))

	for _, ip := range stack {
		frame := ctx.ResolveFrame(ip)

		frames = append(frames, frame)
	}

	return frames
}
