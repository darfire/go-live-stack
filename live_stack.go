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

const (
	READ    = 1
	WRITE   = 2
	EXECUTE = 4
	SHARED  = 8
	PRIVATE = 16
)

type MappedRegion struct {
	Start       uint64
	End         uint64
	Permissions uint32
	Offset      uint64
	Device      string
	Inode       uint64
	Pathname    string
	IsFile      bool
}

func (region *MappedRegion) IsExecutable() bool {
	return (region.Permissions & EXECUTE) != 0
}

type ProcessContext struct {
	Pid uint32

	Regions []MappedRegion

	Elfs map[string]ElfContext
}

type StackFrame struct {
	InstructionPointer uint64
	Symbol             *elf.Symbol
	Offset             uint64
	Region             *MappedRegion
	Error              error
}

type ElfContext struct {
	Pathname string
	File     *elf.File
	Symbols  []elf.Symbol
}

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

	symbols, err := elfFile.Symbols()

	if err != nil {
		return ElfContext{}, err
	}

	slices.SortFunc(symbols, func(a, b elf.Symbol) int {
		return cmp.Compare(a.Value, b.Value)
	})

	return ElfContext{
		Pathname: pathname,
		Symbols:  symbols,
		File:     elfFile,
	}, nil
}

func ParseAddress(str string) (uint64, uint64, error) {
	tokens := strings.Split(str, "-")

	if len(tokens) != 2 {
		return 0, 0, errors.New("invalid address format")
	}

	start, err := strconv.ParseUint(tokens[0], 16, 16)

	if err != nil {
		return 0, 0, err
	}

	end, err := strconv.ParseUint(tokens[1], 16, 16)

	if err != nil {
		return 0, 0, err
	}

	return start, end, nil
}

func ParsePermissions(str string) (uint32, error) {
	if len(str) != 4 {
		return 0, errors.New("invalid permissions format")
	}

	var val uint32 = 0

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
		default:
			return 0, errors.New("invalid permission flag")
		}
	}

	return val, nil
}

func ParseMappedRegion(line string) (MappedRegion, error) {
	tokens := strings.Fields(line)

	if len(tokens) < 5 || len(tokens) > 6 {
		return MappedRegion{}, errors.New("invalid mapped region format")
	}

	start, end, err := ParseAddress(tokens[0])

	if err != nil {
		return MappedRegion{}, err
	}

	permissions, err := ParsePermissions(tokens[1])

	if err != nil {
		return MappedRegion{}, err
	}

	offset, err := strconv.ParseUint(tokens[2], 16, 16)

	if err != nil {
		return MappedRegion{}, err
	}

	device := tokens[3]

	inode, err := strconv.ParseUint(tokens[4], 10, 10)

	if err != nil {
		return MappedRegion{}, err
	}

	var pathname string

	if len(tokens) == 6 {
		pathname = tokens[5]
	}

	isFile := len(pathname) > 0 && pathname[0] != '['

	return MappedRegion{
		Start:       start,
		End:         end,
		Permissions: permissions,
		Offset:      offset,
		Device:      device,
		Inode:       inode,
		Pathname:    pathname,
		IsFile:      isFile,
	}, nil
}

func NewProcessContext(pid uint32) (ProcessContext, error) {
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

		region, err := ParseMappedRegion(line)

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
				// moan about it
				continue
			}

			elfFiles[r.Pathname] = elfCtx
		}
	}

	ctx := ProcessContext{
		Pid:     pid,
		Regions: regions,
		Elfs:    elfFiles,
	}

	return ctx, nil
}

func (ctx *ElfContext) GetSymbol(offset uint64) (*elf.Symbol, error) {
	idx, ok := slices.BinarySearchFunc(ctx.Symbols, offset, func(symbol elf.Symbol, offset uint64) int {
		if symbol.Value > offset {
			return -1
		} else if symbol.Value+symbol.Size < offset {
			return 1
		} else {
			return 0
		}
	})

	if !ok {
		return nil, errors.New("symbol not found at given offset")
	}

	return &ctx.Symbols[idx], nil
}

func (ctx *ProcessContext) ResolveFrame(ip uint64) StackFrame {
	frame := StackFrame{
		InstructionPointer: ip,
	}

	idx, ok := slices.BinarySearchFunc(ctx.Regions, ip, func(region MappedRegion, ip uint64) int {
		if region.Start > ip {
			return -1
		} else if region.End < ip {
			return 1
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
		frame.Error = errors.New("corresponding elf file not found")

		return frame
	}

	// identify the corresponding symbol
	fileOffset := (ip - region.Start) + region.Offset

	symbol, err := elfFile.GetSymbol(fileOffset)

	offset := fileOffset - symbol.Value

	if err != nil {
		frame.Error = err

		return frame
	}

	frame.Symbol = symbol

	frame.Offset = offset

	return frame
}

func (ctx *ProcessContext) GetStackTrace(stack []uint64) []StackFrame {
	frames := make([]StackFrame, len(stack))

	for _, ip := range stack {
		frame := ctx.ResolveFrame(ip)

		frames = append(frames, frame)
	}

	return frames
}
