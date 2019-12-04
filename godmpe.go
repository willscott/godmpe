package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"

	"github.com/go-delve/delve/pkg/proc/core/minidump"
	"github.com/spf13/cobra"
	pe "github.com/willscott/pefile-go"
)

var rootCmd = &cobra.Command{
	Use:   "godmpe",
	Short: "godmpe will reformat the memory from a mini.dmp into a PE",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 2 {
			fmt.Printf("Usage: godmpe <mini.dmp> <template.exe> [out.exe]")
			return
		}
		outfile := args[1] + ".out.exe"
		if len(args) > 2 {
			outfile = args[2]
		}
		dmp, err := minidump.Open(args[0], nil)
		if err != nil {
			fmt.Printf("dmp open failed: %v\n", err)
			return
		}
		if dmp == nil {
			fmt.Printf("no dmp :(\n")
			return
		}

		peFile, err := pe.NewPEFile(args[1])
		if err != nil {
			fmt.Printf("pe open failed: %v\n", err)
			return
		}

		newSegments := make([]minidump.MemoryRange, 0)
		for _, memRng := range dmp.MemoryRanges {
			// is it already defined as a segment in the peFile?
			s := getSectionByRVA(peFile, uint32(memRng.Addr))
			if s != nil {
				patchSpace(memRng, peFile, s)
			} else if s = getSectionByRVA(peFile, uint32(memRng.Addr)+uint32(len(memRng.Data))); s != nil {
				patchSpace(memRng, peFile, s)
			} else if len(newSegments) > 0 {
				prevSeg := newSegments[len(newSegments)-1]
				if prevSeg.Addr+uint64(len(prevSeg.Data)) == memRng.Addr {
					prevSeg.Data = append(prevSeg.Data, memRng.Data...)
				} else {
					newSegments = append(newSegments, memRng)
				}
			} else {
				newSegments = append(newSegments, memRng)
			}
		}

		for i, seg := range newSegments {
			h := pe.SectionHeader{}
			h.Size = uint32(binary.Size(h.Data))
			h.Flags = make(map[string]bool)
			h.DataBytes = seg.Data
			name := []uint8(fmt.Sprintf(".dm%05d", i))
			copy(h.Data.Name[:], name[:])
			h.Data.VirtualAddress = uint32(seg.Addr)
			h.Data.SizeOfRawData = uint32(len(seg.Data))
			h.Data.Characteristics = getCharacteristicsAtAddress(dmp, seg.Addr)
			peFile.Sections = append(peFile.Sections, h)
			peFile.COFFFileHeader.Data.NumberOfSections++
		}
		fmt.Printf("found %d new segments after collating\n", len(newSegments))

		if err = peFile.Write(outfile); err != nil {
			fmt.Printf("failed to write out file: %v\n", err)
		}
	},
}

func main() {
	rootCmd.Execute()
}

func getCharacteristicsAtAddress(dmp *minidump.Minidump, addr uint64) uint32 {
	// try to find a meminfo for this address.
	for _, info := range dmp.MemoryInfo {
		if info.Addr <= addr && info.Addr+info.Size >= addr {
			char := uint32(0)
			if (info.Protection & minidump.MemoryProtectReadOnly) != 0 {
				char |= pe.SectionCharacteristics["IMAGE_SCN_MEM_READ"]
			}
			if (info.Protection & minidump.MemoryProtectReadWrite) != 0 {
				char |= pe.SectionCharacteristics["IMAGE_SCN_MEM_READ"]
				char |= pe.SectionCharacteristics["IMAGE_SCN_MEM_WRITE"]
			}
			if (info.Protection & minidump.MemoryProtectWriteCopy) != 0 {
				char |= pe.SectionCharacteristics["IMAGE_SCN_MEM_WRITE"]
			}
			if (info.Protection & minidump.MemoryProtectExecute) != 0 {
				char |= pe.SectionCharacteristics["IMAGE_SCN_MEM_EXECUTE"]
			}
			if (info.Protection & minidump.MemoryProtectExecuteRead) != 0 {
				char |= pe.SectionCharacteristics["IMAGE_SCN_MEM_EXECUTE"]
				char |= pe.SectionCharacteristics["IMAGE_SCN_MEM_READ"]
			}
			if (info.Protection & minidump.MemoryProtectExecuteReadWrite) != 0 {
				char |= pe.SectionCharacteristics["IMAGE_SCN_MEM_EXECUTE"]
				char |= pe.SectionCharacteristics["IMAGE_SCN_MEM_READ"]
				char |= pe.SectionCharacteristics["IMAGE_SCN_MEM_WRITE"]
			}
			if (info.Protection & minidump.MemoryProtectNoCache) != 0 {
				char |= pe.SectionCharacteristics["IMAGE_SCN_MEM_NOT_CACHED"]
			}
			return char
		}
	}

	return pe.SectionCharacteristics["IMAGE_SCN_CNT_INITIALIZED_DATA"] |
		pe.SectionCharacteristics["IMAGE_SCN_ALIGN_16BYTES"] |
		pe.SectionCharacteristics["IMAGE_SCN_MEM_EXECUTE"] |
		pe.SectionCharacteristics["IMAGE_SCN_MEM_READ"] |
		pe.SectionCharacteristics["IMAGE_SCN_MEM_WRITE"]
}
func patchSpace(region minidump.MemoryRange, p *pe.PEFile, segment *pe.SectionHeader) bool {
	sliceStart := uint32(region.Addr) - segment.Data.VirtualAddress
	if uint32(region.Addr) >= segment.Data.VirtualAddress && len(region.Data)+int(sliceStart) <= len(segment.DataBytes) {
		if bytes.Equal(region.Data, segment.DataBytes[sliceStart:sliceStart+uint32(len(region.Data))]) {
			fmt.Printf("byte-equal replacement of memory space requested.")
			return false
		}
	} else if uint32(region.Addr) < segment.Data.VirtualAddress {
		// prepend the segment down to the start of the region w/ 0's, then proceed normally.
		prefill := segment.Data.VirtualAddress - uint32(region.Addr)
		zeros := make([]byte, prefill)
		segment.DataBytes = append(zeros, segment.DataBytes...)
		segment.Data.SizeOfRawData += prefill
		segment.Data.VirtualAddress = uint32(region.Addr)
		sliceStart = 0
	}
	newMem := make([]byte, max(uint32(len(segment.DataBytes)), uint32(len(region.Data))+sliceStart))
	copy(newMem[:], segment.DataBytes[:])
	copy(newMem[sliceStart:sliceStart+uint32(len(region.Data))], region.Data[:])
	segment.DataBytes = newMem
	segment.Data.SizeOfRawData = uint32(len(newMem))

	return true
}

func adjustFileAlignment(p *pe.PEFile, ptr uint32) uint32 {
	fileAlignment := p.OptionalHeader.Data.FileAlignment

	if fileAlignment > pe.FILE_ALIGNMENT_HARDCODED_VALUE {
		// If it's not a power of two, report it:
		if !pe.PowerOfTwo(fileAlignment) {
			log.Printf("If FileAlignment > 0x200 it should be a power of 2. Value: %x", fileAlignment)
		}
	}

	if fileAlignment < pe.FILE_ALIGNMENT_HARDCODED_VALUE {
		return ptr
	}

	return (ptr / 0x200) * 0x200
}

func adjustSectionAlignment(p *pe.PEFile, ptr uint32) uint32 {
	sectionAlignment := p.OptionalHeader.Data.SectionAlignment
	fileAlignment := p.OptionalHeader.Data.FileAlignment
	if fileAlignment < pe.FILE_ALIGNMENT_HARDCODED_VALUE {
		if fileAlignment != sectionAlignment {
			log.Printf("If FileAlignment(%x) < 0x200 it should equal SectionAlignment(%x)", fileAlignment, sectionAlignment)
		}
	}
	if sectionAlignment < 0x1000 { // page size
		sectionAlignment = fileAlignment
	}

	if sectionAlignment != 0 && (ptr%sectionAlignment) != 0 {
		return sectionAlignment * (ptr / sectionAlignment)
	}
	return ptr
}

func max(x, y uint32) uint32 {
	if x < y {
		return y
	}
	return x
}

func getSectionByRVA(p *pe.PEFile, rva uint32) *pe.SectionHeader {
	fi, err := os.Stat(p.Filename)
	if err != nil {
		return nil
	}
	dataLen := uint32(fi.Size())

	for _, section := range p.Sections {
		var size uint32
		adjustedPointer := adjustFileAlignment(p, section.Data.PointerToRawData)
		if dataLen-adjustedPointer < section.Data.SizeOfRawData {
			size = section.Data.Misc
		} else {
			size = max(section.Data.SizeOfRawData, section.Data.Misc)
		}
		vaddr := adjustSectionAlignment(p, section.Data.VirtualAddress)

		if section.NextHeaderAddr != 0 && section.NextHeaderAddr > section.Data.VirtualAddress && vaddr+size > section.NextHeaderAddr {
			size = section.NextHeaderAddr - vaddr
		}

		if vaddr <= rva && rva < (vaddr+size) {
			return &section
		}
	}
	return nil
}
