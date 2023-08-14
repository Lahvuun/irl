use std::io::{Cursor, Write, Seek, SeekFrom};

use byteorder::{WriteBytesExt, LittleEndian};
use coff::SymbolTableRecord;

mod pe;
mod coff;
mod image_info;

const IMAGE_SCN_CNT_CODE: u32 = 0x00000020;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
const IMAGE_SCN_LNK_COMDAT: u32 = 0x00001000;
const IMAGE_SCN_ALIGN_2BYTES: u32 = 0x00200000;
const IMAGE_SCN_ALIGN_4BYTES: u32 = 0x00300000;
const IMAGE_SCN_ALIGN_16BYTES: u32 = 0x00500000;
const IMAGE_SCN_ALIGN_32BYTES: u32 = 0x00600000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

fn main() {
    let args = std::env::args().collect::<Vec<String>>();

    let pe_bytes = std::fs::read(&args[1]).unwrap();
    let image_info_string = std::fs::read_to_string(&args[2]).unwrap();
    let coff_bytes = std::fs::read(&args[3]).unwrap();
    let out_path_string = &args[4];

    let mut pe = pe::read_image(Cursor::new(pe_bytes));
    let mut symbol_table = Vec::new();
    image_info::fill_image_and_symbol_table_with_image_info(&mut pe, &mut symbol_table, &image_info_string);

    {
        let section_count = i16::try_from(pe.sections.len()).unwrap();
        let mut coff = coff::read_coff(Cursor::new(coff_bytes));
        for symbol in &mut coff.symbols {
            match symbol {
                coff::SymbolTableRecord::Symbol(s) => move_symbol(s, section_count),
                coff::SymbolTableRecord::Aux(_) => (),
            }
        }
        append_sections(&mut pe, &mut coff, u32::try_from(symbol_table.len()).unwrap());
        symbol_table.extend(coff.symbols);
    }

    fix_relocations(&mut pe, symbol_table);

    let mut buffer = Vec::new();
    let mut cursor = Cursor::new(&mut buffer);
    pe::write_image(pe, &mut cursor);
    std::fs::File::create(out_path_string).unwrap().write_all(&buffer).unwrap();
}

fn move_symbol(s: &mut coff::Symbol, offset: i16) {
    if s.section_number < 1 {
        return;
    }
    s.section_number += offset;
}

fn append_sections(image: &mut pe::Image, coff: &mut coff::COFF, symbol_table_index_delta: u32) {
    let section_alignment = image.optional_header.section_alignment;
    let file_alignment = image.optional_header.file_alignment;
    for si in 0..coff.sections.len() {
        let section = &mut coff.sections[si];

        let raw_data_length = u32::try_from(section.raw_data.len()).unwrap();
        if raw_data_length == 0 {
            continue;
        }

        section.virtual_size = calculate_aligned_size(raw_data_length, section_alignment);
        assert_eq!(section.virtual_size % section_alignment, 0);

        let last_image_section = &image.sections[image.sections.len() - 1];
        let last_image_section_virtual_size = calculate_aligned_size(last_image_section.virtual_size, section_alignment);
        section.virtual_address = last_image_section.virtual_address + last_image_section_virtual_size;
        assert_eq!(section.virtual_address % section_alignment, 0);

        let raw_data_alignment_difference = raw_data_length % file_alignment;
        if raw_data_alignment_difference != 0 {
            // TODO: evaluate other bytes?
            let padding = vec![0xcc; usize::try_from(file_alignment - raw_data_alignment_difference).unwrap()];
            section.raw_data.extend(padding);
        }

        for ri in 0..section.relocations.len() {
            let relocation = &mut section.relocations[ri];
            relocation.symbol_table_index += symbol_table_index_delta;
        }

        let alignment_characteristics =
            section.characteristics
            & !IMAGE_SCN_CNT_CODE
            & !IMAGE_SCN_CNT_INITIALIZED_DATA
            & !IMAGE_SCN_CNT_UNINITIALIZED_DATA
            & !IMAGE_SCN_MEM_EXECUTE
            & !IMAGE_SCN_MEM_READ
            & !IMAGE_SCN_MEM_WRITE;
        assert!(alignment_characteristics == (IMAGE_SCN_LNK_COMDAT | IMAGE_SCN_ALIGN_4BYTES)
                || alignment_characteristics == IMAGE_SCN_ALIGN_2BYTES
                || alignment_characteristics == IMAGE_SCN_ALIGN_4BYTES
                || alignment_characteristics == IMAGE_SCN_ALIGN_16BYTES
                || alignment_characteristics == IMAGE_SCN_ALIGN_32BYTES);

        section.characteristics =
            section.characteristics
            & (IMAGE_SCN_CNT_CODE
               | IMAGE_SCN_CNT_INITIALIZED_DATA
               | IMAGE_SCN_CNT_UNINITIALIZED_DATA
               | IMAGE_SCN_MEM_EXECUTE
               | IMAGE_SCN_MEM_READ
               | IMAGE_SCN_MEM_WRITE);

        // TODO: This should probably be calculated.
        image.coff_header.number_of_sections += 1;
        image.optional_header.size_of_image += section.virtual_size;

        image.sections.push(std::mem::take(section));
    }
}

fn calculate_aligned_size(size: u32, alignment: u32) -> u32 {
    let alignment_difference = size % alignment;
    if alignment_difference != 0 {
        return size + alignment - alignment_difference;
    }
    return size;
}

#[derive(Debug)]
struct RelocationPatch {
    symbol_section_number: i16,
    symbol_value: u32,
    relocation_section_index: usize,
    relocation_position: u32,
    relocation_type: RelocationType,
}

#[derive(Debug)]
enum RelocationType {
    Dir32,
    Dir32NB,
    Rel32,
}

fn fix_relocations(image: &mut pe::Image, symbol_table: Vec<SymbolTableRecord>) {
    let mut patches = Vec::new();
    let mut si = 0;
    for section in &mut image.sections {
        for relocation in &mut section.relocations {
            let relocation_type = match relocation.relocation_type {
                0x0006 => RelocationType::Dir32,
                0x0007 => RelocationType::Dir32NB,
                0x0014 => RelocationType::Rel32,
                n => panic!("unknown relocation type {:#06x}", n),
            };
            let undefined_symbol = match &symbol_table[usize::try_from(relocation.symbol_table_index).unwrap()] {
                SymbolTableRecord::Symbol(s) => s,
                SymbolTableRecord::Aux(_) => panic!("tried to look up aux symbol"),
            };
            let defined_symbol = find_defined_symbol(undefined_symbol, &symbol_table);
            patches.push(RelocationPatch {
                symbol_section_number: defined_symbol.section_number,
                symbol_value: defined_symbol.value,
                relocation_section_index: si,
                relocation_position: relocation.virtual_address,
                relocation_type,
            });
        }
        si += 1;
    }

    for patch in patches {
        match patch.relocation_type {
            RelocationType::Dir32 => {
                let va = image.optional_header.image_base + image.sections[usize::try_from(patch.symbol_section_number - 1).unwrap()].virtual_address + patch.symbol_value;

                let mut raw_data_cursor = Cursor::new(&mut image.sections[patch.relocation_section_index].raw_data);
                raw_data_cursor.seek(SeekFrom::Start(u64::from(patch.relocation_position))).unwrap();
                raw_data_cursor.write_u32::<LittleEndian>(va).unwrap();
            }
            RelocationType::Dir32NB => {
                let rva = image.sections[usize::try_from(patch.symbol_section_number - 1).unwrap()].virtual_address + patch.symbol_value;

                let mut raw_data_cursor = Cursor::new(&mut image.sections[patch.relocation_section_index].raw_data);
                raw_data_cursor.seek(SeekFrom::Start(u64::from(patch.relocation_position))).unwrap();
                raw_data_cursor.write_u32::<LittleEndian>(rva).unwrap();
            }
            RelocationType::Rel32 => {
                let symbol_section_virtual_address = image.sections[usize::try_from(patch.symbol_section_number - 1).unwrap()].virtual_address;
                let relocation_section_virtual_address = image.sections[patch.relocation_section_index].virtual_address;
                let symbol_virtual_address = image.optional_header.image_base + symbol_section_virtual_address + patch.symbol_value;
                let displacement = symbol_virtual_address.overflowing_sub(image.optional_header.image_base + relocation_section_virtual_address + patch.relocation_position + 4).0;

                let mut raw_data_cursor = Cursor::new(&mut image.sections[patch.relocation_section_index].raw_data);
                raw_data_cursor.seek(SeekFrom::Start(u64::from(patch.relocation_position))).unwrap();
                raw_data_cursor.write_u32::<LittleEndian>(displacement).unwrap();
            }
        }
    }
}

fn find_defined_symbol<'a>(undefined_symbol: &'a coff::Symbol, symbol_table: &'a Vec<SymbolTableRecord>) -> &'a coff::Symbol {
    for symbol in symbol_table {
        let s = match symbol {
            SymbolTableRecord::Symbol(s) => s,
            SymbolTableRecord::Aux(_) => continue,
        };
        if s.name == undefined_symbol.name
            && s.storage_class == undefined_symbol.storage_class
            && s.symbol_type == undefined_symbol.symbol_type
            && s.section_number > 0 {
                return s;
            }
    }
    panic!("could not find defined symbol for {}", undefined_symbol.name);
}
