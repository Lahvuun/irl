use serde::Deserialize;

use super::coff::{SymbolTableRecord, Section, Relocation, create_symbol_for_relocation, create_symbol_for_table};
use super::pe::Image;

pub fn fill_image_and_symbol_table_with_image_info(image: &mut Image, symbol_table: &mut Vec<SymbolTableRecord>, image_info_str: &str) {
    let image_info: ImageInfo = toml::from_str(image_info_str).unwrap();
    fill_image_relocations_and_symbol_table_with_image_info(image_info.relocations, &mut image.sections, symbol_table);
    fill_symbol_table_with_image_info(image_info.symbols, &mut image.sections, symbol_table);
}

fn fill_image_relocations_and_symbol_table_with_image_info(relocations: Vec<ImageInfoRelocation>, image_sections: &mut Vec<Section>, symbol_table: &mut Vec<SymbolTableRecord>) {
    for relocation in relocations {
        let section_number = find_section_number_for_virtual_address(relocation.virtual_address, image_sections);
        let section = &mut image_sections[usize::try_from(section_number).unwrap() - 1];

        // TODO: actually query the imagebase.
        let virtual_address = relocation.virtual_address - 0x400000 - section.virtual_address;
        let symbol_table_index = symbol_table.len();
        symbol_table.push(create_symbol_for_relocation(relocation.name));
        let relocation_type = relocation.relocation_type;

        section.relocations.push(Relocation {
            virtual_address,
            symbol_table_index: u32::try_from(symbol_table_index).unwrap(),
            relocation_type,
        })
    }
}

fn fill_symbol_table_with_image_info(symbols: Vec<ImageInfoSymbol>, image_sections: &Vec<Section>, symbol_table: &mut Vec<SymbolTableRecord>) {
    for symbol in symbols {
        let section_number = find_section_number_for_virtual_address(symbol.virtual_address, image_sections);
        // TODO: actually query the imagebase.
        let value = symbol.virtual_address - 0x400000 - image_sections[usize::try_from(section_number).unwrap() - 1].virtual_address;
        symbol_table.push(create_symbol_for_table(symbol.name, value, section_number, symbol.is_function));
    }
}

fn find_section_number_for_virtual_address(address: u32, image_sections: &Vec<Section>) -> i16 {
    let mut i = 1;
    for section in image_sections {
        if address > section.virtual_address && address < (section.virtual_address + section.virtual_size) {
            return i;
        }
        i += 1;
    }
    panic!("failed to find the section of {:#010x}, recheck the value", address)
}

#[derive(Deserialize, Debug)]
struct ImageInfo {
    relocations: Vec<ImageInfoRelocation>,
    symbols: Vec<ImageInfoSymbol>,
}

#[derive(Deserialize, Debug)]
struct ImageInfoRelocation {
    name: String,
    virtual_address: u32,
    relocation_type: u16,
}

#[derive(Deserialize, Debug)]
struct ImageInfoSymbol {
    name: String,
    virtual_address: u32,
    is_function: bool,
}
