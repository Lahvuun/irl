use std::io::{Seek, SeekFrom, Cursor};

use byteorder::{ReadBytesExt, WriteBytesExt, LittleEndian};

pub fn read_coff<F: ReadBytesExt + Seek>(mut coff: F) -> COFF {
    let header = read_header(&mut coff);
    let section_table_position = coff.stream_position().unwrap();

    coff.seek(SeekFrom::Start(u64::from(header.pointer_to_symbol_table) + (u64::from(header.number_of_symbols) * 18))).unwrap();
    let string_table_size = coff.read_u32::<LittleEndian>().unwrap();
    let mut string_table = vec![0; usize::try_from(string_table_size).unwrap()];
    coff.seek(SeekFrom::Current(-4)).unwrap();
    coff.read_exact(&mut string_table).unwrap();

    coff.seek(SeekFrom::Start(section_table_position)).unwrap();
    let sections = read_sections(&mut coff, header.number_of_sections, &string_table);

    coff.seek(SeekFrom::Start(u64::from(header.pointer_to_symbol_table))).unwrap();
    let symbols = read_symbols(&mut coff, header.number_of_symbols, &string_table);

    COFF {sections, symbols}
}

pub fn read_header<F: ReadBytesExt>(coff: &mut F) -> Header {
    let machine = coff.read_u16::<LittleEndian>().unwrap();
    assert_eq!(machine, 0x014c);
    let number_of_sections = coff.read_u16::<LittleEndian>().unwrap();
    let time_date_stamp = coff.read_u32::<LittleEndian>().unwrap();
    let pointer_to_symbol_table = coff.read_u32::<LittleEndian>().unwrap();
    let number_of_symbols = coff.read_u32::<LittleEndian>().unwrap();
    let size_of_optional_header = coff.read_u16::<LittleEndian>().unwrap();
    let characteristics = coff.read_u16::<LittleEndian>().unwrap();

    Header {
        machine,
        number_of_sections,
        time_date_stamp,
        pointer_to_symbol_table,
        number_of_symbols,
        size_of_optional_header,
        characteristics,
    }
}

pub fn read_sections<F: ReadBytesExt + Seek>(coff: &mut F, number_of_sections: u16, string_table: &[u8]) -> Vec<Section> {
    let mut sections = Vec::with_capacity(usize::try_from(number_of_sections).unwrap());
    for _ in 0..number_of_sections {
        let name = read_section_name(coff, string_table);
        let virtual_size = coff.read_u32::<LittleEndian>().unwrap();
        let virtual_address = coff.read_u32::<LittleEndian>().unwrap();
        let size_of_raw_data = coff.read_u32::<LittleEndian>().unwrap();
        let pointer_to_raw_data = coff.read_u32::<LittleEndian>().unwrap();
        let pointer_to_relocations = coff.read_u32::<LittleEndian>().unwrap();
        // TODO: actually read these values?
        coff.seek(SeekFrom::Current(4)).unwrap();
        // TODO: actually read these values?
        let number_of_relocations = coff.read_u16::<LittleEndian>().unwrap();
        coff.seek(SeekFrom::Current(2)).unwrap();

        let characteristics_position = coff.stream_position().unwrap();

        coff.seek(SeekFrom::Start(u64::from(pointer_to_raw_data))).unwrap();
        let mut raw_data = vec![0; usize::try_from(size_of_raw_data).unwrap()];
        coff.read_exact(&mut raw_data).unwrap();

        coff.seek(SeekFrom::Start(u64::from(pointer_to_relocations))).unwrap();
        let relocations = read_relocations(coff, number_of_relocations);

        coff.seek(SeekFrom::Start(characteristics_position)).unwrap();
        let characteristics = coff.read_u32::<LittleEndian>().unwrap();
        sections.push(Section {
            name,
            virtual_size,
            virtual_address,
            raw_data,
            relocations,
            characteristics,
        });
    }
    sections
}

pub fn create_symbol_for_relocation(name: String) -> SymbolTableRecord {
    SymbolTableRecord::Symbol(Symbol {
        name,
        value: 0,
        section_number: 0,
        symbol_type: 0x0020,
        storage_class: 0x02,
        number_of_aux_symbols: 0,
    })
}

pub fn create_symbol_for_table(name: String, value: u32, section_number: i16, is_function: bool) -> SymbolTableRecord {
    SymbolTableRecord::Symbol(Symbol {
        name,
        value,
        section_number,
        symbol_type: if is_function { 0x0020 } else { 0x0000 },
        storage_class: 0x02,
        number_of_aux_symbols: 0,
    })
}

pub fn write_header<F: WriteBytesExt>(header: Header, destination: &mut F) {
    destination.write_u16::<LittleEndian>(header.machine).unwrap();
    destination.write_u16::<LittleEndian>(header.number_of_sections).unwrap();
    destination.write_u32::<LittleEndian>(header.time_date_stamp).unwrap();
    destination.write_u32::<LittleEndian>(header.pointer_to_symbol_table).unwrap();
    destination.write_u32::<LittleEndian>(header.number_of_symbols).unwrap();
    destination.write_u16::<LittleEndian>(header.size_of_optional_header).unwrap();
    destination.write_u16::<LittleEndian>(header.characteristics).unwrap();
}

pub fn write_sections<F: WriteBytesExt + Seek>(sections: &Vec<Section>, destination: &mut F) {
    let mut current_raw_data_pointer: usize = 0x1000;

    for si in 0..sections.len() {
        let section = &sections[si];

        let name_bytes = section.name[..8].as_bytes();
        assert_eq!(name_bytes.len(), 8);
        destination.write_all(name_bytes).unwrap();
        destination.write_u32::<LittleEndian>(section.virtual_size).unwrap();
        destination.write_u32::<LittleEndian>(section.virtual_address).unwrap();
        destination.write_u32::<LittleEndian>(u32::try_from(section.raw_data.len()).unwrap()).unwrap();
        assert_eq!(section.raw_data.len() % 0x1000, 0);
        destination.write_u32::<LittleEndian>(u32::try_from(current_raw_data_pointer).unwrap()).unwrap();
        current_raw_data_pointer += section.raw_data.len();
        destination.write_u32::<LittleEndian>(0).unwrap();
        // TODO: write the actual value.
        destination.write_u32::<LittleEndian>(0).unwrap();
        destination.write_u16::<LittleEndian>(0).unwrap();
        // TODO: write the actual value.
        destination.write_u16::<LittleEndian>(0).unwrap();
        // TODO: unset COFF flags.
        destination.write_u32::<LittleEndian>(section.characteristics).unwrap();
    }
}

pub struct COFF {
    pub sections: Vec<Section>,
    pub symbols: Vec<SymbolTableRecord>,
}

pub struct Header {
    machine: u16,
    pub number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[derive(Debug)]
pub enum SymbolTableRecord {
    Symbol(Symbol),
    Aux([u8; 18]),
}

#[derive(Debug)]
pub struct Symbol {
    pub name: String,
    pub value: u32,
    pub section_number: i16,
    pub symbol_type: u16,
    pub storage_class: u8,
    number_of_aux_symbols: u8,
}

#[derive(Default)]
pub struct Section {
    name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_data: Vec<u8>,
    pub relocations: Vec<Relocation>,
    pub characteristics: u32,
}

#[derive(Debug)]
pub struct Relocation {
    pub virtual_address: u32,
    pub symbol_table_index: u32,
    pub relocation_type: u16,
}

fn read_symbols<F: ReadBytesExt>(coff: &mut F, number_of_symbols: u32, string_table: &[u8]) -> Vec<SymbolTableRecord> {
    let mut symbols = Vec::with_capacity(usize::try_from(number_of_symbols).unwrap());
    let mut si = 0;
    while si < number_of_symbols {
        let mut name_buf = [0; 8];
        coff.read_exact(&mut name_buf).unwrap();
        let name = if name_buf[..4] != [0, 0, 0, 0] {
            String::from_utf8_lossy(&name_buf).into_owned()
        } else {
            let offset = u32::from_le_bytes(<[u8; 4]>::try_from(&name_buf[4..]).unwrap());
            read_string(string_table, usize::try_from(offset).unwrap())
        };
        let value = coff.read_u32::<LittleEndian>().unwrap();
        let section_number = coff.read_i16::<LittleEndian>().unwrap();
        let symbol_type = coff.read_u16::<LittleEndian>().unwrap();
        let storage_class = coff.read_u8().unwrap();
        let number_of_aux_symbols = coff.read_u8().unwrap();
        symbols.push(SymbolTableRecord::Symbol(Symbol {
            name,
            value,
            section_number,
            symbol_type,
            storage_class,
            number_of_aux_symbols,
        }));

        for _ in 0..number_of_aux_symbols {
            let mut buf = [0; 18];
            coff.read_exact(&mut buf).unwrap();
            symbols.push(SymbolTableRecord::Aux(buf));

            si += 1;
        }
        si += 1;
    }
    symbols
}

fn read_relocations<F: ReadBytesExt>(coff: &mut F, number_of_relocations: u16) -> Vec<Relocation> {
    let mut relocations = Vec::with_capacity(usize::try_from(number_of_relocations).unwrap());
    for _ in 0..number_of_relocations {
        let virtual_address = coff.read_u32::<LittleEndian>().unwrap();
        let symbol_table_index = coff.read_u32::<LittleEndian>().unwrap();
        let relocation_type = coff.read_u16::<LittleEndian>().unwrap();
        relocations.push(Relocation {
            virtual_address,
            symbol_table_index,
            relocation_type,
        })
    }
    relocations
}

fn read_section_name<F: ReadBytesExt>(coff: &mut F, string_table: &[u8]) -> String {
    let mut buffer: [u8; 8] = [0; 8];
    coff.read_exact(&mut buffer).unwrap();
    // Literal "/"
    if buffer[0] == 0x2f {
        let string_table_offset = String::from_utf8_lossy(&buffer[1..]).trim_end_matches("\0").parse::<usize>().unwrap();
        read_string(string_table, string_table_offset)
    } else {
        String::from_utf8_lossy(&buffer).into_owned()
    }
}

fn read_string(string_table: &[u8], offset: usize) -> String {
    let mut buffer = Vec::with_capacity(64);
    for i in offset..string_table.len() {
        let b = string_table[i];
        if b == 0 {
            return String::from_utf8(buffer).unwrap();
        }
        buffer.push(b);
    }
    panic!("reached the end of the string table without encountering a null terminator");
}
