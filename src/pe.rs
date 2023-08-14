use std::io::{Write, Seek, SeekFrom};

use byteorder::{ReadBytesExt, WriteBytesExt, LittleEndian};

use super::coff::{read_sections, Section};

const PE_SIGNATURE_OFFSET: u64 = 0x3c;

pub fn read_image<F: ReadBytesExt + Seek>(mut pe: F) -> Image {
    pe.seek(SeekFrom::Start(PE_SIGNATURE_OFFSET)).unwrap();
    let pe_signature_position = pe.read_u32::<LittleEndian>().unwrap();
    pe.seek(SeekFrom::Start(0)).unwrap();
    let mut stub = vec![0; usize::try_from(pe_signature_position).unwrap()];
    pe.read_exact(&mut stub).unwrap();

    let pe_signature = pe.read_u32::<LittleEndian>().unwrap();
    assert_eq!(pe_signature, 0x00004550);
    let coff_header = super::coff::read_header(&mut pe);
    let optional_header = read_optional_header(&mut pe);
    let data_directories = read_data_directories(&mut pe, optional_header.number_of_rva_and_sizes);
    let sections = read_sections(&mut pe, coff_header.number_of_sections, &[]);

    Image {
        stub,
        pe_signature,
        coff_header,
        optional_header,
        data_directories,
        sections,
    }
}

pub fn write_image<F: WriteBytesExt + Seek>(image: Image, destination: &mut F) {
    destination.write_all(&image.stub).unwrap();
    destination.write_u32::<LittleEndian>(image.pe_signature).unwrap();
    super::coff::write_header(image.coff_header, destination);
    write_optional_header(image.optional_header, destination);
    write_data_directories(image.data_directories, destination);
    super::coff::write_sections(&image.sections, destination);
    let position = destination.stream_position().unwrap();
    let padding = vec![0; 0x1000 - usize::try_from(position).unwrap()];
    destination.write_all(&padding).unwrap();
    for section in image.sections {
        destination.write_all(&section.raw_data).unwrap();
    }
}

pub struct Image {
    stub: Vec<u8>,
    pe_signature: u32,
    pub coff_header: super::coff::Header,
    pub optional_header: OptionalHeader,
    data_directories: Vec<DataDirectory>,
    pub sections: Vec<Section>,
}

pub struct OptionalHeader {
    magic: u16,
    major_linker_version: u8,
    minor_linker_veresion: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    base_of_data: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    pub size_of_image: u32,
    size_of_headers: u32,
    check_sum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u32,
    size_of_stack_commit: u32,
    size_of_heap_reserve: u32,
    size_of_heap_commit: u32,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
}

struct DataDirectory {
    virtual_address: u32,
    size: u32,
}

fn read_optional_header<F: ReadBytesExt>(pe: &mut F) -> OptionalHeader {
    let magic = pe.read_u16::<LittleEndian>().unwrap();
    assert_eq!(magic, 0x010b);
    let major_linker_version = pe.read_u8().unwrap();
    let minor_linker_veresion = pe.read_u8().unwrap();
    let size_of_code = pe.read_u32::<LittleEndian>().unwrap();
    let size_of_initialized_data = pe.read_u32::<LittleEndian>().unwrap();
    let size_of_uninitialized_data = pe.read_u32::<LittleEndian>().unwrap();
    let address_of_entry_point = pe.read_u32::<LittleEndian>().unwrap();
    let base_of_code = pe.read_u32::<LittleEndian>().unwrap();
    let base_of_data = pe.read_u32::<LittleEndian>().unwrap();
    let image_base = pe.read_u32::<LittleEndian>().unwrap();
    let section_alignment = pe.read_u32::<LittleEndian>().unwrap();
    let file_alignment = pe.read_u32::<LittleEndian>().unwrap();
    let major_operating_system_version = pe.read_u16::<LittleEndian>().unwrap();
    let minor_operating_system_version = pe.read_u16::<LittleEndian>().unwrap();
    let major_image_version = pe.read_u16::<LittleEndian>().unwrap();
    let minor_image_version = pe.read_u16::<LittleEndian>().unwrap();
    let major_subsystem_version = pe.read_u16::<LittleEndian>().unwrap();
    let minor_subsystem_version = pe.read_u16::<LittleEndian>().unwrap();
    let win32_version_value = pe.read_u32::<LittleEndian>().unwrap();
    let size_of_image = pe.read_u32::<LittleEndian>().unwrap();
    let size_of_headers = pe.read_u32::<LittleEndian>().unwrap();
    let check_sum = pe.read_u32::<LittleEndian>().unwrap();
    let subsystem = pe.read_u16::<LittleEndian>().unwrap();
    let dll_characteristics = pe.read_u16::<LittleEndian>().unwrap();
    let size_of_stack_reserve = pe.read_u32::<LittleEndian>().unwrap();
    let size_of_stack_commit = pe.read_u32::<LittleEndian>().unwrap();
    let size_of_heap_reserve = pe.read_u32::<LittleEndian>().unwrap();
    let size_of_heap_commit = pe.read_u32::<LittleEndian>().unwrap();
    let loader_flags = pe.read_u32::<LittleEndian>().unwrap();
    let number_of_rva_and_sizes = pe.read_u32::<LittleEndian>().unwrap();

    OptionalHeader {
        magic,
        major_linker_version,
        minor_linker_veresion,
        size_of_code,
        size_of_initialized_data,
        size_of_uninitialized_data,
        address_of_entry_point,
        base_of_code,
        base_of_data,
        image_base,
        section_alignment,
        file_alignment,
        major_operating_system_version,
        minor_operating_system_version,
        major_image_version,
        minor_image_version,
        major_subsystem_version,
        minor_subsystem_version,
        win32_version_value,
        size_of_image,
        size_of_headers,
        check_sum,
        subsystem,
        dll_characteristics,
        size_of_stack_reserve,
        size_of_stack_commit,
        size_of_heap_reserve,
        size_of_heap_commit,
        loader_flags,
        number_of_rva_and_sizes,
    }
}

fn write_optional_header<F: WriteBytesExt>(header: OptionalHeader, destination: &mut F) {
    destination.write_u16::<LittleEndian>(header.magic).unwrap();
    destination.write_u8(header.major_linker_version).unwrap();
    destination.write_u8(header.minor_linker_veresion).unwrap();
    destination.write_u32::<LittleEndian>(header.size_of_code).unwrap();
    destination.write_u32::<LittleEndian>(header.size_of_initialized_data).unwrap();
    destination.write_u32::<LittleEndian>(header.size_of_uninitialized_data).unwrap();
    destination.write_u32::<LittleEndian>(header.address_of_entry_point).unwrap();
    destination.write_u32::<LittleEndian>(header.base_of_code).unwrap();
    destination.write_u32::<LittleEndian>(header.base_of_data).unwrap();
    destination.write_u32::<LittleEndian>(header.image_base).unwrap();
    destination.write_u32::<LittleEndian>(header.section_alignment).unwrap();
    destination.write_u32::<LittleEndian>(header.file_alignment).unwrap();
    destination.write_u16::<LittleEndian>(header.major_operating_system_version).unwrap();
    destination.write_u16::<LittleEndian>(header.minor_operating_system_version).unwrap();
    destination.write_u16::<LittleEndian>(header.major_image_version).unwrap();
    destination.write_u16::<LittleEndian>(header.minor_image_version).unwrap();
    destination.write_u16::<LittleEndian>(header.major_subsystem_version).unwrap();
    destination.write_u16::<LittleEndian>(header.minor_subsystem_version).unwrap();
    destination.write_u32::<LittleEndian>(header.win32_version_value).unwrap();
    destination.write_u32::<LittleEndian>(header.size_of_image).unwrap();
    destination.write_u32::<LittleEndian>(header.size_of_headers).unwrap();
    destination.write_u32::<LittleEndian>(header.check_sum).unwrap();
    destination.write_u16::<LittleEndian>(header.subsystem).unwrap();
    destination.write_u16::<LittleEndian>(header.dll_characteristics).unwrap();
    destination.write_u32::<LittleEndian>(header.size_of_stack_reserve).unwrap();
    destination.write_u32::<LittleEndian>(header.size_of_stack_commit).unwrap();
    destination.write_u32::<LittleEndian>(header.size_of_heap_reserve).unwrap();
    destination.write_u32::<LittleEndian>(header.size_of_heap_commit).unwrap();
    destination.write_u32::<LittleEndian>(header.loader_flags).unwrap();
    destination.write_u32::<LittleEndian>(header.number_of_rva_and_sizes).unwrap();
}

fn read_data_directories<F: ReadBytesExt>(mut pe: F, number_of_rva_and_sizes: u32) -> Vec<DataDirectory> {
    let mut data_directories = Vec::with_capacity(usize::try_from(number_of_rva_and_sizes).unwrap());
    for _ in 0..number_of_rva_and_sizes {
        let virtual_address = pe.read_u32::<LittleEndian>().unwrap();
        let size = pe.read_u32::<LittleEndian>().unwrap();
        data_directories.push(DataDirectory {virtual_address, size});
    }
    data_directories
}

fn write_data_directories<F: WriteBytesExt>(directories: Vec<DataDirectory>, destination: &mut F) {
    for directory in directories {
        destination.write_u32::<LittleEndian>(directory.virtual_address).unwrap();
        destination.write_u32::<LittleEndian>(directory.size).unwrap();
    }
}
