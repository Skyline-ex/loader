#![feature(let_else)]
use std::path::Path;
use nn::ro::{NrrHeader, Module};
use thiserror::Error;
use nnsdk as nn;

macro_rules! align_up {
    ($x:expr, $a:expr) => {
        ((($x) + (($a) - 1)) & !(($a) - 1))
    };
}

#[derive(Error, Debug)]
pub enum LoaderError {
    #[error("{0}")]
    IO(#[from] std::io::Error),

    #[error("Error registering modules: {0:#x}")]
    RegistrationError(u32),

    #[error("Error mounting module: {0:#x}")]
    MountError(u32),

    #[error("Error retrieving buffer size: {0:#x}")]
    InvalidModuleBuffer(u32),
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Sha256Hash([u8; 0x20]);

impl Sha256Hash {
    pub fn new(data: &[u8]) -> Self {
        let mut hash = [0u8; 0x20];
        unsafe {
            nn::crypto::GenerateSha256Hash(hash.as_mut_ptr() as _, 0x20, data.as_ptr() as _, data.len() as u64);
        }
        Self(hash)
    }
}

struct NroFile {
    data: Vec<u8>,
    name: String,
}

impl NroFile {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, LoaderError> {
        let path = path.as_ref();
        std::fs::read(path)
            .map(|data| Self { data, name: path.file_name().unwrap().to_string_lossy().to_string() })
            .map_err(Into::into)
    }

    pub fn fix_bss_size(&mut self) {
        unsafe {
            // Get the mod header offset
            let mod_header_offset = *(self.data.as_ptr().add(4) as *const u32);

            let mod_header = self.data.as_mut_ptr().add(mod_header_offset as usize + 0x18) as *mut u32;

            let bss_end_offset = *mod_header.add(3);
            let module_object_offset = *mod_header.add(7);
            if bss_end_offset == module_object_offset {
                *mod_header.add(3) += 0xD0;
            }
        }
    }

    pub fn hash(&self) -> Sha256Hash {
        Sha256Hash::new(&self.data)
    }

    pub fn mount(self) -> Result<Module, LoaderError> {
        use std::alloc;

        let Self { data, name } = self;

        let layout = alloc::Layout::from_size_align(data.len(), 0x1000).unwrap();
        let image = unsafe {
            let memory = alloc::alloc(layout);
            std::ptr::copy_nonoverlapping(data.as_ptr(), memory, data.len());
            drop(data);
            memory
        };

        let bss_size = unsafe {
            let mut size = 0;
            let rc = nn::ro::GetBufferSize(&mut size, image as _);
            if rc != 0 {
                alloc::dealloc(image, layout);
                return Err(LoaderError::InvalidModuleBuffer(rc));
            }
            size as usize
        };

        let bss_layout = alloc::Layout::from_size_align(bss_size, 0x1000).unwrap();

        let bss_memory = unsafe {
            alloc::alloc(layout)
        };

        unsafe {
            let mut module: Module = std::mem::MaybeUninit::zeroed().assume_init();
            module.Name[0..name.len()].copy_from_slice(name.as_bytes());
            
            let rc = nn::ro::LoadModule(
                &mut module,
                image as _,
                bss_memory as _,
                bss_size as u64,
                nn::ro::BindFlag_BindFlag_Lazy as i32
            );

            if rc != 0 {
                alloc::dealloc(image, layout);
                alloc::dealloc(bss_memory, bss_layout);

                Err(LoaderError::MountError(rc))
            } else {
                Ok(module)
            }
        }
    }
}

pub struct MountInfo {
    pub modules: Vec<Result<nn::ro::Module, LoaderError>>,
    pub registration_info: nn::ro::RegistrationInfo,
}

pub fn mount_from_directory<P: AsRef<Path>, F: Fn(&Path) -> bool>(program_id: u64, path: P, validator: F) -> Result<MountInfo, LoaderError> {
    use std::alloc;
    let mut plugins = Vec::new();
    for entry in std::fs::read_dir(path)? {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        if !validator(&path) { continue };

        plugins.push(NroFile::open(&path).map(|mut nro| { nro.fix_bss_size(); nro }));
    }

    // Handle creating the raw NRR image
    let registration_info = {
        let num_modules = plugins.iter()
            .filter(|plugin| plugin.is_ok())
            .count();

        let image_size = align_up!(
            std::mem::size_of::<nn::ro::NrrHeader>() + num_modules * std::mem::size_of::<Sha256Hash>(),
            0x1000
        );
        

        let (header, shas) = unsafe {
            let layout = alloc::Layout::from_size_align(image_size, 0x1000).unwrap();
            let memory = alloc::alloc_zeroed(layout);
            (
                &mut *(memory as *mut NrrHeader),
                std::slice::from_raw_parts_mut(
                    memory.add(std::mem::size_of::<NrrHeader>()) as *mut Sha256Hash, 
                    num_modules
                )
            )
        };


        header.magic = 0x3052524E;
        header.program_id = nn::ro::ProgramId { value: program_id };
        header.size = image_size as u32;
        header.type_ = 0;
        header.hashes_offset = std::mem::size_of::<NrrHeader>() as u32;
        header.num_hashes = num_modules as u32;

        for (count, file) in plugins.iter().filter(|plugin| plugin.is_ok()).enumerate() {
            shas[count] = file.as_ref().unwrap().hash();
        }

        shas.sort();

        unsafe {
            let mut nrr_info = std::mem::MaybeUninit::uninit();
            let rc = nn::ro::RegisterModuleInfo(nrr_info.as_mut_ptr(), header as *mut NrrHeader as _);
            if rc != 0 {
                let layout = alloc::Layout::from_size_align(image_size, 0x1000).unwrap();
                alloc::dealloc(header as *mut NrrHeader as _, layout);
                return Err(LoaderError::RegistrationError(rc));
            }
            nrr_info.assume_init()
        }
    };

    let modules = plugins
        .into_iter()
        .map(|plugin| plugin.and_then(NroFile::mount))
        .collect();
    

    Ok(MountInfo {
        modules,
        registration_info
    })
}