mod crypto;

use std::{fs, io, os::unix::fs::PermissionsExt, path::PathBuf, sync::Mutex};
use crate::crypto::{hash_password, gen_salt};
use lazy_static::lazy_static;
use serde::Serialize;
use rpassword::prompt_password;
use clap::Parser;
use rand::Rng;
use base64::{Engine as _, engine::general_purpose};

lazy_static! {
    pub static ref master_key: Mutex<String> = Mutex::new(String::from(""));
}

#[derive(Debug, Parser)]
struct ClaspOptions {
    action: String,
    service: Option<String>,
    password: Option<String>,
}

impl ClaspOptions {
    //initialze clasp by creating master key
    fn init() -> io::Result<()> {
        //prompt the user for a master key
        let mut mut_master_key = master_key.lock().unwrap();
        
        let file_path: std::path::PathBuf = PathBuf::from("./storage/master_key.txt");
        let _ = fs::File::create(&file_path);

        let file_metadata = file_path.metadata().expect("ERROR: File not found");
        let mut file_permissions = file_metadata.permissions();

        file_permissions.set_mode(0o600);
        fs::set_permissions(&file_path, file_permissions.clone()).unwrap();

        let mut contents = Vec::new();

        //prompt the user for master key
        match prompt_password("Enter master key\n") {
            Ok(pass) => {
                *mut_master_key = pass.clone();

                let mut rng = rand::rng();
                let salt_size: u64 = rng.random_range(5..=9);

                let salt = gen_salt(salt_size);
                println!("salt: {}", salt);

                let hashed_key = hash_password(&(*mut_master_key), salt.as_str());

                let b64_hash_key = general_purpose::STANDARD.encode(hashed_key);
                
                contents.extend_from_slice("master_key:".as_bytes());
                contents.extend_from_slice(b64_hash_key.as_bytes());

                //writing the master key into the file
                let _ = fs::write(&file_path, contents);

                //change the permissions to only read
                file_permissions.set_mode(0o400);
                fs::set_permissions(&file_path, file_permissions.clone()).unwrap();
            },
            Err(e) => eprintln!("ERROR: {}", e),
        }

        //write the master key to a file
        return Ok(());
    }

    fn add(service: Option<String>, password: Option<String>) -> io::Result<()> {
        todo!();
    }
}

#[derive(Debug, Serialize)]
struct ClaspEntries {
    service: String,
    password: String,
}

fn main() {
    let args = ClaspOptions::parse();
    match args.action.as_str() {
        "init" => {
            let res: io::Result<()> = ClaspOptions::init();
            match res {
                Ok(()) => println!("INFO: Initialization Complete"),
                Err(e) => eprintln!("ERROR: {}", e),
            }
        },
        "add" =>  {
            match ClaspOptions::add(args.service, args.password) {
                Ok(()) => println!("INFO: Added a new Entry"),
                Err(e) => eprintln!("ERROR: Error adding a new entry\n{}", e),
            } 
        }       
        "remove" => println!("Action used is: init"),
        "modify" => println!("Action used is: init"),
        "list" => println!("Action used is: init"),
        "show" => println!("Action used is: init"),
        "output" => println!("Action used is: init"),
        "help" => {
            println!("master key is: {:?}", *master_key);
            println!("Action used is: init");
        },
        "gen" => !todo!(),
        _ => eprintln!("INFO: invalid action/option. Do clasp help"),
    }
}
