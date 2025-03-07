mod crypto;

use std::{fmt, fs::{self, OpenOptions}, io::{self, Write}, os::unix::fs::PermissionsExt, path::PathBuf, sync::Mutex};
use crate::crypto::{hash_password, gen_salt};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use serde_json;
use rpassword::prompt_password;
use clap::Parser;
use rand::Rng;
use base64::{Engine as _, engine::general_purpose};

lazy_static! {
    pub static ref master_key: Mutex<String> = Mutex::new(String::from(""));
}

#[derive(Debug, Serialize, Deserialize)]
struct ClaspEntries {
    service: String,
    password: String,
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
        let mut entry = ClaspEntries {service: "".to_string(), password: "".to_string()};  
        let mut not_found = false;

        match service {
            Some(service) => {
                entry.service = service; 
            },
            None => not_found = true,
        }

        match password {
            Some(password) => {
                //hash the password and store it in the json file
                let mut rng = rand::rng();
                let salt_size: u64 = rng.random_range(5..=9);

                let salt = gen_salt(salt_size);
                println!("salt: {}", salt);

                let hashed_pass = hash_password(&(password.to_string()), salt.as_str());

                let b64_hash_pass = general_purpose::STANDARD.encode(hashed_pass);
                entry.password = b64_hash_pass; 
            },
            None => not_found = true,
        }

        if not_found {
            eprintln!("ERROR:  Service or Password Not found.\nUSAGE: \n")
        }

        //allow the file write to append
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open("./storage/creds.json")
            .expect("ERROR: Failed to create or open a file\n");

        //store entry into a json file with password hashed
        let json_data = serde_json::to_string_pretty(&entry).expect("ERROR: Failed to convert struct to string");
        //store the entry in a file 
        
        file.write_all(json_data.as_bytes())?;
        let _ = file.write_all(b"\n")?;
    
        //println!("service: {}, password: {}", entry.service, entry.password);
        Ok(())
    }
    
    fn remove(service: Option<String>) -> io::Result<()>{
        Ok(())
    }
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
        "remove" => {
            match ClaspOptions::remove(args.service) {
                Ok(()) => println!("INFO: Service removed succesfully"),
                Err(e) => eprintln!("ERROR: Error removing a service\n{}", e),
            }
        },
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
