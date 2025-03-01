mod crypto;

use std::{fs, io, os::unix::fs::PermissionsExt, path::PathBuf, sync::Mutex, process::exit};
use lazy_static::lazy_static;
use serde::Serialize;
use rpassword::prompt_password;
use clap::Parser;
use rand::Rng;

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

        let mut contents: String = String::from("");

        //prompt the user for master key
        match prompt_password("Enter master key\n") {
            Ok(pass) => {
                *mut_master_key = String::from(pass);

                let mut hashed_key: String = String::new();

                let mut rng = rand::rng();
                let salt_size: u64 = rng.random::<u64>();

                let salt = crypto::gen_salt(salt_size);

                crypto::hash_password::<sha2::Sha256>(&(*mut_master_key), salt.as_str(), &mut hashed_key);
                
                contents = "master-key:".to_string() + &hashed_key;

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
                Ok(()) => println!("INFO: Initialization, master_key: {:?}", *master_key),
                Err(e) => eprintln!("ERROR: {}", e),
            }
        },
        "add" => println!("Action used is: init"),
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
