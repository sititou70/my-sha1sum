mod sha1;

use clap::{App, Arg};
use sha1::*;
use std::env;
use std::fs::File;
use std::io::{stdin, BufReader};
use std::process;

fn main() {
    let matches = App::new("my-sha1sum")
        .version("0.1.0")
        .author("sititou70 <sititou70@gmail.com>")
        .about("Calculate sha1 sum of stdin or files.")
        .usage("./sha1sum input1.txt input2.bin...")
        .arg(
            Arg::with_name("files")
                .multiple(true)
                .help("the input files"),
        )
        .get_matches();

    if env::args().len() == 1 {
        let stdin = stdin();
        printHash(sha1(Box::new(stdin)));
        println!("  -");
        process::exit(0);
    }

    let file_names = matches.values_of("files");
    for file_name in file_names.unwrap_or_default() {
        let file = match File::open(file_name) {
            Ok(f) => f,
            Err(e) => {
                println!("file read error: {}", e);
                continue;
            }
        };

        if !file.metadata().unwrap().is_file() {
            println!("this is not a file: {}", file_name);
            continue;
        }

        printHash(sha1(Box::new(BufReader::new(file))));
        println!("  {}", file_name);
    }
}
