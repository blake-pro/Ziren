fn main() {
    println!("cargo:rustc-link-search=native=./lib");
    println!("cargo:rustc-link-lib=static=example");
    zkm2_build::build_program("../program");
}
