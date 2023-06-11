# LASEC Semester Project: 
## Implementation of state-of-the-art messaging

The Signal protocol is used as the de facto standard in secure messaging. However, over the years, researchers have been trying to propose solutions to make Signal (and messaging protocols in general) even more secure in the presence of complex and powerful adversaries. Among these propositions we can cite:
- In-band detection of active attacks (i.e. how the client of the receiver can detect the impersonation of the sender).
- Out-of-band detection of active attacks (i.e. how the receiver can detect the impersonation of the sender out-of-band, for example using QR codes).
These solutions are often only theoretical and therefore their potential impact on the efficiency of real systems is hard to quantify. The goal of the project is to implement the improvements mentioned above and benchmark them.

## Repository structure
<pre>
├── mset-mu-hash _______________
├── rc                         |
├── rrc                        --\
├── s-rid-rc                   --/ Crates containing all the project implementations and optimizations.
├── unf-arc-based-on-rc        |
├── unf-arc-based-on-rrc ______|
├── execute_tests.py           --> Script used to run all project tests in one command.

</pre>

## Installation
To run the project, start by installing Rust on your computer.  
```curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh```  
as indicated on the Rust webpage https://www.rust-lang.org/tools/install.

## Testing the installation
To verify that Rust is up and running on your machine, you can try building one of the project crates by navigating to one of the crate directories---e.g rc, rrc, mset-mu-hash, s-rid-rc, unf-arc-based-on-rrc, unf-arc-based-on-rc--- and run 
```cargo build```. This should build the cargo crate you are currently in.

## Executing the programs
Since most of the code is contained in the form of crates---or libraries---, it does not have an entry point such as a main function or program. To execute code from a given crate, you must run the following.

```cargo new <name_of_test_file>```

This will create a folder containing a src/main.rs file, and a ```Cargo.toml``` file.
In the ```Cargo.toml``` file, under ```[dependencies]```, add ```<crate_name> = { path = "<path_to_crate_directory>" }```
ex. ```rc = {path = "../rc"}```.

Once you have added this, you can use the crate's API---which can be found in the crate's lib.rs file---to write your own program. Example programs can be found in the **README.md** file which is present in every crate. When using a library function in your main program, "import" it at the top of the main file, using:
```use <crate_name>::{api_fct_1, api_fct_2, ...};```

## Running tests and benchmarks
To run **all the test suites at once**, run ```python execute_tests.py```.

To run tests **of a single crate individually**, navigate to that crate, then run ```cargo test``` -> ex. ```cd rc; cargo test```

To run the benchmarks of a crate, navigate to that crate and run ```cargo bench```.
