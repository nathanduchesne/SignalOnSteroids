# LASEC Semester Project: 
## Implementation of state-of-the-art messaging

The Signal protocol is used as the de facto standard in secure messaging. However, over the years, researchers have been trying to propose solutions to make Signal (and messaging protocols in general) even more secure in the presence of complex and powerful adversaries. Among these propositions we can cite:
- In-band detection of active attacks (i.e. how the client of the receiver can detect the impersonation of the sender [3]).
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

## Running tests and benchmarks
To run **all the test suites at once**, run ```python execute_tests.py```.

To run tests **of a single crate individually**, navigate to that crate, then run ```cargo test``` -> ex. ```cd rc; cargo test```

To run the benchmarks of a crate, navigate to that crate and run ```cargo bench```.
