# LASEC Semester Project: 
## Implementation of state-of-the-art messaging

The Signal protocol is used as the de facto standard in secure messaging. However, over the years, researchers have been trying to propose solutions to make Signal (and messaging protocols in general) even more secure in the presence of complex and powerful adversaries. Among these propositions we can cite:
- Resistance to quantum adversaries (i.e. post-quantum security [1,2]). 
- In-band detection of active attacks (i.e. how the client of the receiver can detect the impersonation of the sender [3]).
- Out-of-band detection of active attacks (i.e. how the receiver can detect the impersonation of the sender out-of-band, for example using QR codes).
These solutions are often only theoretical and therefore their potential impact on the efficiency of real systems is hard to quantify. The goal of the project would be to implement some, or all, of the improvements mentioned above and benchmark them. In a first step, these could be implemented as a stand-alone implementation. Then, if time permits, the system could be integrated directly into the Signal source code.

## Running tests and benchmarks
Unit tests are in RC/src/lib.rs in the ```tests``` module and can be run from the RC directory by calling ```cargo test```.  
Benchmarks for the Ratcheted Communication (RC) API ```Initall, Send``` and ```Receive``` can be run from the RC directory using ```cargo bench```.
