A Rust implementation of the Signal double ratchet algorithm: 🔗 https://signal.org/docs/specifications/doubleratchet/.
While the original ratchet communication scheme exposes the ```ratchet_encrypt()``` and ```ratchet_decrypt()``` functions, the RC scheme in the paper this project is based on exposes another API, namely send() and receive().
The ```send()``` and ```receive()``` functions can be used as follows:

```
let (alice_state, bob_state) = init_all();
let associated_data: [u8; 32] = [10; 32];
let plaintext = b"Hola mi amigo!";

let (ord, header, ciphertext) = send(&mut alice_state, &associated_data, plaintext);
let (acc, ord, plaintext_received) = receive(&mut bob_state, &associated_data, header, ciphertext);
```

if acc is false, this means an error occured in the protocol, and it should therefore be aborted ❌.
