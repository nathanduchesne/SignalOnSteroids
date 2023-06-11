This crate implements the baseline RRC scheme found in “On Active Attack Detection in Messaging with Immediate Decryption”, Khashayar Barooti, Daniel Collins, Simone Colombo, Loïs Huguenin-Dumittan, and Serge Vaudenay. 
It can be used in the following manner:
```
let (mut alice_state, mut bob_state) = rrc_init_all(Security::RRidAndSRid);
let associated_data = [0u8;32];
let plaintext = b"Wassup my dude?";
let (_, mut ciphertext, header) = rrc_send(&mut alice_state, &associated_data, plaintext);
let (acc, _, decrypted_plaintext) = rrc_receive(&mut bob_state, &associated_data, &mut ciphertext, header);
assert_eq!(acc, true);
assert_eq!(plaintext.to_vec(), decrypted_plaintext);
```

Additionally, for practical reasons and real-world use cases, the crate provides functions which serialize and deserialize the send/receive objects to bytes.
```
let (mut alice_state, mut bob_state) = rrc_init_all(Security::RRidAndSRid);
let associated_data = [0u8;32];
let plaintext = b"Wassup my dude?";
let bytes = send_bytes(&mut alice_state, &associated_data, plaintext);
let (acc, _, decrypted_plaintext) = receive_bytes(&bytes, &mut bob_state, &associated_data);
assert_eq!(acc, true);
assert_eq!(plaintext.to_vec(), decrypted_plaintext);
```
