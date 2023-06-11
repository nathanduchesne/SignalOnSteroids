ex. how to use this crate 💻 
```
let (mut alice_state, mut bob_state) = s_rid_rc_init();
let associated_data: [u8; 32] = [0;32]; # The initial value of this is specific to your application
let plaintext_alice = b"Hello I am Alice";

let (_, ct) = s_rid_rc_send(&mut alice_state, &associated_data, plaintext_alice);
let (acc, _, pt) = s_rid_rc_receive(&mut bob_state, &associated_data, ct);
```
to use the encoding/decoding features to use this crate in pratical communication based used-cases, use the send_bytes variants:
```
let associated_data: [u8; 32] = [0; 32];
let plaintext = b"I want to send bytes :p";
let bytes = s_rid_rc_send_bytes(&mut alice_state, &associated_data, plaintext);
let (acc, _, received_plaintext) = s_rid_rc_receive_bytes(&mut bob_state, &associated_data, &bytes);
```

in both cases, if the **acc** flag returns false, this means either a forgery occured or one of the two users is malicious, so communication should be aborted.
