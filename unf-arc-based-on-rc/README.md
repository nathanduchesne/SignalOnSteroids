Here is a code example to use this library 💻:

```
let (mut alice_state, mut bob_state) = arc_init(); 👩🏻🧑🏾‍🦱
let associated_data: [u8; 32] = [123; 32]; 📟
let alice_pt = b"Hello I am Alice"; 👩🏻🗣
let (_, header, ct) = arc_send(&mut alice_state, &associated_data, &alice_pt); 👩🏻 -> 🧑🏾‍🦱
arc_receive(&mut bob_state, &associated_data, header, &mut ct); 🧑🏾‍🦱
... (they chat for a while and finally meet in person) 👩🏻💬🧑🏾‍🦱
// Alice send an authentication tag to check for forgeries
let mut at = arc_auth_send(&mut alice_state); 👩🏻❓ 
arc_auth_receive(&mut bob_state, at); 🧑🏾✅
// Bob sends an authentication tag to check for forgeries
let mut at = arc_auth_send(&mut bob_state); 🧑🏾‍🦱❓
arc_auth_receive(&mut alice_state, at);👩🏻✅
```
If the acceptance bit returned by the arc_auth_receive() is false, it means a forgery occured or one of the 2 users is malicious.
