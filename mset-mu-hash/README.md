The code in this crate was heavily inspired by https://cronokirby.com/posts/2021/07/on_multi_set_hashing/ 's blog and the associated source code. The source code linked in the repo is under the MIT License,
meaning the mset-mu-hash, based on this paper (📝 : http://people.csail.mit.edu/devadas/pubs/mhashes.pdf) is also under the MIT License. 

The slight changes made to the code were done mainly to account for the breaking backward-compatibility update made by the https://github.com/RustCrypto crate owners. 


ex. how to use this crate 💻
```
let mut hash = RistrettoHash::<Sha512>::default();
hash.add(b"signal", 1);
hash.add(b"whatsapp", 2);

hash.update(b"face");
hash.update(b"book");
hash.end_update();

hash.finalize()
```

where Sha512 can be replaced with any 64 byte digest hash function.
