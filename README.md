# El Gamal in Julia
A simple implementation of the El Gamal encryption system in the Julia language.

Originally written for the students at the University of California, Santa Cruz.

```
@article{elgamal1985public,
  title={A public key cryptosystem and a signature scheme based on discrete logarithms},
  author={ElGamal, Taher},
  journal={IEEE transactions on information theory},
  volume={31},
  number={4},
  pages={469--472},
  year={1985},
  publisher={IEEE}
}
```

The implementation has the ability to use *safe primes* for creating
the keys. This can be a little slow, but you do not need to do this more
than once.

```
@misc{cryptoeprint:2001:007,
    author       = {Ronald Rivest and Robert Silverman},
    title        = {Are 'Strong' Primes Needed for {RSA}?},
    howpublished = {Cryptology ePrint Archive, Report 2001/007},
    year         = {2001},
    note         = {\url{https://ia.cr/2001/007}},
}

```
# Usage

```
(prv, pub) = keys(safety, bits)

c = encrypt(encode("string"), pub)

m = decode(decrypt(c, prv)
```

Running it on the command line executes interactively to encrypt and decrypt strings.

```
dmz :: ~/El-Gamal-in-Julia » ./elgamal.jl
How many bits? 128
pub = (572927111265326666004563340005006575427, 65537, 106689413353486727133802126941609549788)
prv = (572927111265326666004563340005006575427, 572881428683612937908443576094045369689)
>> Hi Buckaroos!
En[Hi Buckaroos!] = (319834251681942755631187036386350456050, 516191262128696593557688409582791082418)
De[(319834251681942755631187036386350456050, 516191262128696593557688409582791082418)] = Hi Buckaroos!
>> ^D
```
