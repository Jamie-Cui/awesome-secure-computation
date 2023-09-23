# awesome-secure-computation [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

This repo is a paper summary for cryptography-based secure computation papers (I prefer published papers 😛), including topics like [*Multiparty Computation*](https://en.wikipedia.org/wiki/Secure_multi-party_computation), [*Homomorphic Encryption (or Lattice)*](https://en.wikipedia.org/wiki/Homomorphic_encryption) and [*Differential Privacy*](https://en.wikipedia.org/wiki/Differential_privacy). If you are looking for hardware solutions like Trusted Platform Module (TPM), or Trusted Execution Environment (TEE), I'm sorry this repo is not what you're looking for :(.

Here's a good place to ask questions about cryptography/cryptanalysis, or answering one (if you are capable of doing so): [https://crypto.stackexchange.com/](https://crypto.stackexchange.com/), and finding papers [Cryptology ePrint Archive](https://eprint.iacr.org/).

**Useful Links**:

- [Security Conferences Ranking](http://faculty.cs.tamu.edu/guofei/sec_conf_stat.htm) (By Prof. Guofei Gu)
- [Security and Privacy Conference Deadlines](https://sec-deadlines.github.io/)
- [Crypto21: Mentoring Videos about how to do research in cryptography](https://mentor-crypto-2021.github.io/)

**Texbooks**:

- A Pragmatic Introduction to Secure Multi-Party Computation  
  *David Evans, Vladimir Kolesnikov, and Mike Rosulek*  
  [eprint avaliable](https://www.cs.virginia.edu/~evans/pragmaticmpc/pragmaticmpc.pdf) 
- Foundations of Cryptography  
  *Oded Goldreich*  
  [author's notes](https://www.wisdom.weizmann.ac.il/~oded/foc.html)
- Introduction to Modern Cryptography  
  *Jonathan Katz and Yehuda Lindell*  
  [author's notes](http://www.cs.umd.edu/~jkatz/imc.html)

**Open-source Tools (mostly in C++)**:
- [[secretflow/yacl]](https://github.com/secretflow/yacl): OT, OPRF (🤠 I participant in the develop of yacl, so don't hesitate to contact me if you have any questions or suggestions)
- [[emp-toolkit]](https://github.com/emp-toolkit): OT, ZKP, MPC
- [[libOTe]](https://github.com/osu-crypto/libOTe): OT, VOLE
- [[libPSI]](https://github.com/osu-crypto/libPSI): PSI
- [[MP-SPDZ]](https://github.com/mc2-project/MP-SPDZ): Generic MPC

## Table of Papers

- [MPC](mpc.md)
  * [Summaries and Talks](mpc.md/#summaries-and-talks)
  * [OT](#ot)
  * [OLE/vOLE](#vole)
  * [OPRF and PSI](#oprf-and-psi)
  * [PIR](#pir)
  * [PFE](#pfe)
  * [FSS](#fss)
  * [Semi-honest MPC](#semi-honest-mpc)
  * [Malicious MPC](#malicious-mpc)
- [Lattice](#lattice)
  * [Summaries and Talks](#summaries-and-talks-1)
  * [HE](#he)
- [ZKP](zkp.md)
