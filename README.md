# awesome-secure-computation [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

This repo is a paper summary for cryptography-based secure computation, including topics like [*Multiparty Computation*](https://en.wikipedia.org/wiki/Secure_multi-party_computation), [*Homomorphic Encryption (or Lattice)*](https://en.wikipedia.org/wiki/Homomorphic_encryption) and [*Differential Privacy*](https://en.wikipedia.org/wiki/Differential_privacy). If you are looking for hardware solutions like Trusted Platform Module (TPM), or Trusted Execution Environment (TEE), I'm sorry this repo is not what you're looking for :(.

Here's a good place to ask questions about cryptography/cryptanalysis, or answering one (if you are capable of doing so): [https://crypto.stackexchange.com/](https://crypto.stackexchange.com/), and finding papers [Cryptology ePrint Archive](https://eprint.iacr.org/).

**Useful Links**:

- [Security Conferences Ranking](http://faculty.cs.tamu.edu/guofei/sec_conf_stat.htm)
- [Security and Privacy Conference Deadlines](https://sec-deadlines.github.io/)



## 1. Secure Computation

**Summaries and Talks**

- 10th BIU Winter School: information-theoretic cryptography, 2020, [link](https://cyber.biu.ac.il/event/the-10th-biu-winter-school-on-cryptography/)
- 9th BIU Winter School: information-theoretic cryptography: zero-knowledge proofs, 2019
- SoK: General purpose compilers for secure multi-party computation, 2019, [Github](https://github.com/MPC-SoK/frameworks), [Paper](https://ieeexplore.ieee.org/abstract/document/8835312)
- Crypto Innovation School 2018, [link](https://crypto.sjtu.edu.cn/cis2018/)



**Oblivious Transfer (OT)**

- Efficient Two-Round OT Extension and Silent Non-Interactive Secure Computation, 2019, [BCGI19+](https://eprint.iacr.org/2019/1159)
- Endemic Oblivious Transfer, 2019, [MR19](https://eprint.iacr.org/2019/706)
- Efficient Two-Round OT Extension and Silent Non-Interactive Secure Computation, 2019, [BCGIKRS19](https://eprint.iacr.org/2019/1159)
- Efficient Pseudorandom Correlation Generators: Silent OT Extension and More, 2019, [BCGIKRS19](https://eprint.iacr.org/2019/448)
- Actively Secure 1-out-of-N OT Extension with Application to Private Set Intersection, 2017, [OOS17](https://eprint.iacr.org/2016/933)
- Improved Private Set Intersection against Malicious Adversaries, 2016, [RR16](https://eprint.iacr.org/2016/746)
- Efficient Batched Oblivious PRF with Applications to Private Set Intersection, 2016, [KKRT16](https://eprint.iacr.org/2016/799)
- Actively Secure OT Extension with Optimal Overhead, 2015, [KOS15](https://eprint.iacr.org/2015/546)
- High Performance Multi-Party Computation for Binary Circuits Based on Oblivious Transfer, 2015, [BLNNOOSS15](https://eprint.iacr.org/2015/472)
- The Simplest Protocol for Oblivious Transfer, 2015, [CO15](https://eprint.iacr.org/2015/267)
- More Efficient Oblivious Transfer and Extensions for Faster Secure Computation, 2015, [ALSZ15](https://eprint.iacr.org/2013/552)
- Extending Oblivious Transfers Efficiently, 2003, [IKNP03](https://www.iacr.org/archive/crypto2003/27290145/27290145.pdf)



**Private Set Intersection (PSI)**

- Circuit-PSI with Linear Complexity via Relaxed Batch OPPRF, 2021, [CGS21](https://eprint.iacr.org/2021/034)
- VOLE-PSI : Fast OPRF and Circuit-PSI from Vector-OLE, 2021, [RS21](https://eprint.iacr.org/2021/266)
- Private Set Operations from Oblivious Switching, 2021, [GMRS21](https://eprint.iacr.org/2021/243)
- Private Matching for Compute, 2020, [BKMSTV20](https://eprint.iacr.org/2020/599)
- SpOT-Light: Lightweight Private Set Intersection from Sparse OT Extension, 2019, [SPOT-OT](https://eprint.iacr.org/2019/634)
- Private Set Intersection in the Internet Setting From Lightweight Oblivious PRF, 2020, [CM20](https://eprint.iacr.org/2020/729)
- PIR-PSI: Scaling Private Contact Discovery, 2018, [DRRT18](https://eprint.iacr.org/2018/579)
- Malicious-Secure private set intersection via dual execution, 2017, [RR17](https://eprint.iacr.org/2017/769)
- Improved private set intersection against malicious adversaries, 2016, [RR16](https://eprint.iacr.org/2016/746)
- Efficient batched oblivious PRF with applications to private set intersection, 2016, [KKRT16](https://eprint.iacr.org/2016/799)
- Phasing : Private Set Intersection using Permutation-based Hashing, 2015,[PSSZ15](https://eprint.iacr.org/2015/634)
- Private set intersection: Are garbled circuits better than custom protocols, 2012, [HEK12](https://www.cs.umd.edu/~jkatz/papers/psi.pdf)
- Linear-complexity private set intersection protocols secure in malicious model, 2010, [CKT10](https://eprint.iacr.org/2010/469)



**Private Information Retrieval (PIR) (Single-Server)**

- Batched Differentially Private Information Retrieval, 2020, [eprint](https://eprint.iacr.org/2020/1596.pdf)
- Random-index PIR with Applications to Large-Scale Secure MPC, 2020, [eprint](https://eprint.iacr.org/2020/1248)
- Private Information Retrieval with Sublinear Online Time, 2020, [eprint](https://eprint.iacr.org/2019/1075)
- Communication Computation Trade-offs in PIR, 2019, [eprint](https://eprint.iacr.org/2019/1483)
- PIR with compressed queries and amortized query processing, 2018, [eprint](https://eprint.iacr.org/2017/1142)
- Private Stateful Information Retrieval, 2018, [eprint](https://eprint.iacr.org/2018/1083)
- Can We Access a Database Both Locally and Privately? 2017, [eprint](https://eprint.iacr.org/2017/567)
- Towards Doubly Efficient Private Information Retrieval, 2017, [eprint](https://eprint.iacr.org/2017/568)
- XPIR : Private Information Retrieval for Everyone, 2016, [eprint](https://eprint.iacr.org/2014/1025)
- Optimal Rate Private Information Retrieval from Homomorphic Encryption, 2015, [eprint](https://petsymposium.org/2015/papers/23_Kiayias.pdf)
- First CPIR Protocol with Data-Dependent Computation, 2009, [eprint](https://dl.acm.org/doi/10.5555/1883749.1883769)
- An Oblivious Transfer Protocol with Log-Squared Communication, 2005, [eprint](https://eprint.iacr.org/2004/063)
- Single-database private information retrieval with constant communication rate, 2005, [eprint](https://www.cs.umd.edu/~gasarch/TOPICS/pir/logn.pdf)
- A new efficient all-or-nothing disclosure of secrets protocol, 1998
- Replication is NOT needed: SINGLE database, computationally- private information retrieval, 1997, [KO97](https://web.cs.ucla.edu/~rafail/PUBLIC/34.pdf)



**Private Function Evaluation (PFE) (General)**

- Linear-Complexity Private Function Evaluation is Practical, 2020, [eprint](https://eprint.iacr.org/2020/853)
- An Efficient 2-Party Private Function Evaluation Protocol Based on Half Gates, 2019, [eprint](https://eprint.iacr.org/2017/415)
- Highly Efficient and Reusable Private Function Evaluation with Linear Complexity, 2018, [eprint](https://eprint.iacr.org/2018/515)
- Private Function Evaluation for MPC, 2015, [eprint](https://eprint.iacr.org/2013/137)
- Actively Secure Private Function Evaluation, 2014, [eprint](https://eprint.iacr.org/2014/102)
- How to Hide Circuits in MPC: An Efficient Framework for Private Function Evaluation, 2013, [eprint](https://eprint.iacr.org/2013/137)
- Private set intersection: Are garbled circuits better than custom protocols, 2012, [eprint](https://www.cs.umd.edu/~jkatz/papers/psi.pdf)
- Constant-round private function evaluation with linear complexity, 2011, [eprint](https://eprint.iacr.org/2010/528)
- Bureaucratic protocols for secure two-party sorting, selection, and permuting, 2010, [eprint](https://dl.acm.org/doi/10.1145/1755688.1755716)
- Selective private function evaluation with applications to private statistics, 2001, [eprint](https://dl.acm.org/doi/10.1145/383962.384047)





**Function Secret Sharing (FSS)**

- Function Secret Sharing for PSI-CA : With Applications to Private Contact Tracing, 2021, [DILO+21](https://eprint.iacr.org/2020/1599)
- Correlated Pseudorandom Functions from Variable-Density LPN, 2020, [BCG+20a](https://eprint.iacr.org/2020/1417)
- Function Secret Sharing for Mixed-Mode and Fixed-Point Secure Computation, 2020, [BCG+20b](https://eprint.iacr.org/2020/1392)
- Secure Computation with Preprocessing via Function Secret Sharing, 2019, [BGI19](https://eprint.iacr.org/2019/1095)
- Efficient Two-Round OT Extension and Silent Non-Interactive Secure Computation, 2019, [BCG+19](https://eprint.iacr.org/2019/1159)
- Distributed vector-ole: Improved constructions and implementation, 2019, [SGRR19](https://eprint.iacr.org/2019/1084)
- Compressing vector OLE, 2018, [BCGI18](https://eprint.iacr.org/2019/273)
- Function Secret Sharing, 2016, [BGI16a](https://www.iacr.org/archive/eurocrypt2015/90560300/90560300.pdf)
- Function secret sharing: Improvements and extensions, 2016, [BGI16b](https://eprint.iacr.org/2018/707)
- Distributed point functions and their applications, 2014, [GI19](https://www.iacr.org/archive/eurocrypt2014/84410245/84410245.pdf)







**Semi-honest Generic Protocols**

- The Round Complexity of Secure Protocols, 1990, [BMR90](http://web.cs.ucdavis.edu/~rogaway/papers/bmr90)
- Completeness Theorems for Non-Cryptographic Fault Tolerant Distributed Computation, 1988, [BGW88](https://dl.acm.org/doi/10.1145/62212.62213)
- How to play any mental game? 1987, [GMW87](https://dl.acm.org/doi/10.1145/28395.28420)
- How to generate and exchange secrets? 1986, [Yao86](https://ieeexplore.ieee.org/document/4568207)



**Malicious Generic Protocols**

- New Primitives for Actively-Secure MPC over Rings with Applications to Private Machine Learning, 2019, [DEF19](https://eprint.iacr.org/2019/599)
- Using TopGear in Overdrive: A more efficient ZKPoK for SPDZ, 2019, [BCS19](https://eprint.iacr.org/2019/035)
- SPDZ2k: Efficient MPC MOD 2k for dishonest majority, 2018, [SDESC18](https://eprint.iacr.org/2018/482)
- Overdrive: Making SPDZ great again, 2017, [KPR17](https://eprint.iacr.org/2017/1230)
- High-throughput secure three-party computation for malicious adversaries and an honest majority, 2016, [FLNW16](https://eprint.iacr.org/2016/944)
- MASCOT: Faster Malicious Arithmetic Secure Computation with Oblivious Transfer Marcel, 2016, [KOS16](https://eprint.iacr.org/2016/505)
- A new approach to practical active-secure two-party computation, 2011, [NNOB11](https://eprint.iacr.org/2011/091)



**Covert Generic Protocols**

- Practical Covertly Secure MPC for Dishonest Majority – or : Breaking the SPDZ Limits, 2012, [DKLPSS12](https://eprint.iacr.org/2012/642)
- Calling out Cheaters: Covert Security With Public Verifiability, 2012, [AO12](https://eprint.iacr.org/2012/708)
- Security Against Covert Adversaries : Efficient Protocols for Realistic Adversaries, 2009, [AL09](https://eprint.iacr.org/2007/060)



## 2. Lattice

**Summaries and Talks**

- Crypto Innovation School 2019, [link](https://crypto.sjtu.edu.cn/cis2019/)

**Homomorphic Encryption (HE)**

- Homomorphic Encryption for Arithmetic of Approximate Numbers, 2016, [CKKS16](https://eprint.iacr.org/2016/421)
- Homomorphic Encryption from Learning with Errors: Conceptually-Simpler, Asymptotically-Faster, Attribute-Based, 2013, [GSW13](https://eprint.iacr.org/2013/340)
- Somewhat Practical Fully Homomorphic Encryption, 2012, [BFV12](https://pdfs.semanticscholar.org/531f/8e756ea280f093138788ee896b3fa8ca085a.pdf)
- Fully Homomorphic Encryption without Bootstrapping, 2011, [BGV11](https://eprint.iacr.org/2011/277.pdf)
- Computing Arbitrary Functions of Encrypted Data, 2009, [Gen09](https://crypto.stanford.edu/craig/easy-fhe.pdf)
