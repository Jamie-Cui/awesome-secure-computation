# awesome-crypto [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

[TOC]

This repo is a paper summary for cryptography, including topics like [*Multiparty Computation*](https://en.wikipedia.org/wiki/Secure_multi-party_computation), [*Homomorphic Encryption*](https://en.wikipedia.org/wiki/Homomorphic_encryption) and [*Differential Privacy*](https://en.wikipedia.org/wiki/Differential_privacy). Here's a good place to ask questions related to cryptography, or answering one (if you are capable of doing so): [https://crypto.stackexchange.com/](https://crypto.stackexchange.com/), and finding papers [Cryptology ePrint Archive](https://eprint.iacr.org/)

> **[Recent NEWS]** Good Tutorials on Secure Computation: [10th BIU Winter School](https://cyber.biu.ac.il/event/the-10th-biu-winter-school-on-cryptography/)

> Countdown for Security Conf DDLs: [Security and Privacy Conference Deadlines](https://sec-deadlines.github.io/)

### Secure Computation (MPC, OT, etc.)

### 0. Summaries & Talks

| Title                                                        | Year | Note                                            | Eprint                                                       |
| ------------------------------------------------------------ | ---- | ----------------------------------------------- | ------------------------------------------------------------ |
| SoK: General purpose compilers for secure multi-party computation | 2019 | [github](https://github.com/MPC-SoK/frameworks) | [HNZ19](https://ieeexplore.ieee.org/abstract/document/8835312) |
| Crypto Innovation School 2018                                | 2018 | Tutorials                                       | [CIS18](https://crypto.sjtu.edu.cn/cis2018/)                 |

### 1. Primitives

#### 1.1. OT

| Title                                                        | Year | Note                                           | Eprint                                                       |
| ------------------------------------------------------------ | ---- | ---------------------------------------------- | ------------------------------------------------------------ |
| Endemic Oblivious Transfer                                   | 2019 | malicious secure 1-out-of-2 base OT            | [MR19](https://eprint.iacr.org/2019/706)                     |
| Efficient Two-Round OT Extension and Silent Non-Interactive Secure Computation | 2019 | semi-honest 1-out-of-2 Silent OT               | [BCGIKRS19](https://eprint.iacr.org/2019/1159)               |
| Efficient Pseudorandom Correlation Generators: Silent OT Extension and More | 2019 | Silent OT Extension                            | [BCGIKRS19](https://eprint.iacr.org/2019/448)                |
| Actively Secure 1-out-of-N OT Extension with Application to Private Set Intersection | 2016 | The malicious secure 1-out-of-N OT             | [OOS17](https://eprint.iacr.org/2016/933)                    |
| Improved Private Set Intersection against Malicious Adversaries | 2016 | The malicious secure approximate K-out-of-N OT | [RR16](https://eprint.iacr.org/2016/746)                     |
| Efficient Batched Oblivious PRF with Applications to Private Set Intersection | 2016 | The semi-honest 1-out-of-N OT                  | [KKRT16](https://eprint.iacr.org/2016/799)                   |
| Actively Secure OT Extension with Optimal Overhead           | 2015 | The malicious secure 1-out-of-2 OT             | [KOS15](https://eprint.iacr.org/2015/546)                    |
| High Performance Multi-Party Computation for Binary Circuits Based on Oblivious Transfer | 2015 | The malicious secure 1-out-of-2 Delta-OT       | [BLNNOOSS15](https://eprint.iacr.org/2015/472)               |
| The Simplest Protocol for Oblivious Transfer                 | 2015 | The malicious secure 1-out-of-2 base OT        | [CO15](https://eprint.iacr.org/2015/267)                     |
| More Efficient Oblivious Transfer and Extensions for Faster Secure Computation | 2015 | The semi-honest 1-out-of-2 OT                  | [ALSZ15](https://eprint.iacr.org/2013/552)                   |
| Extending Oblivious Transfers Efficiently                    | 2003 | The semi-honest 1-out-of-2 OT                  | [IKNP03](https://www.iacr.org/archive/crypto2003/27290145/27290145.pdf) |

#### 1.2. FSS

| Title                                                | Year | Note | Eprint                                                       |
| ---------------------------------------------------- | ---- | ---- | ------------------------------------------------------------ |
| Function Secret Sharing                              | 2016 |      | [BGI16a](https://www.iacr.org/archive/eurocrypt2015/90560300/90560300.pdf) |
| Function secret sharing: Improvements and extensions | 2016 |      | [BGI16b](https://eprint.iacr.org/2018/707)                   |
| Distributed point functions and their applications   | 2014 |      | [GI19](https://www.iacr.org/archive/eurocrypt2014/84410245/84410245.pdf) |

#### 1.3. OLE

| Title                                                        | Year | Note | Eprint                                      |
| ------------------------------------------------------------ | ---- | ---- | ------------------------------------------- |
| Distributed vector-ole: Improved constructions and implementation | 2019 |      | [SGRR19](https://eprint.iacr.org/2019/1084) |
| Compressing vector OLE                                       | 2018 |      | [BCGI18](https://eprint.iacr.org/2019/273)  |

#### 1.4. PSI

| Title                                                        | Year | Note     | Eprint                                                |
| ------------------------------------------------------------ | ---- | -------- | ----------------------------------------------------- |
| Private Matching for Compute                                 | 2020 | Facebook | [BKMSTV20](https://eprint.iacr.org/2020/599)          |
| Private Set Intersection in the Internet Setting From Lightweight Oblivious PRF | 2020 |          | [CM20](https://eprint.iacr.org/2020/729)              |
| PIR-PSI: Scaling Private Contact Discovery                   | 2018 |          | [DRRT18](https://eprint.iacr.org/2018/579)            |
| Malicious-Secure private set intersection via dual execution | 2017 |          | [RR17](https://eprint.iacr.org/2017/769)              |
| Improved private set intersection against malicious adversaries | 2016 |          | [RR16](https://eprint.iacr.org/2016/746)              |
| Efficient batched oblivious PRF with applications to private set intersection | 2016 |          | [KKRT16](https://eprint.iacr.org/2016/799)            |
| Phasing : Private Set Intersection using Permutation-based Hashing | 2015 |          | [PSSZ15](https://eprint.iacr.org/2015/634)            |
| Private set intersection: Are garbled circuits better than custom protocols | 2012 |          | [HEK12](https://www.cs.umd.edu/~jkatz/papers/psi.pdf) |
| Linear-complexity private set intersection protocols secure in malicious model | 2010 |          | [CKT10](https://eprint.iacr.org/2010/469)             |

### 2. Generic Protocols

#### 2.1. Semi-honest protocols

| Title                                                        | Year | Note | Eprint                                                   |
| ------------------------------------------------------------ | ---- | ---- | -------------------------------------------------------- |
| The Round Complexity of Secure Protocols                     | 1990 |      | [BMR90](http://web.cs.ucdavis.edu/~rogaway/papers/bmr90) |
| Completeness Theorems for Non-Cryptographic Fault Tolerant Distributed Computation | 1988 |      | [BGW88](https://dl.acm.org/doi/10.1145/62212.62213)      |
| How to play any mental game?                                 | 1987 |      | [GMW87](https://dl.acm.org/doi/10.1145/28395.28420)      |
| How to generate and exchange secrets?                        | 1986 |      | [Yao86](https://ieeexplore.ieee.org/document/4568207)    |

#### 2.2. Covert Security

| Title                                                        | Year | Note | Eprint                                       |
| ------------------------------------------------------------ | ---- | ---- | -------------------------------------------- |
| Practical Covertly Secure MPC for Dishonest Majority – or : Breaking the SPDZ Limits | 2012 |      | [DKLPSS12](https://eprint.iacr.org/2012/642) |
| Calling out Cheaters: Covert Security With Public Verifiability | 2012 |      | [AO12](https://eprint.iacr.org/2012/708)     |
| Security Against Covert Adversaries : Efficient Protocols for Realistic Adversaries | 2009 |      | [AL09](https://eprint.iacr.org/2007/060)     |

#### 2.3. Malicious Security

| Title                                                        | Year | Note | Eprint |
| ------------------------------------------------------------ | ---- | ---- | ------ |
| Using TopGear in Overdrive: A more efficient ZKPoK for SPDZ  |      |      |        |
| SPDZ2k: Efficient MPC MOD 2k for dishonest majority          |      |      |        |
| Overdrive: Making SPDZ great again                           |      |      |        |
| High-throughput secure three-party computation for malicious adversaries and an honest majority |      |      |        |
| MASCOT: Faster Malicious Arithmetic Secure Computation with Oblivious Transfer Marcel |      |      |        |
| A new approach to practical active-secure two-party computation |      |      |        |

## Homomorphic Encryption

| Title                                                        | Year | Note | Eprint                                                       |
| ------------------------------------------------------------ | ---- | ---- | ------------------------------------------------------------ |
| Computing Arbitrary Functions of Encrypted Data              | 2009 |      | [Gen09](https://crypto.stanford.edu/craig/easy-fhe.pdf)      |
| Fully Homomorphic Encryption without Bootstrapping           | 2011 |      | [BGV11](https://eprint.iacr.org/2011/277.pdf)                |
| Somewhat Practical Fully Homomorphic Encryption              | 2012 |      | [BFV12](https://pdfs.semanticscholar.org/531f/8e756ea280f093138788ee896b3fa8ca085a.pdf) |
| Homomorphic Encryption from Learning with Errors: Conceptually-Simpler, Asymptotically-Faster, Attribute-Based | 2013 |      | [GSW13](https://eprint.iacr.org/2013/340)                    |
| Homomorphic Encryption for Arithmetic of Approximate Numbers | 2016 |      | [CKKS16](https://eprint.iacr.org/2016/421)                   |

## Recent Research

- Endemic Oblivious Transfer, **#OT**, [[pdf]](https://eprint.iacr.org/2019/706)
- A Survey on Homomorphic Encryption Schemes: Theory and Implementation, **#Survey #HE** [[pdf]](https://arxiv.org/pdf/1704.03578.pdf)
- Improved Bootstrapping for Approximate Homomorphic Encryption, **#HE**, [[pdf]](https://eprint.iacr.org/2018/1043.pdfhttps://eprint.iacr.org/2018/1043.pdf)
- Homomorphic Secret Sharing from Lattices Without FHE, **#FHE**, [[pdf]](https://eprint.iacr.org/2019/129.pdf)
- SpOT-Light: Lightweight Private Set Intersection from Sparse OT Extension, **#MPC #PSI**, [[pdf]](https://eprint.iacr.org/2019/634.pdf)
- SoK: General Purpose Compilers for Secure Multi-Party Computation, **#MPC-Compiler #SoK**, [[pdf]](https://marsella.github.io/static/mpcsok.pdf)
- Efficient Publicly Verifiable 2PC over a Blockchain with Applications to Financially-Secure Computations, **#Verifiable-2PC-MPC #Blockchains**, [[pdf]](http://homes.sice.indiana.edu/yh33/mypub/pvc.pdf)
- A High-Assurance Evaluator for Machine-Checked Secure Multiparty Computation, **#PMPC**, [[pdf]](https://eprint.iacr.org/2019/922)
- Reusable Non-Interactive Secure Computation, **#MPC**, [[pdf]](https://eprint.iacr.org/2018/940.pdf)
- Unconditionally Secure Computation Against Low-Complexity Leakage, **MPC**, [[pdf]](https://eprint.iacr.org/2019/627)
- Adaptively Secure MPC with Sublinear Communication Complexity, **#MPC**, [[pdf]](https://eprint.iacr.org/2018/1161)
- Communication Lower Bounds for Statistically Secure MPC, with or without Preprocessing, **#MPC**,
- Efficient Two-Round OT Extension and Silent Non-Interactive Secure Computation, **#Efficient-MPC #OT**, [[pdf]](https://eprint.iacr.org/2019/1159)
- Communication-Efficient Unconditional MPC with Guaranteed Output Delivery, **#Efficient-MPC**, [[pdf]](https://eprint.iacr.org/2019/646)
- Efficient MPC via Program Analysis: : A Framework for Efficient Optimal Mixing, **#Efficient-MPC**, [[pdf]](https://eprint.iacr.org/2019/651)
- HoneyBadgerMPC and AsynchroMix: Practical Asynchronous MPC and its Application to Anonymous Communication, **#Practical-MPC**, [[pdf]](https://eprint.iacr.org/2019/883.pdf)
- Practical Fully Secure Three-Party Computation via Sublinear Distributed Zero-Knowledge Proofs, **#Practical-MPC #ZKP**, [[pdf]](https://eprint.iacr.org/2019/1390)
- Two-Thirds Honest-Majority MPC for Malicious Adversaries at Almost the Cost of Semi-Honest, **#MPC #SecurityModel**, [[pdf]](https://eprint.iacr.org/2019/658)
- Covert security with public verifiability: faster, leaner, and simpler, Hong19, **#Covert-MPC**, [[pdf]](https://eprint.iacr.org/2018/1108.pdf)
- Degree 2 is Complete for the Round-Complexity of Malicious MPC, **#Malicious-MPC**, [[pdf]](https://eprint.iacr.org/2019/200.pdf)
  [[pdf]](https://eprint.iacr.org/2019/220)

### Differential Privacy

- Calibrating Noise to Sensitivity in Private DataAnalysis, **DMNS06**, [[pdf]](http://people.csail.mit.edu/asmith/PS/sensitivity-tcc-final.pdf)
- The Algorithmic Foundations of Differential Privacy, **2016#Textbook**, [[pdf]](https://www.cis.upenn.edu/~aaroth/Papers/privacybook.pdf)
- The Composition Theorem for Differential Privacy, **#Composition**, [[pdf]](https://arxiv.org/pdf/1311.0776.pdf)
- On the Difficulties of Disclosure Prevention in Statistical Databases or The Case for Differential Privacy, **Dwork**, [[pdf]](http://www.wisdom.weizmann.ac.il/~naor/PAPERS/imp_disclosure.pdf)
- Distributed differential privacy via shuffling, **2019**, [[pdf]](https://arxiv.org/abs/1808.01394)
- Privacy Integrated Queries:An Extensible Platform for Privacy-Preserving Data Analysis, **#PrivacyAccountant**, [[pdf]](https://www.microsoft.com/en-us/research/wp-content/uploads/2010/09/pinq-CACM.pdf)
- Differentially Private Model Publishing for Deep Learning, **#DP#DL**, [[pdf]](https://arxiv.org/pdf/1904.02200.pdf)

### Machine Learning Related (PPML, AML, FML, etc.)

#### Classic Papers

- Deep Learning with Differential Privacy, *Martín Abadi, Andy Chu, Ian Goodfellow, H. Brendan McMahan, Ilya Mironov, Kunal Talwar, Li Zhang*, **CCS 2016** [[pdf]](https://arxiv.org/pdf/1607.00133.pdf)
- Federated Optimization: Distributed Machine Learning for On-Device Intelligence, **2016 Google AI** [[pdf]](https://arxiv.org/pdf/1610.02527.pdf)
- Federated Learning: Strategies for improving communication efficiency, **2016 Google AI** [[pdf]](https://arxiv.org/pdf/1610.05492.pdf)
- Federated Learning of Deep Networks using Model Averaging, **2016 Google AI** [[pdf]](https://pdfs.semanticscholar.org/8b41/9080cd37bdc30872b76f405ef6a93eae3304.pdf)
- Practical Secure Aggregationfor Privacy-Preserving Machine Learning, **2017 Google AI** [[pdf]](https://acmccs.github.io/papers/p1175-bonawitzA.pdf)

#### Recent Research

- DeepSecure: Scalable Provably-Secure Deep Learning, **PPDL**, [[pdf]](https://arxiv.org/ftp/arxiv/papers/1705/1705.08963.pdf)
- Privacy-Preserving Deep Learning via Additively Homomorphic Encryption, **#PPDL #HE**, [[pdf]](https://eprint.iacr.org/2017/715.pdf)
- SecureML: A System for Scalable Privacy-Preserving Machine Learning, **#PPML** [[pdf]](https://eprint.iacr.org/2017/396.pdf)
- XONN: XNOR-based Oblivious Deep Neural Network Inference, **#PPML #DNN**, [[pdf]](https://eprint.iacr.org/2019/171.pdf)
- Comprehensive Privacy Analysis of Deep Learning, **#PrivacyAnalysis #ML**, [[pdf]](https://arxiv.org/pdf/1812.00910.pdf)
- Towards practical differentially private convex optimization, **#PPML #DP**, [[pdf]](www.omthakkar.com/papers/TPDPCO.pdf)
- Helen: Maliciously Secure Coopetitive Learning for Linear Models, **#PPML #FML #Malicious**, [[pdf]](https://people.eecs.berkeley.edu/~wzheng/helen_ieeesp.pdf)
- Exploiting Unintended Feature Leakage in Collaborative Learning, **#AML #FML**, [[pdf]](https://arxiv.org/pdf/1805.04049.pdf)
- ML-Leaks: Model and Data Independent Membership Inference Attacks and Defenses on Machine Learning Models, **#AML**, [[pdf]](https://arxiv.org/pdf/1806.01246.pdf)
- Neural Cleanse: Identifying and Mitigating Backdoor Attacks in Neural Networks, **#AML**, [[pdf]](people.cs.uchicago.edu/~ravenben/publications/pdf/backdoor-sp19.pdf)
- NIC: Detecting Adversarial Samples with Neural Network Invariant Checking, **#AML**,  [[pdf]](https://www.cs.purdue.edu/homes/ma229/papers/NDSS19.pdf)
- Stealthy Adversarial Perturbations Against Real-Time Video Classification Systems, **#AML #RT-Video** ,[[pdf]](https://www.ndss-symposium.org/ndss-paper/stealthy-adversarial-perturbations-against-real-time-video-classification-systems/)
- TEXTBUGGER: Generating Adversarial Text Against Real-world Applications, **#AML #Text**, [[pdf]](https://arxiv.org/abs/1812.05271)




In the below I listed several top conferences in security/cryptography [[**Reference**]](http://faculty.cs.tamu.edu/guofei/sec_conf_stat.htm):

| Conference Name                                              | Abbreviation    |
| ------------------------------------------------------------ | --------------- |
| IEEE Symposium on Security and Privacy                       | S&P             |
| ACM Conference on Computer and Communications Security       | CCS             |
| USENIX Security Symposium                                    | USENIX Security |
| Network and Distributed System Security Symposium            | NDSS            |
| International Conference on Theory and Applications of Cryptographic Techniques | EUROCRYPT       |
| International Cryptology Conference                          | CRYPTO          |
