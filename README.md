# awesome-crypto [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

This repo is a paper summary for cryptography, including topics like [*Multiparty Computation*](https://en.wikipedia.org/wiki/Secure_multi-party_computation), [*Homomorphic Encryption*](https://en.wikipedia.org/wiki/Homomorphic_encryption) and [*Differential Privacy*](https://en.wikipedia.org/wiki/Differential_privacy). Here's a good place to ask questions related to cryptography, or answering one (if you are capable of doing so): [https://crypto.stackexchange.com/](https://crypto.stackexchange.com/), and finding papers [Cryptology ePrint Archive](https://eprint.iacr.org/)

> **[Recent NEWS]** Good Tutorials on Secure Computation: [10th BIU Winter School](https://cyber.biu.ac.il/event/the-10th-biu-winter-school-on-cryptography/)


### Secure Computation (HE, MPC, OT, etc.)

#### Classic Papers

- How to play any mental game?, **GMW87**, [[pdf]](https://dl.acm.org/citation.cfm?id=28420)
- Completeness Theorems for Non-Cryptographic Fault Tolerant Distributed Computation, **BGW88**, [[pdf]\(ACM\)](https://dl.acm.org/citation.cfm?id=62213)
- The Round Complexity of Secure Protocols, **BMR90**, [[pdf]](http://web.cs.ucdavis.edu/~rogaway/papers/bmr90)
- Computing Arbitrary Functions of Encrypted Data, **Gen09**, [[pdf]](https://crypto.stanford.edu/craig/easy-fhe.pdf)
- Fully Homomorphic Encryption without Bootstrapping, **BGV11**, [[pdf]](https://eprint.iacr.org/2011/277.pdf)
- Somewhat Practical Fully Homomorphic Encryption, **BFV12**, [[pdf]](https://pdfs.semanticscholar.org/531f/8e756ea280f093138788ee896b3fa8ca085a.pdf)
- Homomorphic Encryption from Learning with Errors: Conceptually-Simpler, Asymptotically-Faster, Attribute-Based, **GSW13**, [[pdf]](https://eprint.iacr.org/2013/340.pdf)
- Homomorphic Encryption for Arithmetic of Approximate Numbers, **CKSS16**, [[pdf]](https://eprint.iacr.org/2016/421.pdf)

#### Recent Research

- A Survey on Homomorphic Encryption Schemes: Theory and Implementation, **ACM CSUR 2018** [[pdf]](https://arxiv.org/pdf/1704.03578.pdf)
- Endemic Oblivious Transfer, **#OT**, [[pdf]](https://eprint.iacr.org/2019/706)
- Efficient Publicly Verifiable 2PC over a Blockchain with Applications to Financially-Secure Computations, **#MPC #Blockchains**, [[pdf]](http://homes.sice.indiana.edu/yh33/mypub/pvc.pdf)
- A High-Assurance Evaluator for Machine-Checked Secure Multiparty Computation, **#PMPC**, [[pdf]](https://eprint.iacr.org/2019/922)
- HoneyBadgerMPC and AsynchroMix: Practical Asynchronous MPC and its Application to Anonymous Communication, **#MPC**, [[pdf]](https://eprint.iacr.org/2019/883.pdf)
- Practical Fully Secure Three-Party Computation via Sublinear Distributed Zero-Knowledge Proofs, **#MPC #ZKP**, [[pdf]](https://eprint.iacr.org/2019/1390)
- Efficient Two-Round OT Extension and Silent Non-Interactive Secure Computation, **#OT#MPC**, [[pdf]](https://eprint.iacr.org/2019/1159)
- Two-Thirds Honest-Majority MPC for Malicious Adversaries at Almost the Cost of Semi-Honest, **#MPC #SecurityModel**, [[pdf]](https://eprint.iacr.org/2019/658)
- Efficient MPC via Program Analysis: : A Framework for Efficient Optimal Mixing, **#EfficientMPC**, [[pdf]](https://eprint.iacr.org/2019/651)
- Reusable Non-Interactive Secure Computation, **#MPC**, [[pdf]](https://eprint.iacr.org/2018/940.pdf)
- Unconditionally Secure Computation Against Low-Complexity Leakage, **MPC**, [[pdf]](https://eprint.iacr.org/2019/627)
- Adaptively Secure MPC with Sublinear Communication Complexity, **#MPC**, [[pdf]](https://eprint.iacr.org/2018/1161)
- SpOT-Light: Lightweight Private Set Intersection from Sparse OT Extension, **#MPC #PSI**, [[pdf]](https://eprint.iacr.org/2019/634.pdf)
- Communication Lower Bounds for Statistically Secure MPC, with or without Preprocessing, **#MPC**, [[pdf]](https://eprint.iacr.org/2019/220)
- Communication-Efficient Unconditional MPC with Guaranteed Output Delivery, **#MPC**, [[pdf]](https://eprint.iacr.org/2019/646)
- Degree 2 is Complete for the Round-Complexity of Malicious MPC, **#MaliciousMPC**, [[pdf]](https://eprint.iacr.org/2019/200.pdf)
- Improved Bootstrapping for Approximate Homomorphic Encryption, **#HE** [[pdf]](https://eprint.iacr.org/2018/1043.pdfhttps://eprint.iacr.org/2018/1043.pdf)
- Homomorphic Secret Sharing from Lattices Without FHE, **#FHE** [[pdf]](https://eprint.iacr.org/2019/129.pdf)
- SoK: General Purpose Compilers for Secure Multi-Party Computation, **#MPC #SoK**, [[pdf]](https://marsella.github.io/static/mpcsok.pdf)
- Covert security with public verifiability: faster, leaner, and simpler, Hong19, **#CovertMPC** [[pdf]](https://eprint.iacr.org/2018/1108.pdf


### Differential Privacy
- Calibrating Noise to Sensitivity in Private DataAnalysis, DMNS06, [[pdf]](http://people.csail.mit.edu/asmith/PS/sensitivity-tcc-final.pdf)
- Privacy Integrated Queries:An Extensible Platform for Privacy-Preserving Data Analysis, **#PrivacyAccountant**, [[pdf]](https://www.microsoft.com/en-us/research/wp-content/uploads/2010/09/pinq-CACM.pdf)

### Machine Learning Related (PPML, AML, FML, etc.)

#### Classic Papers
- Deep Learning with Differential Privacy, *Martín Abadi, Andy Chu, Ian Goodfellow, H. Brendan McMahan, Ilya Mironov, Kunal Talwar, Li Zhang*, **CCS 2016** [[pdf]](https://arxiv.org/pdf/1607.00133.pdf)
- Federated Optimization: Distributed Machine Learning for On-Device Intelligence, **2016 Google AI** [[pdf]](https://arxiv.org/pdf/1610.02527.pdf)
- Federated Learning: Strategies for improving communication efficiency, **2016 Google AI** [[pdf]](https://arxiv.org/pdf/1610.05492.pdf)
- Federated Learning of Deep Networks using Model Averaging, **2016 Google AI** [[pdf]](https://pdfs.semanticscholar.org/8b41/9080cd37bdc30872b76f405ef6a93eae3304.pdf)
- Practical Secure Aggregationfor Privacy-Preserving Machine Learning, **2017 Google AI** [[pdf]](https://acmccs.github.io/papers/p1175-bonawitzA.pdf)

#### Recent Research
- Privacy-Preserving Deep Learning via Additively Homomorphic Encryption, **IEEE TIFS 2018** [[pdf]](https://eprint.iacr.org/2017/715.pdf)
- DeepSecure: Scalable Provably-Secure Deep Learning, [[pdf]](https://arxiv.org/ftp/arxiv/papers/1705/1705.08963.pdf)
- SecureML: A System for Scalable Privacy-Preserving Machine Learning, [[pdf]](https://eprint.iacr.org/2017/396.pdf)
- XONN: XNOR-based Oblivious Deep Neural Network Inference, **#PPML #DNN**, [[pdf]](https://eprint.iacr.org/2019/171.pdf)
- Comprehensive Privacy Analysis of Deep Learning, **#Privacy #ML**, [[pdf]](https://arxiv.org/pdf/1812.00910.pdf)
- Exploiting Unintended Feature Leakage in Collaborative Learning, **#FML**, [[pdf]](https://arxiv.org/pdf/1805.04049.pdf)
- ML-Leaks: Model and Data Independent Membership Inference Attacks and Defenses on Machine Learning Models, **#AML**, [[pdf]](https://arxiv.org/pdf/1806.01246.pdf)

### Genomic Privacy (untracked)

A pretty and well-organised resource website: [genomicprivacy.org](https://genomeprivacy.org/publications/)

- MBeacon: Privacy-Preserving Beacons for DNA Methylation Data, **NDSS 2019**, [[pdf]](https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_03A-2_Hagestedt_paper.pdf)
- Privacy Preserving Genome Wide Asssociation Study is Practical, **BMC Bioinformatics 2018**, [[pdf]](https://eprint.iacr.org/2017/955.pdf)
- Privacy-Preserving Search of Similar Patients inGenomic Data, **PPET 2018**,[[pdf]](https://www.petsymposium.org/2018/files/papers/issue4/popets-2018-0034.pdf)
- Routes for breaching and protecting genetic privacy, **Nature Reviews Genetics 2014**, [[pdf]](https://www.ncbi.nlm.nih.gov/pubmed/24805122)
- Resolving Individuals Contributing Trace Amounts of DNA to Highly Complex Mixtures Using High-Density SNP Genotyping Microarrays, **PLoS 2008**, [[pdf]](https://journals.plos.org/plosgenetics/article?id=10.1371/journal.pgen.1000167)


In the below I listed several top conferences in security/cryptography [[**Reference**]](http://faculty.cs.tamu.edu/guofei/sec_conf_stat.htm):

Here's the main website for this year's conferences!
- [S&P 2019](https://www.ieee-security.org/TC/SP2019/)
- [CCS 2019](https://www.sigsac.org/ccs/CCS2019/)
- [USENIX Security 2019](https://www.usenix.org/conference/usenixsecurity19)
- [NDSS 2019](https://www.ndss-symposium.org/ndss2019/)
- [EUROCRYPT 2019](https://eurocrypt.iacr.org/2019/)
- [CRYPTO 2019](https://crypto.iacr.org/2019/)

| Conference Name                                                                     | Abbreviation    |Time (this year)|
|-------------------------------------------------------------------------------------|-----------------|----------------|
| IEEE Symposium on Security and Privacy                                              | S&P             |MAY 20-22       |
| ACM Conference on Computer and Communications Security                              | CCS             |November 11-15  |
| USENIX Security Symposium                                                           | USENIX Security |August 14–16    |
| Network and Distributed System Security Symposium                                   | NDSS            |June 23-25      |
| International Conference on Theory and Applications of Cryptographic Techniques     | EUROCRYPT       |May 19-23       |
| International Cryptology Conference                                                 | CRYPTO          |August 18-22    |


