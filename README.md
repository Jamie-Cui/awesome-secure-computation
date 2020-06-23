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


