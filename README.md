# awesome-secure-computation [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

This repo is a paper summary for cryptography-based secure computation papers (I prefer published papers 😛), including topics like [*Multiparty Computation*](https://en.wikipedia.org/wiki/Secure_multi-party_computation), [*Homomorphic Encryption (or Lattice)*](https://en.wikipedia.org/wiki/Homomorphic_encryption) and [*Differential Privacy*](https://en.wikipedia.org/wiki/Differential_privacy). If you are looking for hardware solutions like Trusted Platform Module (TPM), or Trusted Execution Environment (TEE), I'm sorry this repo is not what you're looking for :(.

Here's a good place to ask questions about cryptography/cryptanalysis, or answering one (if you are capable of doing so): [https://crypto.stackexchange.com/](https://crypto.stackexchange.com/), and finding papers [Cryptology ePrint Archive](https://eprint.iacr.org/).

**Useful Links**:

- [Security Conferences Ranking](http://faculty.cs.tamu.edu/guofei/sec_conf_stat.htm)
- [Security and Privacy Conference Deadlines](https://sec-deadlines.github.io/)
- [Crypto21: Mentoring Videos about how to do research in cryptography](https://mentor-crypto-2021.github.io/)

## Table of Contents (or Papers)

- [MPC](#mpc)
  * [Summaries and Talks](#summaries-and-talks)
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

## MPC

> MPC: Multi-Party Computation

### Summaries and Talks

- 10th BIU Winter School: information-theoretic cryptography, 2020, [link](https://cyber.biu.ac.il/event/the-10th-biu-winter-school-on-cryptography/)
- 9th BIU Winter School: information-theoretic cryptography: zero-knowledge proofs, 2019
- SoK: General purpose compilers for secure multi-party computation, 2019, [Github](https://github.com/MPC-SoK/frameworks), [Paper](https://ieeexplore.ieee.org/abstract/document/8835312)
- Crypto Innovation School 2018, [link](https://crypto.sjtu.edu.cn/cis2018/)

### OT

> OT: Oblivious Transfer  
> 1-out-of-2 base OT and OT Extensions

- Silver: Silent VOLE and Oblivious Transfer from Hardness of Decoding Structured LDPC Codes  
  *Geoffroy Couteau, Peter Rindal, Srinivasan Raghuraman*  
  Crypto 2021, [eprint](https://eprint.iacr.org/2021/1150), CRR21

- The Rise of Paillier: Homomorphic Secret Sharing and Public-Key Silent OT  
  *Claudio Orlandi, Peter Scholl, Sophia Yakoubov*  
  EuroCrypt 2021, [eprint](https://eprint.iacr.org/2021/262), OSY21

- Batching Base Oblivious Transfers  
  *Ian McQuoid, Mike Rosulek, Lawrence Roy*  
  AsiaCrypt 2021, [eprint](https://eprint.iacr.org/2021/682), MRR21

- Efficient Two-Round OT Extension and Silent Non-Interactive Secure Computation  
  *Elette Boyle, Geoffroy Couteau, Niv Gilboa, Yuval Ishai, Lisa Kohl, Peter Rindal, Peter Scholl*  
  CCS 2019, [eprint](https://eprint.iacr.org/2019/1159), BCGI+19 (with Peter Rindal)
  
- Endemic Oblivious Transfer  
  *Daniel Masny, Peter Rindal*  
  CCS 2019, [eprint](https://eprint.iacr.org/2019/706), MR19 
  
- Efficient Pseudorandom Correlation Generators: Silent OT Extension and More  
  *Elette Boyle, Geoffroy Couteau, Niv Gilboa, Yuval Ishai, Lisa Kohl, Peter Scholl*  
  Crypto 2019, [eprint](https://eprint.iacr.org/2019/448), BCGI+19 (without Peter Rindal)

- Actively Secure 1-out-of-N OT Extension with Application to Private Set Intersection  
  *Michele Orrù, Emmanuela Orsini, Peter Scholl*  
  CT-RSA 2017, [eprint](https://eprint.iacr.org/2016/933), OOS17

- Actively Secure OT Extension with Optimal Overhead  
  *Marcel Keller, Emmanuela Orsini, Peter Scholl*  
  Crypto 2015, [eprint](https://eprint.iacr.org/2015/546), KOS15
  
- The Simplest Protocol for Oblivious Transfer  
  *Tung Chou, Claudio Orlandi*  
  LatinCrypt 2015, [eprint](https://eprint.iacr.org/2015/267), CO15
  
- More Efficient Oblivious Transfer and Extensions for Faster Secure Computation  
  *Gilad Asharov, Yehuda Lindell, Thomas Schneider, Michael Zohner*  
  CCS 2013, [eprint](https://eprint.iacr.org/2013/552), ALSZ13
  
- Extending Oblivious Transfers Efficiently  
  *Yuval Ishai, Joe Kilian, Kobbi Nissim, Erez Petrank*  
  Crypto 2003, [eprint](https://www.iacr.org/archive/crypto2003/27290145/27290145.pdf), IKNP03

- Oblivious Transfer and Polynomial Evaluation  
  *Moni Naor, Benny Pinkas*  
  STOC 1999, [eprint](https://dl.acm.org/doi/pdf/10.1145/301250.301312), NP99

### vOLE

- Silver: Silent VOLE and Oblivious Transfer from Hardness of Decoding Structured LDPC Codes  
  *Geoffroy Couteau, Peter Rindal, Srinivasan Raghuraman*  
  Crypto 2021, [eprint](https://eprint.iacr.org/2021/1150), CRR21
  
- Two-Round Oblivious Linear Evaluation from Learning with Errors  
  *Pedro Branco, Nico Döttling, Paulo Mateus*  
  PKC 2022, [eprint](https://eprint.iacr.org/2020/635), BDM20

- Efficient Protocols for Oblivious Linear Function Evaluation from Ring-LWE  
  *Carsten Baum, Daniel Escudero, Alberto Pedrouzo-Ulloa, Peter Scholl, Juan Ramón Troncoso-Pastoriza*  
  SCN 2020, [eprint](https://eprint.iacr.org/2020/970), BEPS+20

- Distributed vector-OLE: Improved constructions and implementation  
  *Phillipp Schoppmann, Adrià Gascón, Leonie Reichert, Mariana Raykova*  
  CCS 2019, [eprint](https://eprint.iacr.org/2019/1084), SGRR19

- Compressing vector OLE  
  *Elette Boyle, Geoffroy Couteau, Niv Gilboa, Yuval Ishai*  
  CCS 2018, [eprint](https://eprint.iacr.org/2019/273), BCGI18
  
- Maliciously secure oblivious linear function evaluation with constant overhead  
  *Satrajit Ghosh, Jesper Buus Nielsen, Tobias Nilges*  
  AsiaCrypt 2017, [eprint](https://eprint.iacr.org/2017/409), GNN17

- TinyOLE: Efficient actively secure two-party computation from oblivious linear function evaluation, 2017,   
  *Nico Döttling, Satrajit Ghosh, Jesper Buus Nielsen, Tobias Nilges, Roberto Trifiletti*  
  CCS 2017, [eprint](https://eprint.iacr.org/2017/790), DGNN+17

- Oblivious Transfer and Polynomial Evaluation  
  *Moni Naor, Benny Pinkas*  
  STOC 1999, [eprint](https://dl.acm.org/doi/pdf/10.1145/301250.301312), NP99

### OPRF and PSI

- (Industry) The Apple PSI System  
  [analysis](https://www.apple.com/child-safety/pdf/Apple_PSI_System_Security_Protocol_and_Analysis.pdf)

- Circuit-PSI with Linear Complexity via Relaxed Batch OPPRF  
  *Nishanth Chandran, Divya Gupta, Akash Shah*  
  PETS 2022, [eprint](https://eprint.iacr.org/2021/034), CGS22

- Compact and Malicious Private Set Intersection for Small Sets  
  *Mike Rosulek, Ni Trieu*  
  CCS 2021, [eprint](https://eprint.iacr.org/2021/1159), RT21

- Simple, Fast Malicious Multiparty Private Set Intersection  
  *Ofri Nevo, Ni Trieu, Avishay Yanai*  
  CCS 2021, [eprint](https://eprint.iacr.org/2021/1221), NTY21

- Labeled PSI from Homomorphic Encryption with Reduced Computation and Communication  
  *Kelong Cong, Radames Cruz Moreno, Mariana Botelho da Gama, Wei Dai, Ilia Iliashenko, Kim Laine, Michael Rosenberg*  
  CCS 2021, [eprint](https://eprint.iacr.org/2021/1116), CMBD+21

- VOLE-PSI: Fast OPRF and Circuit-PSI from Vector-OLE  
  *Peter Rindal, Phillipp Schoppmann*  
  EuroCrypt 2021, [eprint](https://eprint.iacr.org/2021/266), RS21

- Private Set Operations from Oblivious Switching  
  *Gayathri Garimella, Payman Mohassel, Mike Rosulek, Saeed Sadeghian, Jaspal Singh*  
  PKC 2021, [eprint](https://eprint.iacr.org/2021/243), GMRS21

- Private Matching for Compute  
  *Prasad Buddhavarapu, Andrew Knox, Payman Mohassel, Shubho Sengupta, Erik Taubeneck, Vlad Vlaskin*  
  Unpublished 2020, [eprint](https://eprint.iacr.org/2020/599)

- Private Set Intersection in the Internet Setting From Lightweight Oblivious PRF  
  *Melissa Chase, Peihan Miao*  
  Crypto 2020, [eprint](https://eprint.iacr.org/2020/729), CM20

- SpOT-Light: Lightweight Private Set Intersection from Sparse OT Extension, 2019,   
  *Benny Pinkas, Mike Rosulek, Ni Trieu, Avishay Yanai*  
  Crypto 2019, [eprint](https://eprint.iacr.org/2019/634), PRTY19

- PIR-PSI: Scaling Private Contact Discovery  
  *Daniel Demmler, Peter Rindal, Mike Rosulek, Ni Trieu*  
  PETS 2018, [eprint](https://eprint.iacr.org/2018/579), DRRT18

- Malicious-Secure Private Set Intersection via Dual Execution  
  *Peter Rindal, Mike Rosulek*  
  CCS 2017, [eprint](https://eprint.iacr.org/2017/769), RR17b 

- Improved Private Set Intersection Against Malicious Adversaries  
  *Peter Rindal, Mike Rosulek*  
  EuroCrypt 2017, [eprint](https://eprint.iacr.org/2016/746), RR17a

- Efficient Batched Oblivious PRF with Applications to Private Set Intersection  
  *Vladimir Kolesnikov, Ranjit Kumaresan, Mike Rosulek, Ni Trieu*  
  CCS 2016, [eprint](https://eprint.iacr.org/2016/799), KKRT16

- Phasing: Private Set Intersection using Permutation-based Hashing  
  *Benny Pinkas, Thomas Schneider, Gil Segev, Michael Zohner*  
  Usenix Security 2015, [eprint](https://eprint.iacr.org/2015/634), PSSZ15
  
- Private Set Intersection: Are Garbled Circuits Better than Custom Protocols?
  *Yan Huang, David Evans, Jonathan Katz*  
  NDSS 2012, [eprint](https://www.cs.umd.edu/~jkatz/papers/psi.pdf), HEK12

- Linear-Complexity Private Set Intersection Protocols Secure in Malicious Model  
  *Emiliano De Cristofaro, Jihye Kim, Gene Tsudik*  
  AsiaCrypt 2010, [eprint](https://eprint.iacr.org/2010/469), CKT10

- Practical Private Set Intersection Protocols with Linear Computational and Bandwidth Complexity  
  *Emiliano De Cristofaro, Gene Tsudik*  
  Unpublished 2010, [eprint](https://eprint.iacr.org/2009/491), CT10

- Information Sharing Across Private Databases  
  *Rakesh Agrawal, Alexandre V. Evfimievski, Ramakrishnan Srikant*  
  SIGMOD 2003, [eprint](https://www.cs.cornell.edu/aevf/research/SIGMOD_2003.pdf), AES03


### PIR

- OnionPIR: Response Efficient Single-Server PIR  
  *Muhammad Haris Mughees, Hao Chen, Ling Ren*  
  CCS 2021, [eprint](https://eprint.iacr.org/2021/1081), MCR21

- On the Security of Doubly Efficient PIR  
  *Elette Boyle, Justin Holmgren, Fermi Ma, Mor Weiss*  
  Report 2021, [eprint](https://eprint.iacr.org/2021/1113)

- Random-index PIR with Applications to Large-Scale Secure MPC  
  *Craig Gentry, Shai Halevi, Bernardo Magri, Jesper Buus Nielsen, Sophia Yakoubov*  
  TCC 2021, [eprint](https://eprint.iacr.org/2020/1248), GHMN+20

- Private Information Retrieval with Sublinear Online Time  
  *Henry Corrigan-Gibbs, Dmitry Kogan*  
  EuroCrypt 2020, [eprint](https://eprint.iacr.org/2019/1075), GK20

- Batched Differentially Private Information Retrieval  
  *Kinan Dak Albab, Rawane Issa, Mayank Varia, Kalman Graffi*  
  Unpublished 2020, [eprint](https://eprint.iacr.org/2020/1596.pdf), AIVG20

- Communication Computation Trade-offs in PIR  
  *Asra Ali, Tancrède Lepoint, Sarvar Patel, Mariana Raykova, Phillipp Schoppmann, Karn Seth, Kevin Yeo*  
  Usenix Security 2019, [eprint](https://eprint.iacr.org/2019/1483), ALPR+19

- PIR with Compressed Queries and Amortized Query Processing  
  *Sebastian Angel, Hao Chen, Kim Laine, Srinath T. V. Setty*  
  SP 2018, [eprint](https://eprint.iacr.org/2017/1142), ACLS+18

- Private Stateful Information Retrieval  
  *Sarvar Patel, Giuseppe Persiano, Kevin Yeo*  
  CCS 2018, [eprint](https://eprint.iacr.org/2018/1083), PPY18

- Can We Access a Database Both Locally and Privately?  
  *Elette Boyle, Yuval Ishai, Rafael Pass, Mary Wootters*  
  TCC 2017, [eprint](https://eprint.iacr.org/2017/567), BIPW17

- Towards Doubly Efficient Private Information Retrieval  
  *Ran Canetti, Justin Holmgren, Silas Richelson*  
  TCC 2017, [eprint](https://eprint.iacr.org/2017/568), CHR17

- XPIR : Private Information Retrieval for Everyone  
  *Carlos Aguilar Melchor, Joris Barrier, Laurent Fousse, Marc-Olivier Killijian*  
  PETS 2016, [eprint](https://eprint.iacr.org/2014/1025), MBFK16

- Optimal Rate Private Information Retrieval from Homomorphic Encryption  
  *Aggelos Kiayias, Nikos Leonardos, Helger Lipmaa, Kateryna Pavlyk, Qiang Tang*  
  PETS 2015, [eprint](https://petsymposium.org/2015/papers/23_Kiayias.pdf), KLLP+15

- First CPIR Protocol with Data-Dependent Computation  
  *Helger Lipmaa*  
  ICISC 2009, [eprint](https://dl.acm.org/doi/10.5555/1883749.1883769), LIP09

- An Oblivious Transfer Protocol with Log-Squared Communication   
  *Helger Lipmaa*  
  ISC 2005, [eprint](https://eprint.iacr.org/2004/063), LIP05

- Single-Database Private Information Retrieval with Constant Communication Rate  
  *Craig Gentry, Zulfikar Ramzan*  
  ICALP 2005, [eprint](https://www.cs.umd.edu/~gasarch/TOPICS/pir/logn.pdf), GR05

- A New Efficient All-Or-Nothing Disclosure of Secrets Protocol  
  *Julien P. Stern*  
  AsiaCrypt 1998, [eprint](https://link.springer.com/content/pdf/10.1007%2F3-540-49649-1_28.pdf), Stern98

- Replication is NOT needed: SINGLE database, computationally- private information retrieval  
  *Eyal Kushilevitz, Rafail Ostrovsky*  
  FOCS 1997, [eprint](https://web.cs.ucla.edu/~rafail/PUBLIC/34.pdf), KO97


### PFE

- Linear-Complexity Private Function Evaluation is Practical  
  *Marco Holz, Ágnes Kiss, Deevashwer Rathee, Thomas Schneider*  
  ESORICS 2020, [eprint](https://eprint.iacr.org/2020/853), HKRS20

- An Efficient 2-Party Private Function Evaluation Protocol Based on Half Gates  
  *Muhammed Ali Bingöl, Osman Biçer, Mehmet Sabir Kiraz, Albert Levi*  
  Comput. J 2019, [eprint](https://eprint.iacr.org/2017/415), BBKL19

- Highly Efficient and Reusable Private Function Evaluation with Linear Complexity  
  *Osman Biçer, Muhammed Ali Bingöl, Mehmet Sabir Kiraz*  
  Unpublished 2018, [eprint](https://eprint.iacr.org/2018/515), BBKL18

- Actively Secure Private Function Evaluation  
  *Payman Mohassel, Seyed Saeed Sadeghian, Nigel P. Smart*  
  AsiaCrypt 2014, [eprint](https://eprint.iacr.org/2014/102), MSS14

- How to Hide Circuits in MPC: An Efficient Framework for Private Function Evaluation  
  *Payman Mohassel, Seyed Saeed Sadeghian*  
  EuroCrypt 2013, [eprint](https://eprint.iacr.org/2013/137), MS13

- Constant-round private function evaluation with linear complexity  
  *Jonathan Katz, Lior Malka*  
  AsiaCrypt 2011, [eprint](https://eprint.iacr.org/2010/528), KM11

- Bureaucratic protocols for secure two-party sorting, selection, and permuting  
  *Guan Wang, Tongbo Luo, Michael T. Goodrich, Wenliang Du, Zutao Zhu*  
  AsiaCCS 2010, [eprint](https://dl.acm.org/doi/10.1145/1755688.1755716), WLGD+10

- Selective private function evaluation with applications to private statistics  
  *Ran Canetti, Yuval Ishai, Ravi Kumar, Michael K. Reiter, Ronitt Rubinfeld, Rebecca N. Wright*  
  PODC 2001, [eprint](https://dl.acm.org/doi/10.1145/383962.384047), CIKR+01


### FSS

- Lightweight Techniques for Private Heavy Hitters  
  *Dan Boneh, Elette Boyle, Henry Corrigan-Gibbs, Niv Gilboa, Yuval Ishai*  
  SP 2021, [eprint](https://arxiv.org/abs/2012.14884), BBGG+21

- Function Secret Sharing for PSI-CA : With Applications to Private Contact Tracing  
  *Samuel Dittmer, Yuval Ishai, Steve Lu, Rafail Ostrovsky, Mohamed Elsabagh, Nikolaos Kiourtis, Brian Schulte, Angelos Stavrou*  
  Unpublished 2021, [eprint](https://eprint.iacr.org/2020/1599), DILO+21

- Function Secret Sharing for Mixed-Mode and Fixed-Point Secure Computation  
  *Elette Boyle, Nishanth Chandran, Niv Gilboa, Divya Gupta, Yuval Ishai, Nishant Kumar, Mayank Rathee*  
  EuroCrypt 2021, [eprint](https://eprint.iacr.org/2020/1392), BCGI+21

- Correlated Pseudorandom Functions from Variable-Density LPN  
  *Elette Boyle, Geoffroy Couteau, Niv Gilboa, Yuval Ishai, Lisa Kohl, Peter Scholl*  
  FOCS 2020, [eprint](https://eprint.iacr.org/2020/1417), BCGI+20

- Secure Computation with Preprocessing via Function Secret Sharing   
  *Elette Boyle, Niv Gilboa, Yuval Ishai*  
  TCC 2019, [eprint](https://eprint.iacr.org/2019/1095), BGI19

- Efficient Two-Round OT Extension and Silent Non-Interactive Secure Computation  
  *Elette Boyle, Geoffroy Couteau, Niv Gilboa, Yuval Ishai, Lisa Kohl, Peter Rindal, Peter Scholl*  
  CCS 2019, [eprint](https://eprint.iacr.org/2019/1159), BCGI+19

- Function secret sharing: Improvements and extensions  
  *Elette Boyle, Niv Gilboa, Yuval Ishai*  
  CCS 2016, [eprint](https://eprint.iacr.org/2018/707), BGI16

- Function Secret Sharing  
  *Elette Boyle, Niv Gilboa, Yuval Ishai*  
  EuroCrypt 2015, [eprint](https://www.iacr.org/archive/eurocrypt2015/90560300/90560300.pdf), BGI15

- Distributed Point Functions and Their Applications  
  *Niv Gilboa, Yuval Ishai*  
  EuroCrypt 2014, [eprint](https://www.iacr.org/archive/eurocrypt2014/84410245/84410245.pdf), GI19

### Semi-honest MPC

- The Round Complexity of Secure Protocols  
  *Donald Beaver, Silvio Micali, Phillip Rogaway*  
  STOC 1990, [eprint](http://web.cs.ucdavis.edu/~rogaway/papers/bmr90), BMR90
  
- Completeness Theorems for Non-Cryptographic Fault Tolerant Distributed Computation  
  *Michael Ben-Or, Shafi Goldwasser, Avi Wigderson*  
  STOC 1988, [eprint](https://dl.acm.org/doi/10.1145/62212.62213), BGW88

- How to play any mental game?  
  *Oded Goldreich, Silvio Micali, Avi Wigderson*  
  STOC 1987, [eprint](https://dl.acm.org/doi/10.1145/28395.28420), GMW87
  
- How to generate and exchange secrets?  
  *Andrew Chi-Chih Yao*  
  FOCS 1986, [eprint](https://ieeexplore.ieee.org/document/4568207), Yao86

### Malicious MPC

- MHz2k: MPC from HE over Z2k with New Packing, Simpler Reshare, and Better ZKP  
  *Jung Hee Cheon, Dongwoo Kim, Keewoo Lee*  
  Crypto 2021, [eprint](https://eprint.iacr.org/2021/1383), CKLM+21

- MonZa2k: Fast Maliciously Secure Two Party Computation on Z_{2^k}  
  *Dario Catalano, Mario Di Raimondo, Dario Fiore, Irene Giacomelli*  
  PKC 2020, [eprint](https://eprint.iacr.org/2019/211), CRFG20

- Overdrive2k: Efficient Secure MPC over $Z_{2^k}$ from Somewhat Homomorphic Encryption  
  *Emmanuela Orsini, Nigel P. Smart, Frederik Vercauteren*  
  CT-RSA 2020, [eprint](https://eprint.iacr.org/2019/153), OSVJ19

- New Primitives for Actively-Secure MPC over Rings with Applications to Private Machine Learning  
  *Ivan Damgård, Daniel Escudero, Tore Kasper Frederiksen, Marcel Keller, Peter Scholl, Nikolaj Volgushev*  
  SP 2019, [eprint](https://eprint.iacr.org/2019/599), DEF19

- Using TopGear in Overdrive: A more efficient ZKPoK for SPDZ  
  *Carsten Baum, Daniele Cozzo, Nigel P. Smart*  
  SAC 2019, [eprint](https://eprint.iacr.org/2019/035), BCS19

- SPDZ2k: Efficient MPC MOD 2k for dishonest majority  
  *Ronald Cramer, Ivan Damgård, Daniel Escudero, Peter Scholl, Chaoping Xing*  
  Crypto 2018, [eprint](https://eprint.iacr.org/2018/482), SDES+18

- Overdrive: Making SPDZ great again  
  *Marcel Keller, Valerio Pastro, Dragos Rotaru*  
  EuroCrypt 2018, [eprint](https://eprint.iacr.org/2017/1230), KPR18

- High-throughput secure three-party computation for malicious adversaries and an honest majority  
  *Jun Furukawa, Yehuda Lindell, Ariel Nof, Or Weinstein*  
  EuroCrypt 2017, [eprint](https://eprint.iacr.org/2016/944), FLNW17

- MASCOT: Faster Malicious Arithmetic Secure Computation with Oblivious Transfer  
  *Marcel Keller, Emmanuela Orsini, Peter Scholl*  
  CCS 2016, [eprint](https://eprint.iacr.org/2016/505), KOS16

- A New Approach to Practical Active-Secure Two-Party Computation  
  *Jesper Buus Nielsen, Peter Sebastian Nordholt, Claudio Orlandi, Sai Sheshank Burra*  
  Crypto 2012, [eprint](https://eprint.iacr.org/2011/091), NNOB12


## Lattice

### Summaries and Talks

- Crypto Innovation School 2019, [link](https://crypto.sjtu.edu.cn/cis2019/)

### HE

- Homomorphic Encryption for Arithmetic of Approximate Numbers  
  *Jung Hee Cheon, Andrey Kim, Miran Kim, Yong Soo Song*  
  AsiaCrypt 2017, [eprint](https://eprint.iacr.org/2016/421), CKKS17

- Homomorphic Encryption from Learning with Errors: Conceptually-Simpler, Asymptotically-Faster, Attribute-Based  
  *Craig Gentry, Amit Sahai, Brent Waters*  
  Crypto 2013, [eprint](https://eprint.iacr.org/2013/340), GSW13

- Somewhat Practical Fully Homomorphic Encryption  
  *Junfeng Fan, Frederik Vercauteren*  
  Unpublished 2012, [eprint](https://pdfs.semanticscholar.org/531f/8e756ea280f093138788ee896b3fa8ca085a.pdf), BFV12

- Fully Homomorphic Encryption without Bootstrapping  
  *Zvika Brakerski, Craig Gentry, Vinod Vaikuntanathan*  
  Electron. Colloquium Comput. Complex. [eprint](https://eprint.iacr.org/2011/277.pdf), BGV11

- Computing Arbitrary Functions of Encrypted Data  
  *Craig Gentry*  
  Commun. ACM 2009, [eprint](https://crypto.stanford.edu/craig/easy-fhe.pdf), Gen09


