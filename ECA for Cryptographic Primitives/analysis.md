# Efficiency Comparison Analysis for RSA, DSA, ECDSA, HMAC-SHA2 and HMAC-SHA3
**Author**: Bc. Robert Pretschner

**UCO**: XXXXXX

## Introduction
In this analysis, I will be conducting an Efficiency Comparison Analysis of cryptography primitives, such as RSA, DSA, ECDSA, HMAC-SHA2 and HMAC-SHA3.

## Methodology
I have conducted this analysis using a Python script that uses `cryptography` library to implement cryptographic operations for RSA, DSA, ECDSA, HMAC-SHA2, and HMAC-SHA3. The script measures the average execution time for key generation, signature generation, and signature verification over 100 runs to ensure statistical significance. The standard deviation is also calculated to assess the variability in execution times.

I have used two different file sizes were used: a small text file (`alice.txt`) and a larger file (`big_alice.txt, approximately 100MB`) to evaluate the impact of file size on performance. Both SHA2 and SHA3 hash functions were utilized for comparison. The key sizes for RSA and DSA were varied, and different curves were used for ECDSA to study the impact on execution times.

For HMAC, key sizes recommended by the symmetric crypto column (128) in referenced materials were used. These measurements provide insights into the practicality and efficiency of each cryptographic primitive in different scenarios, offering a comprehensive comparison.

## Key Generation Analysis

For the key generation analysis I had to firstly choose the desired key size for each of the primitives. For RSA and DSA it was 3072, for ECDSA it was 256 and for HMAC, it was nonce of length 16 bytes.


### Key Generation
|Primitive | Average time on 100 runs|
| ----------- | ----------- |
| RSA         | 0.176729918000201 seconds|
| DSA         | 1.608165252999679 seconds|
| ECDSA       | 9.857699966232758e-05 seconds|
| HMAC-SHA256 | 6.670002767350525e-07 seconds|
| HMAC-SHA3_256| 3.4000004234258085e-07 seconds|

RSA key generation involves finding large prime numbers and computing their product. This process is moderately fast but still involves significant computational effort, especially as the key size increases. RSA's security is based on the difficulty of factoring large numbers, which necessitates these complex calculations.

DSA also requires the generation of large prime numbers and is similar to RSA in its reliance on the mathematical properties of these numbers. However, DSA tends to be slower in key generation compared to RSA. This difference in speed might be due to the specific requirements of the DSA algorithm for prime number generation and the additional parameters it needs to set up.

ECDSA, using elliptic curve cryptography, demonstrates the fastest key generation among the three. This is because elliptic curve algorithms can achieve the same level of security as RSA and DSA with smaller key sizes, thus requiring less computational work.

In contrast to RSA, DSA, and ECDSA, HMAC key generation is a much simpler process. It involves generating a random byte string of a specified size, which is computationally trivial compared to the complex mathematical operations required for RSA, DSA, and ECDSA key generation. This simplicity results in HMAC having significantly faster key generation times. However, it's important to note that HMAC keys serve a different purpose (symmetric cryptography) compared to the keys in RSA, DSA, and ECDSA (asymmetric cryptography). HMAC keys are used for both creating and verifying the HMAC, unlike the public/private key pairs of RSA, DSA, and ECDSA.


## Signature Generation Analysis


### Signature Generation with SHA256 and small text input file alice.txt

|Primitive | Average time on 100 runs|
| ----------- | ----------- |
| RSA         | 0.0019453800001065246 seconds|
| DSA         | 0.0008504929995979182 seconds|
| ECDSA       |  0.00016012900043278931 seconds|
| HMAC-SHA256 |  0.00011281100021733437 seconds|

### Signature Generation with SHA3-256 and small text input file alice.txt

|Primitive | Average time on 100 runs|
| ----------- | ----------- |
| RSA         | 0.0018683770002098754 seconds|
| DSA         | 0.0008472400000027846 seconds|
| ECDSA       | 0.0001543340003263438 seconds|
| HMAC-SHA3_256| 0.0001106990002153907 seconds|

### Signature Generation with SHA256 and large text input file big_alice.txt

|Primitive | Average time on 100 runs|
| ----------- | ----------- |
| RSA         | 1.08851258699935 seconds|
| DSA         | 1.0954840550003428 seconds|
| ECDSA       | 1.0908667760002573 seconds|
| HMAC-SHA256 |  1.1087199890000192 seconds|

### Signature Generation with SHA3-256 and large text input file big_alice.txt

|Primitive | Average time on 100 runs|
| ----------- | ----------- |
| RSA         |1.1737829450000572 seconds|
| DSA         | 1.1659168640001007 seconds|
| ECDSA       |1.1689143559998774 seconds|
| HMAC-SHA3_256| 1.1598383989997092 seconds|

The signature generation times for small files indicate a clear advantage for ECDSA and HMAC algorithms.

RSA and DSA have relatively slower signature generation times. This might be due to the more complex calculations involved in their signature algorithms.

ECDSA outperforms RSA and DSA, highlighting its efficiency, especially with smaller data.

HMAC-SHA2 and SHA3 show the fastest signature generation times for small files. However, their performance decreases as the file size increases, indicating that they are more sensitive to file size compared to RSA, DSA, and ECDSA.


## Signature Verification Analysis


### Signature Verification with SHA256 and small text input file alice.txt

|Primitive | Average time on 100 runs|
| ----------- | ----------- |
| RSA         | 0.0001950709995435318 seconds|
| DSA         | 0.0007994919997145189 second|
| ECDSA       | 0.00019340000006195623 seconds|
| HMAC-SHA256 |  0.00011000200007401872 seconds|
| HMAC-SHA3_256| 0.0001134360001742607 seconds|

### Signature Verification with SHA3-256 and small text input file alice.txt

|Primitive | Average time on 100 runs|
| ----------- | ----------- |
| RSA         | 0.00023339199906331488 seconds|
| DSA         | 0.000794142000231659 seconds|
| ECDSA       | 0.00015085899998666717 seconds|
| HMAC-SHA256 |  0.00018969700009620284 seconds|
| HMAC-SHA3_256| 0.00011272100025962573 seconds|

### Signature Verification with SHA256 and large text input file big_alice.txt

|Primitive | Average time on 100 runs|
| ----------- | ----------- |
| RSA         | 1.0964253249998728 seconds|
| DSA         | 1.1021207209997375 seconds|
| ECDSA       | 1.0934222939999017 seconds|
| HMAC-SHA256 |  1.1146582770001259 seconds|

### Signature Verification with SHA3-256 and large text input file big_alice.txt

|Primitive | Average time on 100 runs|
| ----------- | ----------- |
| RSA         |1.1315943829996105 seconds|
| DSA         | 1.1307057229998463 seconds|
| ECDSA       | 1.1291547399998672 seconds|
| HMAC-SHA3_256| 1.1588495819999662 seconds|

RSA and ECDSA demonstrate quick verification times, with ECDSA slightly outperforming RSA. This suggests their suitability in scenarios where rapid verification is essential.

DSA has a higher verification time compared to RSA and ECDSA, which might make it less preferable in time-sensitive cases.

HMAC-SHA2 and SHA3 show competitive verification times, particularly for small files. Their performance remains consistent with the increase in file size, indicating their robustness in handling larger data for integrity checks.



## Task 5 - Standard deviation and different key sizes
### Key Generation
|Primitive | Standard Deviation|
| ----------- | ----------- |
| RSA         | 0.21333093200058362 seconds|
| DSA         | 0.8364364863074402 seconds|
| ECDSA       | 0.0010477422163794052 seconds|

### Signature Generation
|Primitive | Standard Deviation|
| ----------- | ----------- |
| RSA         | 0.001526543866344295 seconds|
| DSA         | 0.00022989172839056368 seconds|
| ECDSA       | 0.0010965751141866075 seconds|

### Signature Verification
|Primitive | Standard Deviation|
| ----------- | ----------- |
| RSA         | 0.00010333257311837157 seconds|
| DSA         | 0.00022427659292420974 seconds|
| ECDSA       | 0.0008453870863564144 seconds|

Keys used for this analysis were of size 2048 and 3072 for DSA; 2048, 3072 and 4096 for RSA and for ECDSA, I have used curves ``` ec.SECP256R1(), ec.SECP384R1() and ec.SECP521R1(). ```

The standard deviation in key generation times suggests that RSA and DSA's performance is more variable compared to ECDSA. 

Larger key sizes in RSA tend to increase the time, as expected due to the computational complexity of generating large prime numbers.


This variation in RSA and DSA might be due to the differing computational complexities of generating large prime numbers of varying sizes. In contrast, ECDSA's consistent performance across different curves points to its inherent efficiency in key generation.

The signature generation and verification times also exhibit variation with different key sizes, especially for RSA and ECDSA. This variability highlights the impact of key size on the computational intensity of these operations.

## Comparative Analysis
This analysis provides information about the performance of RSA, DSA, ECDSA, HMAC-SHA2, and HMAC-SHA3 cryptographic primitives. The performance is evaluated based on key generation, signature generation, and signature verification times, with both small and large files, using SHA2 and SHA3 as hash functions.

### Key Generation
RSA and DSA show moderate to high key generation times due to the complexity involved in generating large prime numbers and the subsequent mathematical computations.
ECDSA demonstrates a significant advantage in key generation speed due to the nature of elliptic curve cryptography, which requires smaller keys for equivalent security levels compared to RSA and DSA.
The generation of HMAC keys is significantly faster compared to RSA, DSA, and ECDSA. This is because HMAC key generation is essentially the generation of a random byte string of a specified size, which is a computationally simpler process than generating cryptographic keys based on mathematical properties like prime number generation or elliptic curve points.

### Signature Generation

For small files, ECDSA and HMAC algorithms (both SHA2 and SHA3 variants) show very fast signature generation times, significantly outperforming RSA and DSA. This trend changes with large files, where all algorithms demonstrate similar performance. The increase in time for HMAC algorithms with large files suggests that their efficiency is more sensitive to file size than RSA, DSA, and ECDSA.

### Signature Verification

Signature verification times are relatively quick across all algorithms for small files, with RSA, ECDSA, and HMAC showing particularly fast performance. For large files, all algorithms exhibit a substantial increase in verification time, indicating that file size impacts the verification process significantly.

## Conclusion

This analysis highlights the strengths and limitations of each cryptographic primitive in different scenarios. ECDSA stands out for key generation and verification efficiency, while HMAC excels in handling smaller data sizes. RSA offers a good balance for various operations but is not the fastest. The choice of algorithm should be guided by the specific requirements of the use case, considering factors such as file size, need for fast key generation, and computational resources.


## Use Case Recommendations
- **RSA**: Its balance between key generation time and signature verification efficiency makes it ideal for environments where a compromise between security and performance is necessary. I think RSA is well-suited for secure email, secure remote access, and web-based authentication systems.

- **DSA**: It is suitable for systems where keys can be pre-generated or where the delay in key generation is not a significant concern. It's often used in secure document signing and software distribution, where the integrity of the signature is more critical than the speed of key generation.

- **ECDSA**: Its fast key generation and verification times make it suitable for real-time applications and systems requiring frequent key generation. ECDSA is ideal for IoT devices, mobile applications, smart cards and cryptocurrencies.

- **HMAC**: It is particularly effective in systems where both parties can securely manage and store a shared secret key. HMAC is highly efficient for verifying data integrity in API authentication, web applications, and network protocol design.

## References
- https://www.okta.com/identity-101/rsa-encryption/
- https://www.simplilearn.com/tutorials/cryptography-tutorial/digital-signature-algorithm
- https://www.techtarget.com/searchsecurity/definition/Hash-based-Message-Authentication-Code-HMAC
- https://www.hypr.com/security-encyclopedia/elliptic-curve-digital-signature-algorithm
- https://en.wikipedia.org/wiki/Digital_Signature_Algorithm
- https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
- https://en.wikipedia.org/wiki/HMAC
- https://en.wikipedia.org/wiki/RSA_(cryptosystem)

