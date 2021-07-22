/* Configuration */
#define IPHONE  /* Needed for Xcode */
#define HAVE_HASHDRBG
#define HAVE_AESGCM
#define WOLFSSL_SHA512
#define WOLFSSL_SHA384

#ifdef HAVE_FIPS
    #define NO_MD4
    #define NO_HC128
    #define NO_RABBIT
    #define NO_DSA
    #define NO_PWDBASED
#else
    #define WC_RSA_BLINDING
    #define USE_FAST_MATH
    #define TFM_TIMING_RESISTANT
    #define HAVE_ECC
    #define ECC_TIMING_RESISTANT
#endif
/**
 Both arch cannot be compile together do 1 by 1 or via build script
for 64 bit enable macro --> WOLFSSL_SP_ARM64_ASM
for 32 bit enable macro --> WOLFSSL_SP_ARM32_ASM
 */
