/* caam_driver.h
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * https://www.wolfssl.com
 */

#ifndef CAAM_DRIVER_H
#define CAAM_DRIVER_H

#if (defined(__QNX__) || defined(__QNXNTO__))
    int InitCAAM(void);
    #include "caam_qnx.h"
#endif
#if (defined(__INTEGRITY) || defined(INTEGRITY))
    #define CAAM_BASE 0xf2100000
    #define CAAM_PAGE 0xf0100000
#endif


#define CAAM_PAGE_MAX 6

/* max size of 64 word32's */
#define CAAM_DESC_MAX 256

#ifndef CAAM_JOBRING_SIZE
#define CAAM_JOBRING_SIZE 1
#endif

/******************************************************************************
  Basic Descriptors
  ****************************************************************************/

/* descriptor commands */
#define CAAM_KEY      0x00000000
#define CAAM_LOAD     0x10000000
#define CAAM_LOAD_CTX 0x10200000
#define CAAM_IMM      0x00800000
#define CAAM_FIFO_L   0x20000000
#define CAAM_FIFO_S   0x60000000
#define CAAM_FIFO_S_SKEY 0x60260000
#define CAAM_STORE       0x50000000
#define CAAM_STORE_CTX   0x50200000
#define CAAM_MOVE        0x78000000
#define CAAM_OP          0x80000000
#define CAAM_SIG         0x90000000
#define CAAM_JUMP        0xA0000000
#define CAAM_SEQI        0xF0000000/* SEQ in  */
#define CAAM_SEQO        0xF8000000/* SEQ out */
#define CAAM_HEAD        0xB0800000
#define CAAM_NWB         0x00200000

    /* PROTOCOL OPERATION command */
#define CAAM_PROT_UNIDI 0
#define CAAM_BLOB_ENCAP 0x07000000
#define CAAM_BLOB_DECAP 0x06000000
#define CAAM_PKHA_OP    0x01000000

#define CAAM_OPID_BLOB  0x000D0000

/* algorithms modes and types */
#define CAAM_CLASS1 0x02000000/* i.e. AES, PKHA */
#define CAAM_CLASS2 0x04000000/* i.e. hash algos */

#define CAAM_ENC    0x00000001
#define CAAM_DEC    0x00000000
#define CAAM_ALG_INIT   0x00000004
#define CAAM_ALG_INITF  0x0000000C
#define CAAM_ALG_UPDATE 0x00000000
#define CAAM_ALG_FINAL  0x00000008

    /* AES 10h */
#define CAAM_AESCTR 0x00100000
#define CAAM_AESCBC 0x00100100
#define CAAM_AESECB 0x00100200
#define CAAM_AESCFB 0x00100300
#define CAAM_AESOFB 0x00100400
#define CAAM_CMAC   0x00100600
#define CAAM_AESCCM 0x00100800

    /* HASH 40h */
#define CAAM_MD5    0x00400000
#define CAAM_SHA    0x00410000
#define CAAM_SHA224 0x00420000
#define CAAM_SHA256 0x00430000
#define CAAM_SHA384 0x00440000
#define CAAM_SHA512 0x00450000

    /* HMAC 40h + 10 AAI */
#define CAAM_HMAC_MD5    0x00400010
#define CAAM_HMAC_SHA    0x00410010
#define CAAM_HMAC_SHA224 0x00420010
#define CAAM_HMAC_SHA256 0x00430010
#define CAAM_HMAC_SHA384 0x00440010
#define CAAM_HMAC_SHA512 0x00450010

/* ECDSA ECDSEL (pre defined flags for ECDSA parameters i.e. order) */
#define CAAM_ECDSEL_SHIFT 7
#define CAAM_ECDSA_PD 0x00400000
#define CAAM_ECDSA_KEYGEN_PD 0x02000000
#define CAAM_ECDSA_P192 (0x00 << CAAM_ECDSEL_SHIFT)
#define CAAM_ECDSA_P224 (0x01 << CAAM_ECDSEL_SHIFT)
#define CAAM_ECDSA_P256 (0x02 << CAAM_ECDSEL_SHIFT)
#define CAAM_ECDSA_P384 (0x03 << CAAM_ECDSEL_SHIFT)
#define CAAM_ECDSA_P521 (0x04 << CAAM_ECDSEL_SHIFT)

#define CAAM_ECDSA_BRAINPOOL_P256 (0x0B << CAAM_ECDSEL_SHIFT)

    /* PKHA Operation ID ECDSA */
#define CAAM_ECDSA_KEYPAIR 0x00140000
#define CAAM_ECDSA_SIGN    0x00150000
#define CAAM_ECDSA_VERIFY  0x00160000
#define CAAM_ECDSA_ECDH    0x00170000

#define CAAM_ECDSA_MESREP_HASHED (0x10 << 7)

    /* key encryption bit */
#define CAAM_PKHA_ECC 0x00000002
#define CAAM_PKHA_ENC_PRI_AESCBC 0x00000004
#define CAAM_PKHA_ENC_PRI_AESCCM (0x00000010 | CAAM_PKHA_ENC_PRI_AESCBC)
#define CAAM_PKHA_NO_TIMING_RESISTANCE 0x40000000
#define CAAM_LOAD_BLACK_KEY 0x500000

    /* PKHA RSA */
#define CAAM_OPID_RSA_ENCRYPT 0x00180000
#define CAAM_OPID_RSA_DECRYPT 0x00190000


#define CAAM_MD5_CTXSZ (16 + 8)
#define CAAM_SHA_CTXSZ (20 + 8)
#define CAAM_SHA224_CTXSZ (32 + 8)
#define CAAM_SHA256_CTXSZ (32 + 8)
#define CAAM_SHA384_CTXSZ (64 + 8)
#define CAAM_SHA512_CTXSZ (64 + 8)

    /* RNG 50h */
#define CAAM_RNG 0x00500000

    /* Used to get raw entropy from TRNG */
#define CAAM_ENTROPY 0x00500001

#define FIFOL_TYPE_MSG 0x00100000
#define FIFOL_TYPE_AAD 0x00300000
#define FIFOL_TYPE_FC1 0x00010000
#define FIFOL_TYPE_LC1 0x00020000
#define FIFOL_TYPE_LC2 0x00040000

#define FIFOS_TYPE_MSG 0x00300000

/* continue bit set if more output is expected */
#define CAAM_FIFOS_CONT 0x00800000

#define CAAM_PAGE_SZ 4096

/* RNG Registers */
#define CAAM_RTMCTL      0X0600
#define CAAM_RTSDCTL     0X0610
#define CAAM_RTFRQMIN    0X0618
#define CAAM_RTFRQMAX    0X061C
#define CAAM_RDSTA       0X06C0
#define CAAM_RTSTATUS    0x063C
#define CAAM_RDINT0      0x06D0

/* each of the following 11 RTENT registers are an offset of 4 from RTENT0 */
#define CAAM_RTENT0      0x0640
#define CAAM_RTENT11     0x066C /* Max RTENT register */
#define CAAM_RTENT_MAX   0x067C

/* RNG Masks/Values */
#ifndef CAAM_ENT_DLY
    #define CAAM_ENT_DLY   1200 /* @TODO lower value may gain performance */
#endif
#define CAAM_PRGM      0x00010000 /* Set RTMCTL to program state */
#define CAAM_TRNG      0x00000020 /* Set TRNG access */
#define CAAM_CTLERR    0x00001000
#define CAAM_ENTVAL    0x00000400 /* checking RTMCTL for entropy ready */

/* Input Job Ring Registers */
#define CAAM_IRBAR0      0x1004
    //0x1004
#define CAAM_IRSR0       0x100C
#define CAAM_IRJAR0      0x101C

#define CAAM_IRBAR2      0x3000
#define CAAM_IRSR2       0x300C
#define CAAM_IRJAR2      0x301C
#define CAAM_IRSAR_JR2   0x3014



/* Output Job Ring Registers */
#define CAAM_ORBAR0      0x1024
    //0x1024
#define CAAM_ORSR0       0x102C
#define CAAM_ORJAR0      0x103C


#define CAAM_ORBAR2      0x3024
    //0x1024
#define CAAM_ORSR2       0x302C
#define CAAM_ORJAR2      0x303C

#define JRCFGR_JR0_LS    0x1054

/* Status Registers */
#define CAAM_STATUS      0x0FD4
#define CAAM_VERSION_MS  0x0FE8
#define CAAM_VERSION_LS  0x0FEC
#define CAMM_SUPPORT_MS  0x0FF0
#define CAMM_SUPPORT_LS  0x0FF4

#define CAAM_SM_CMD 0x1BE4
#define CAAM_SM_SMPO 0x1FBC
#define CAAM_SM_SMVID_MS 0x1FD8
#define CAAM_SM_SMVID_LS 0x1FDC
#define CAAM_SM_STATUS 0x1BEC
#define CAAM_SM_CSP   0x00008000
#define CAAM_SM_SMAP_LOCK 0x00002000
#define CAAM_SM_SMAG_LOCK 0x00001000
#define CAAM_SM_ALL_RW 0x000000FF

#define CAAM_C1DSR_LS    0x8014
#define CAAM_C1MR        0x8004


/* output FIFO  is 16 entries deep and each entry has a two 4 byte registers */
#define CAAM_FIFOO_MS    0x87F0
#define CAAM_FIFOO_LS    0x87F4

/* input FIFO is 16 entries deep with each entry having two 4 byte registers
   All data written to it from IP bus should be in big endian format */
#define CAAM_FIFOI_LS    0x87E0

/* offset of 4 with range 0 .. 13 */
#define CAAM_CTX1        0x8100
#define CAAM_CTRIV       CAAM_CTX1 + 8 /* AES-CTR iv is in 2 and 3 */
#define CAAM_CBCIV       CAAM_CTX1     /* AES-CBC iv is in 1 and 2 */


    /* debugging registers */
#define CAAM_DECORR 0x009C /* used to set DECO into debug mode */
#define CAAM_DODJR  0x8E00 /* for hung operations */
#define CAAM_DOJQCR_MS 0x8800
#define CAAM_DOOPSTA_MS 0x8810 /* DECO operation status register */
#define CAAM_DODAR  0x8808 /* address of current descriptor */
#define CAAM_DODESB 0x8A00 /* 64 registers that hold the current descriptor buffer */


#define JRINTR_JR0 0x104C
#define JRINTR_JR1 0x204C
#define JRINTR_JR2 0x304C

#define CAAM_SINGLE_STEP_MODE 0x40000000
#define CAAM_STEP 0x80000000

/* Port layer for CAAM driver, functions defined in caam_<env>.c */
unsigned int CAAM_READ(unsigned int reg);
void CAAM_WRITE(unsigned int reg, unsigned int in);
int CAAM_SET_BASEADDR(void);
void CAAM_UNSET_BASEADDR(void);
unsigned int CAAM_ADR_TO_PHYSICAL(void* in, int inSz);
void* CAAM_ADR_MAP(unsigned int in, int inSz, unsigned char copy);
void CAAM_ADR_UNMAP(void* vaddr, unsigned int out, int outSz,
        unsigned char copy);
int CAAM_ADR_SYNC(void* vaddr, int sz);
CAAM_ADDRESS CAAM_ADR_TO_VIRTUAL(CAAM_ADDRESS in, int length);

#ifndef WOLFSSL_CAAM_BUFFER
#define WOLFSSL_CAAM_BUFFER
typedef struct CAAM_BUFFER {
    int BufferType;
    CAAM_ADDRESS TheAddress;
    int Length;
} CAAM_BUFFER;
#endif
unsigned int caamReadRegister(unsigned int reg);
void caamWriteRegister(unsigned int reg, unsigned int in);
int SynchronousSendRequest(int type, unsigned int args[4], CAAM_BUFFER *buf, int sz);
int CleanupCAAM(void);


/* Driver API that can be called by caam_<env>.c port layers */
typedef struct DESCSTRUCT DESCSTRUCT;

int caamKeyCover(DESCSTRUCT *desc, int sz, unsigned int args[4]);
int caamTRNG(unsigned char *out, int outSz);
int caamECDSA_ECDH(DESCSTRUCT *desc, int sz, unsigned int args[4]);
int caamECDSASign(DESCSTRUCT *desc, int sz, unsigned int args[4]);
int caamECDSAVerify(DESCSTRUCT *desc, CAAM_BUFFER *buf, int sz,
        unsigned int args[4]);
int caamECDSAMake(DESCSTRUCT *desc, CAAM_BUFFER *buf, unsigned int args[4]);


int caamAesCmac(DESCSTRUCT *desc, int sz, unsigned int args[4]);
int caamBlob(DESCSTRUCT *desc);

CAAM_ADDRESS caamGetPartition(unsigned int part, int partSz, unsigned int flag);
int caamFreePart(unsigned int part);
int caamFindUnusuedPartition(void);



void caamDescInit(DESCSTRUCT* desc, int type, unsigned int args[4],
        CAAM_BUFFER* buf, int sz);


/* CAAM descriptor */
#define DESC_COUNT 1
#define MAX_BUF 20
#define BUFFER_COUNT (MAX_BUF * DESC_COUNT)

/* CAAM descriptors can only be 64 unsigned ints */
#define MAX_DESC_SZ 64

/* 64 byte buffer for when data crosses a page boundary */
#define ALIGN_BUF 16

/* MAX_CTX is 64 bytes (sha512 digest) + 8 bytes (CAAM length value) */
#define MAX_CTX 18

#define MIN_READ_REG CAAM_BASE
#define MAX_READ_REG (CAAM_BASE + 0x00010000)

struct buffer {
    CAAM_ADDRESS data;
    CAAM_ADDRESS dataSz;
};

struct DESCSTRUCT {
#if defined(__INTEGRITY) || defined(INTEGRITY)
    struct IORequestStruct TheIORequest;
#endif
    struct CAAM_DEVICE*    caam;
    struct buffer          buf[MAX_BUF]; /* buffers holding data input address */
    unsigned int           desc[MAX_DESC_SZ]; /* max size of 64 word32 */
    unsigned int           aadSzBuf[4];       /* Formatted AAD size for CCM */
    unsigned int           alignBuf[ALIGN_BUF]; /* 64 byte buffer for non page
                                                   align */
    unsigned int           iv[MAX_CTX]; /* AES IV and also hash state */
    unsigned int           ctxBuf[MAX_CTX]; /* key */
    CAAM_ADDRESS           output; /* address to output buffer */
    CAAM_ADDRESS           ctxOut; /* address to update buffer holding state */
    Value                  alignIdx;/* index for align buffer */
    Value                  idx;     /* index for descriptor buffer */
    Value                  headIdx; /* for first portion of descriptor buffer */
    Value                  lastIdx; /* for last portion of descriptor buffer */
    Value                  outputIdx; /* idx to output buffer in "buf" */
    Value                  inputSz;   /* size of input buffer */
    Value                  ctxSz;     /* size of CTX/Key buffer */
    Value                  aadSz;     /* AAD size for CCM */
    Value                  startIdx;  /* for telling header where to start */
    Value                  lastFifo;
    Value                  type;
    Value                  state;
    Value                  DescriptorCount;
    Boolean                running; /* True if building/running descriptor is
                                       in process */
};

/* wolfSSL specific flags */
#define CAAM_FIND_PART 0xFFFFFFFF
#define CAAM_GET_PART 0xFFFFFFFE
#define CAAM_FREE_PART 0xFFFFFFFD
#define CAAM_READ_PART 0xFFFFFFFC
#define CAAM_WRITE_PART 0xFFFFFFFB


#define MAX_ECDSA_VERIFY_ADDR 8
#define MAX_ECDSA_SIGN_ADDR 8
#define BLACK_KEY_MAC_SZ 16
#define BLACK_BLOB_KEYMOD_SZ 16
#define RED_BLOB_KEYMOD_SZ 8
#endif /* CAAM_DRIVER_H */
