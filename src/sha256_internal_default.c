/*
 * SPDX-FileCopyrightText: 2023 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Frans van Dorsselaer
 */

/**
 * @file
 * @brief
 * Default implementation of SHA-256.
 */

#include "config.h"

#include <assert.h>

#if !XMSS_ENABLE_SHA256
#   error "SHA-256 is disabled, so SHA-256 related source files must not be compiled."
#endif
#if XMSS_ENABLE_SHA256_GENERIC
#   error "SHA-256 uses generic interface, so SHA-256 related internal source files must not be compiled."
#endif

/*
 * The terminology and naming convention in this file follow that of the NIST FIPS 180-4 standard;
 *      this includes function names, descriptions, parameter names, loop index names, etc.
 * This allows for one-to-one verification of the implementation.
 *
 * Symbolic operations in the standard, see NIST FIPS 180-4, Section 2.2. are mapped one-to-one
 *      to the corresponding C operator. For example, "Bitwise AND operation" maps to the & operator.
 *
 * Note that for this implementation, some parameters in the standard have a fixed, hard-coded value.
 * For example, the number of bits in a word 'w' is always 32 for SHA-256. Since we use the standard C type uint32_t
 * to represent such values (which already includes the explicit number 32), we also explicitly use 32 where the
 * standard denotes 'w' to avoid confusion. Defining a constant 'w' would imply that the parameter could be changed,
 * whereas using uint32_t demands that it is in fact 32.
 */

#include <string.h>

#include "libxmss.h"
#if LIBXMSS
#   include "types.h"
    // Forward-declare our implementation as static before including the public header.
    LIBXMSS_STATIC
    void xmss_sha256_process_block(XmssNativeValue256 *Hi, const uint32_t *Mi);
#endif

#include "override_sha256_internal.h"

/**
 * @brief
 * The right shift operation.
 *
 * @details
 * See NIST FIPS 180-4, Section 3.2 (3).
 *
 * Input validation is omitted for performance reasons.
 *
 * @param[in] n   The number of bits to shift; must be 0 <= n < 32.
 * @param[in] x   The input number.
 *
 * @returns   The result of the right shift operation.
 */
static inline uint32_t SHR(const uint32_t n, const uint32_t x)
{
    return x >> n;
}

/**
 * @brief
 * The rotate right (circular right shift) operation.
 *
 * @details
 * See NIST FIPS 180-4, Section 3.2 (3).
 *
 * Input validation is omitted for performance reasons.
 *
 * @param[in] n   The number of bits to rotate; must be 0 <= n < 32.
 * @param[in] x   The input number.
 *
 * @returns   The result of the rotate right operation.
 */
static inline uint32_t ROTR(const uint32_t n, const uint32_t x)
{
    return (uint32_t)((x >> n) | (x << (32 - n)));
}

/**
 * @brief
 * The $\\textit{Ch}(x,y,z)$ function of the SHA-256 standard; no further description available.
 *
 * @details
 * See NIST FIPS 180-4, Section 4.1.2.
 *
 * Input validation is omitted for performance reasons.
 *
 * @param[in] x   The first input parameter to $\\textit{Ch}(x,y,z)$.
 * @param[in] y   The second input parameter to $\\textit{Ch}(x,y,z)$.
 * @param[in] z   The third input parameter to $\\textit{Ch}(x,y,z)$.
 *
 * @returns   The result of the $\\textit{Ch}(x,y,z)$ function of the SHA-256 standard.
 */
static inline uint32_t Ch(const uint32_t x, const uint32_t y, const uint32_t z)
{
    return (x & y) ^ (~x & z);
}

/**
 * @brief
 * The $\\textit{Maj}(x,y,z)$ function of the SHA-256 standard; no further description available.
 *
 * @details
 * See NIST FIPS 180-4, Section 4.1.2.
 *
 * Input validation is omitted for performance reasons.
 *
 * @param[in] x   The first input parameter to $\\textit{Maj}(x,y,z)$.
 * @param[in] y   The second input parameter to $\\textit{Maj}(x,y,z)$.
 * @param[in] z   The third input parameter to $\\textit{Maj}(x,y,z)$.
 *
 * @returns   The result of the $\\textit{Maj}(x,y,z)$ function of the SHA-256 standard.
 */
static inline uint32_t Maj(const uint32_t x, const uint32_t y, const uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

/**
 * @brief
 * The $\\Sigma_0(x)$ function of the SHA-256 standard; no further description available.
 *
 * @details
 * See NIST FIPS 180-4, Section 4.1.2.
 *
 * Input validation is omitted for performance reasons.
 *
 * @param[in] x   The input parameter to $\\Sigma_0(x)$.
 *
 * @returns   The result of the $\\Sigma_0(x)$ function of the SHA-256 standard.
 */
static inline uint32_t SIGMA0(const uint32_t x)
{
    return ROTR(2, x) ^ ROTR(13, x) ^ ROTR(22, x);
}

/**
 * @brief
 * The $\\Sigma_1(x)$ function of the SHA-256 standard; no further description available.
 *
 * @details
 * See NIST FIPS 180-4, Section 4.1.2.
 *
 * Input validation is omitted for performance reasons.
 *
 * @param[in] x   The input parameter to $\\Sigma_1(x)$.
 *
 * @returns   The result of the $\\Sigma_1(x)$ function of the SHA-256 standard.
 */
static inline uint32_t SIGMA1(const uint32_t x)
{
    return ROTR(6, x) ^ ROTR(11, x) ^ ROTR(25, x);
}

/**
 * @brief
 * The $\\sigma_0(x)$ function of the SHA-256 standard; no further description available.
 *
 * @details
 * See NIST FIPS 180-4, Section 4.1.2.
 *
 * Input validation is omitted for performance reasons.
 *
 * @param[in] x   The input parameter to $\\sigma_0(x)$.
 *
 * @returns   The result of the $\\sigma_0(x)$ function of the SHA-256 standard.
 */
static inline uint32_t sigma0(const uint32_t x)
{
    return ROTR(7, x) ^ ROTR(18, x) ^ SHR(3, x);
}

/**
 * @brief
 * The $\\sigma_1(x)$ function of the SHA-256 standard; no further description available.
 *
 * @details
 * See NIST FIPS 180-4, Section 4.1.2.
 *
 * Input validation is omitted for performance reasons.
 *
 * @param[in] x   The input parameter to $\\sigma_1(x)$.
 *
 * @returns   The result of the $\\sigma_1(x)$ function of the SHA-256 standard.
 */
static inline uint32_t sigma1(const uint32_t x)
{
    return ROTR(17, x) ^ ROTR(19, x) ^ SHR(10, x);
}

/**
 * @brief
 * The constant values K[t] to be used for the iteration t of the hash computation.
 *
 * @details
 * See NIST FIPS 180-4, Section 4.2.2.
 *
 * These values represent the first thirty-two bits of the fractional parts of the cube roots of the first
 * sixty-four prime numbers.
 */
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

LIBXMSS_STATIC
void xmss_sha256_process_block(XmssNativeValue256 *const Hi, const uint32_t *const Mi)
{
    assert(Hi != NULL);
    assert(Mi != NULL);

    /*
     * See: NIST FIPS 180-4, Section 6.2.2.
     *
     * This is the part inside the outer loop.
     */

    /* For performance reasons, the local variables are defined uninitialized and not explicitly set to 0. */

    uint32_t W[64];
    /*
     * The working variable a through h are defined as an array so we can use memcpy() for initialization
     * and so we can iterate over them in a loop.
     */
    uint32_t working_variables[8];
#ifndef DOXYGEN
#define a working_variables[0]
#define b working_variables[1]
#define c working_variables[2]
#define d working_variables[3]
#define e working_variables[4]
#define f working_variables[5]
#define g working_variables[6]
#define h working_variables[7]
#endif

    /* 1. Prepare the message schedule, {Wt} */
    memcpy(W, Mi, 16 * sizeof(uint32_t));
    for (unsigned int t = 16; t <= 63; ++t) {
        W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
    }

    /* 2. Initialize the eight working variables */
    memcpy(working_variables, Hi, sizeof(working_variables));

    /* 3. <NIST does not provide a description for this step> */
    for (unsigned int t = 0; t <= 63; ++t) {
        uint32_t T1 = h + SIGMA1(e) + Ch(e, f, g) + K[t] + W[t];
        uint32_t T2 = SIGMA0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    /* 4. Compute the next iteration of the intermediate hash value */
    for (unsigned int j = 0; j <= 7; ++j) {
        Hi->data[j] += working_variables[j];
    }
}

#ifndef DOXYGEN
#undef a
#undef b
#undef c
#undef d
#undef e
#undef f
#undef g
#undef h
#endif
