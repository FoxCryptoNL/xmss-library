/*
 * SPDX-FileCopyrightText: 2022 Fox Crypto B.V.
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: Thomas Schaap
 */

/**
 * @file
 * @brief
 * Public API for the XMSS signing library.
 */

#pragma once

#ifndef XMSS_SIGNING_H_INCLUDED
/** @private @brief Include guard. */
#define XMSS_SIGNING_H_INCLUDED

#include "structures.h"
#include "types.h"

/* === Library initialization === */

/**
 * @brief
 * Initialize a new instantiation of the signature key and generation library.
 *
 * @details
 * Memory Management
 * =================
 *
 * The library needs to allocate and deallocate memory during several calls. The user of the library must provide a
 * #XmssReallocFunction and #XmssFreeFunction implementation. This allows, for example, an implementation that does not
 * use any dynamic memory allocations. If dynamic memory allocation is available on the target platform, then one can
 * simply pass the standard C library implementations for `realloc()` and `free()`.
 *
 * Whenever a function in this library has a pointer-to-pointer-to-struct parameter, it will allocate memory for that
 * structure using the provided pointer's initial value as input pointer to the user-provided #XmssReallocFunction. For
 * every pointer-to-pointer-to-struct parameter a single call to the user-provided #XmssReallocFunction will be made.
 *
 * ```
 *     XmssKeyContext *key_context = NULL;
 *     xmss_load_private_key(&key_context, private_key, key_usage, context);
 *     // This would perform one call to realloc(NULL, XMSS_KEY_CONTEXT_SIZE).
 *
 *     XmssKeyContext *initialized_key_context = 0x12345678;
 *     xmss_load_private_key(&initialized_key_context, private_key, key_usage, context);
 *     // This would perform one call to realloc(0x12345678, XMSS_KEY_CONTEXT_SIZE).
 * ```
 *
 * Allocated memory returned via a pointer-to-pointer-to-struct parameter changes ownership to the caller: the caller is
 * responsible for its deallocation. This can be done implicitly by a later call to a library function that explicitly
 * promises to deallocate the memory, or by explicitly calling the correct deallocation function for the type.
 *
 * Deallocating memory is only done by library calls when explicitly mentioned, for example by
 * xmss_generate_public_key(), and by the structure deallocation functions. If memory needs to be deallocated, the
 * user-provided #XmssFreeFunction will be called once with a non-NULL argument for every structure that needs to be
 * deallocated.
 *
 * Non-standard implementations for #XmssReallocFunction and #XmssFreeFunction can be used to create a library
 * instantiation that only uses static memory allocations.
 *
 * ```
 *     void *static_realloc(void *ptr, size_t size) { return ptr; }
 *     void static_free(void *ptr) {}
 *
 *     uint8_t context[XMSS_SIGNING_CONTEXT_SIZE];
 *     XmssSigningContext *context_ptr = context;
 *
 *     xmss_context_initialize(&context_ptr, parameter_set, &static_realloc, &static_free, NULL);
 *     // Because static_realloc is passed as the realloc argument, the previously allocated context is 'reallocated'
 *     // by calling the static_realloc function, which does nothing. No dynamic memory is used.
 *     // The XMSS_SIGNING_CONTEXT_SIZE macro allows allocating memory for the structure, even though its contents are
 *     // opaque and its size unknown to the caller.
 * ```
 *
 * @param[in,out] context       The context required for further use of the library. This will only point to a fully
 *                              initialized signing context upon success. Upon failure this will point to NULL and any
 *                              memory allocated during this function's execution has been freed again.
 * @param[in] parameter_set     The XMSS parameter set that this library instantiation will support.
 * @param[in] custom_realloc    The library will use this function to allocate memory needed for new structures.
 * @param[in] custom_free       The library will use this function to deallocate previously allocated memory.
 * @param[in] zeroize           If this is not NULL, the library will use this function to erase sensitive data.
 *                              Special care must be taken to select a function that can not be optimized away by the
 *                              compiler. No such function exists in pure C99, but the default implementation offers
 *                              a best-effort solution that is known to work on almost all compilers.
 * @retval #XMSS_OKAY   Success.
 * @retval #XMSS_ERR_NULL_POINTER   `context`, `custom_realloc`, or `custom_free` is NULL.
 * @retval #XMSS_ERR_ALLOC_ERROR    Memory allocation caused an error.
 * @retval #XMSS_ERR_INVALID_ARGUMENT   An unsupported parameter set is specified.
 * @retval #XMSS_ERR_FAULT_DETECTED A bit error was detected.
 *                                  (Note that bit errors can also cause different errors or segfaults.)
 */
XmssError xmss_context_initialize(XmssSigningContext **context, XmssParameterSetOID parameter_set,
    XmssReallocFunction custom_realloc, XmssFreeFunction custom_free, XmssZeroizeFunction zeroize);

/* === Key loading === */

/**
 * @brief
 * Load a private key partition from storage.
 *
 * @details
 * A private key is stored in two parts, the stateless part and the stateful part. Both parts are required to be able to
 * use the key.
 *
 * When the private key partition has successfully been loaded, the blobs should be (securely) erased from memory. This
 * prevents possible misuse that could lead to fatal key reuse.
 *
 * Loading the private key is not sufficient to be able to generate signatures. The public key must also be loaded or
 * generated.
 *
 * This function is bit error resilient in that a singe random bit error cannot cause it to load an invalid private key,
 * a stateful part that does not correspond to the stateless part, or a private key with a parameter set that does not
 * match `context`.
 *
 * @see xmss_partition_signature_space() for more information on private key partitions.
 *
 * @param[in,out] key_context   The context required for further use of the library with this key.
 * @param[in] private_key   The stateless part of the private key. This must be a valid XmssPrivateKeyStatelessBlob.
 * @param[in] key_usage     The stateful part of the private key. This must be a valid XmssPrivateKeyStatefulBlob that
 *                          was previously created for the stateless private key part passed in private_key.
 * @param[in] context   The initialized context of the library. This must be initialized for the parameter set that was
 *                      used to create the private key. After xmss_load_private_key() successfully returns this
 *                      context may be deallocated: only key_context is needed for further use of the library.
 * @retval #XMSS_OKAY    Success.
 * @retval #XMSS_ERR_NULL_POINTER   A NULL pointer was passed.
 * @retval #XMSS_ERR_ARGUMENT_MISMATCH  `private_key` does not contain a private key that was generated for the
 *                                      parameter set for which context was initialized, or the data in `private_key`
 *                                      and `key_usage` is not part of the same private key.
 * @retval #XMSS_ERR_ALLOC_ERROR    Memory allocation caused an error.
 * @retval #XMSS_ERR_INVALID_BLOB   The data in `private_key` or `key_usage` is not valid.
 * @retval #XMSS_ERR_BAD_CONTEXT    `context` is not a correctly initialized context.
 * @retval #XMSS_ERR_FAULT_DETECTED A bit error was detected.
 *                                  (Note that bit errors can also cause different errors or segfaults.)
 */
XmssError xmss_load_private_key(XmssKeyContext **key_context, const XmssPrivateKeyStatelessBlob *private_key,
    const XmssPrivateKeyStatefulBlob *key_usage, const XmssSigningContext *context);

/**
 * @brief
 * Load a public key from storage.
 *
 * @details
 * The public key is stored and loaded separately from the private key. Both the private key and the public key are
 * required to generate signatures. They are stored separately both to allow using different storage and because the
 * public key can be regenerated if it is lost.
 *
 * The public key also includes a previously generated cache, which greatly speeds up signature generation.
 *
 * @see xmss_generate_public_key() for more information about caching.
 *
 * If public_key contains caching data, xmss_load_public_key() will load the cache structure in cache and add it to
 * the context. If public_key does not contain any cache, cache's value will be changed to point to NULL. Static
 * memory implementations that do not know the size of the cache up front can pass a preallocated cache buffer of size
 * XMSS_INTERNAL_CACHE_SIZE(tree_depth) to accommodate all possible caches.
 *
 * This function is bit error resilient in that a single random bit error cannot cause it to load an invalid public key
 * or a valid public key that does not match `key_context`.
 *
 * @param[in,out] cache     A pointer to the initial pointer to pass to the user-provided #XmssReallocFunction to
 *                          allocate memory for a cache to be loaded. If a cache is indeed loaded, this argument's
 *                          contents will be set to NULL; the allocated cache is made part of the key context, instead.
 * @param[in] key_context   The context with the loaded private key for which the public key is to be loaded.
 *                          The context will be updated with the loaded public key and cache.
 * @param[in] public_key    The public key. This must be a valid XmssPublicKeyInternalBlob.
 * @retval #XMSS_OKAY    Success.
 * @retval #XMSS_ERR_NULL_POINTER   A NULL pointer was passed.
 * @retval #XMSS_ERR_ARGUMENT_MISMATCH  `public_key` does not contain the public key for the private key that was loaded
 *                                      in `key_context`.
 * @retval #XMSS_ERR_ALLOC_ERROR    Memory allocation caused an error.
 * @retval #XMSS_ERR_INVALID_BLOB   The data in `public_key` is not valid.
 * @retval #XMSS_ERR_BAD_CONTEXT    `key_context` is not a correctly initialized context.
 * @retval #XMSS_ERR_FAULT_DETECTED A bit error was detected.
 *                                  (Note that bit errors can also cause different errors or segfaults.)
 */
XmssError xmss_load_public_key(XmssInternalCache **cache, XmssKeyContext *key_context,
    const XmssPublicKeyInternalBlob *public_key);

/* === Key generation === */

/**
 * @brief
 * Generate a new private key.
 *
 * @details
 * After the private key has been generated the returned blobs should immediately be stored in a secure location and
 * (securely) wiped from memory.
 *
 * A newly generated private key is a single partition that covers the entire key's signature space.
 *
 * @see xmss_partition_signature_space() for more information on private key partitions.
 *
 * Index Obfuscation
 * =================
 *
 * Index obfuscation, if enabled, is part of the private key. A vital part of XMSS' security is preventing
 * double use of the same key. This is normally done by keeping track of the last used index, but with index obfuscation
 * this is less trivial. Making the obfuscation a part of the private key ensures that used index tracking remains
 * secure.
 *
 * To initialize the index obfuscation random data is required. It is not a problem if not enough random data of the
 * highest quality is available: index obfuscation is not a security feature but mere obfuscation. If only lower quality
 * random is available, that is fine. Whatever random is used, it MUST be completely separate from the secure random
 * that is used to generate the private key itself.
 *
 * @param[in,out] key_context       The context required for further use of the library with this key.
 * @param[in,out] private_key       The stateless part of the private key. This must be stored in a secure location. It
 *                                  will never change.
 * @param[in,out] key_usage         The stateful part of the private key. This must be stored in a secure location. It
 *                                  must be possible to update the `key_usage` in its secure storage location every time
 *                                  signatures need to be created.
 * @param[in] secure_random         Must contain 96 bytes of cryptographically secure random data. These random bytes
 *                                  will be used to generate the secure parts of the private key.
 * @param[in] index_obfuscation_setting   Selects whether or not index obfuscation will be used for the key.
 * @param[in] random                Random data for initialization of the index obfuscation. If index obfuscation is
 *                                  enabled, then this needs to contain 32 bytes of random data. If
 *                                  `index_obfuscation_setting` is #XMSS_INDEX_OBFUSCATION_OFF, then this parameter is
 *                                  ignored and may be NULL.
 * @param[in] context               The initialized context of the library. This must be initialized for the parameter
 *                                  set that was used to create the private key. After xmss_load_private_key()
 *                                  successfully returns this context may be deallocated: only `key_context` is needed
 *                                  for further use of the library.
 * @retval #XMSS_OKAY    Success.
 * @retval #XMSS_ERR_NULL_POINTER   A NULL pointer was passed.
 * @retval #XMSS_ERR_ALLOC_ERROR    Memory allocation caused an error.
 * @retval #XMSS_ERR_BAD_CONTEXT    `context` is not a correctly initialized context.
 * @retval #XMSS_ERR_INVALID_ARGUMENT   An invalid `index_obfuscation_setting` is passed.
 * @retval #XMSS_ERR_FAULT_DETECTED A bit error was detected.
 *                                  (Note that bit errors can also cause different errors or segfaults.)
 */
XmssError xmss_generate_private_key(XmssKeyContext **key_context, XmssPrivateKeyStatelessBlob **private_key,
    XmssPrivateKeyStatefulBlob **key_usage, const XmssBuffer *secure_random,
    XmssIndexObfuscationSetting index_obfuscation_setting, const XmssBuffer *random, const XmssSigningContext *context);

/**
 * @brief
 * Set up the process of generating the public key.
 *
 * @details
 * During the calculation of the public key a cache is immediately created, as well.
 *
 * Public Key Generation in Multiple Parts
 * =======================================
 *
 * Generating the public key is split into three parts to allow tracking progress and utilizing multiple cores. The
 * first part is the setup, using xmss_generate_public_key(). During setup a division of the work is chosen, the number
 * of partitions that need to be generated. Then during the second step each of those partitions is executed separately,
 * via calls to xmss_calculate_public_key_part(). This is where the majority of all calculations is done. Finally, after
 * all partitions' work has been finished, the final result can be calculated by calling
 * xmss_finish_calculate_public_key().
 *
 * The division into multiple partitions allows tracking progress by tracking how many partitions have finished. With
 * 1024 partitions, each partition is just under 0.1% of the work, which is excellent for something like a progress bar.
 * Dividing the work into multiple partitions also allows using multiple cores for the calculations: each partition's
 * calculations are entirely independent from the others, so it is inherently safe to run the calculations for several
 * partitions in parallel.
 *
 * When no calculations are being processed, for example when some of the xmss_calculate_public_key_part() calls have
 * finished and all the others have not yet been started, the process of calculating the public key can be aborted by
 * simply deallocating the key generation context.
 *
 * Caching types
 * =============
 *
 * Two different types of caching can be employed. The type to use is passed in the `cache_type` parameter. The effects
 * of the cache depends on the cache level. Single level caching will cache the nodes at only that level, whereas top
 * caching will also cache the nodes between that level and the root. Top caching can be considered the cumulative
 * version of single level caching, adding one more level of cache as the level decreases whereas single level caching
 * simply caches the next level.
 *
 * To compare the two, the table below summarizes which levels' nodes are cached for a given cache level. Note that $h$
 * is the height of the tree.
 *
 * | Cache level     | Single level caching | Top caching                   |
 * :----------------:|:--------------------:|:------------------------------:
 * |     $h - 1$     |       $h - 1$        |           $(h - 1)$           |
 * |     $h - 2$     |       $h - 2$        |      $(h - 1) + (h - 2)$      |
 * |     $h - 3$     |       $h - 3$        | $(h - 1) + (h - 2) + (h - 3)$ |
 * |        0        |          0           |           everything          |
 *
 * The trade-off is between memory usage and computation time when generating a signature. Compared to single level
 * caching, top caching uses roughly twice the amount of memory and storage, but offers an ever greater speed-up of
 * signature generation as the cache level decreases. For cache levels close to $h$, the difference in speed-up is
 * negligible, but when the cache level is $h/2$ top caching reduces the computation time by almost twice as much as
 * single level caching. If the cache level is 0, this increases to (almost) a factor $2^h$.
 *
 * Despite their differences, either cache type greatly speeds up the signature generation process compared to not using
 * any cache.
 *
 * If memory and storage are not constrained, top caching with minimum cache level is advised. For a tree height
 * $h = 20$, it requires roughly 64 MiB of memory and public key storage for cache level 0.
 *
 * Using a cache does not impact the exported public key: the cache is only stored in the XmssPublicKeyInternalBlob, the
 * internal, extended format for a public key.
 *
 * @param[in,out] generation_buffer     The work-in-progress public key. This context contains all the (temporary) data
 *                                      needed to calculate the entire public key and any requested cache layer.
 * @param[in,out] cache         A pointer to the initial pointer to pass to the user-provided #XmssReallocFunction to
 *                              allocate memory for a cache to be loaded. If a cache is to be generated, this argument's
 *                              contents will be set to NULL; the allocated cache is made part of the key generation
 *                              context, instead.
 * @param[in,out] generation_cache  A pointer to the initial pointer to pass to the user-provided #XmssReallocFunction
 *                                  to allocate memory for the temporary cache needed while generating the public key.
 *                                  This argument's contents will be set to NULL when the temporary cache is allocated:
 *                                  it will be made part of the key generation context, instead. For static allocation,
 *                                  the size can be determined with #XMSS_PUBLIC_KEY_GENERATION_CACHE_SIZE.
 * @param[in] key_context       The context with the private key for which the public will be calculated.
 * @param[in] cache_type        The type of caching to use. Top caching is advised unless memory or storage is
 *                              constrained.
 * @param[in] cache_level       The layer for which a cache should be created, where 0 is the bottom layer of the tree
 *                              and the highest layer (which is the public key itself) would be equal to the tree depth
 *                              (10, 16 or 20, depending on the XMSS parameter set that is used). Valid cache levels
 *                              must be smaller than the tree depth, though, since a cache of only the public key itself
 *                              makes no sense.
 *                              A cache at the lowest level is highly recommended for performance, at the expense of
 *                              some additional memory and storage used for the public key blob (not the exportable
 *                              public key).
 * @param[in] generation_partitions The number of partitions to divide the work in. If set to 1, a single call to
 *                                  xmss_calculate_public_key_part will calculate the entire public key. Set to any
 *                                  higher power of 2 (at most 2^tree depth), calculating the public key will require as
 *                                  many calls to xmss_calculate_public_key_part() to calculate (most of) the public
 *                                  key.
 * @retval #XMSS_OKAY   Success.
 * @retval #XMSS_ERR_NULL_POINTER   A NULL pointer was passed.
 * @retval #XMSS_ERR_ALLOC_ERROR    Memory allocation caused an error.
 * @retval #XMSS_ERR_BAD_CONTEXT    `key_context` is not a correctly initialized context.
 * @retval #XMSS_ERR_INVALID_ARGUMENT   An invalid `cache_type` is passed, `cache_level` is out of range or
 *                                      `generation_partitions` is out of range or not a power of 2.
 */
XmssError xmss_generate_public_key(XmssKeyGenerationContext **generation_buffer, XmssInternalCache **cache,
    XmssInternalCache **generation_cache, const XmssKeyContext *key_context, XmssCacheType cache_type,
    uint8_t cache_level, uint32_t generation_partitions);

/**
 * @brief
 * Perform work on an ongoing public key calculation.
 *
 * @see xmss_generate_public_key() for more information on generating a public key.
 *
 * @details
 * This function must be called exactly `generation_partitions` time to perform all the calculations on the public key.
 * `generation_partitions` is set during the public key generation setup, in xmss_generate_public_key().
 *
 * @param[in] generation_buffer The work-in-progress public key that calculations will be done for.
 * @param[in] partition_index   The partition number, running from 0 to `generation_partitions` - 1, for which the
 *                              calculations will be done. Each `partition_index` must be used exactly once.
 * @retval #XMSS_OKAY   Success.
 * @retval #XMSS_ERR_NULL_POINTER   A NULL pointer was passed.
 * @retval #XMSS_ERR_BAD_CONTEXT        `key_context` is not a correctly initialized context.
 * @retval #XMSS_ERR_INVALID_ARGUMENT   `partition_index` is out of range for the passed generation_buffer.
 * @retval #XMSS_ERR_PARTITION_DONE     The generation partition indicated by `partition_index` has already been
 *                                      started.
 */
XmssError xmss_calculate_public_key_part(XmssKeyGenerationContext *generation_buffer, uint32_t partition_index);

/**
 * @brief
 * Finalize calculation on a public key.
 *
 * @see xmss_generate_public_key() for more information on generating a public key.
 *
 * @details
 * This function will gather all the work done in the separate xmss_calculate_public_key_part() calls and combine
 * them to form the public key, possibly performing the last few steps.
 *
 * Calling this function before each required call to xmss_calculate_public_key_part() has finished is an error.
 *
 * On success, `generation_buffer` and `generation_cache` will be deallocated.
 *
 * @param[in,out] public_key    The blob with the public key and cache. It is recommended to store this blob for later
 *                              use.
 * @param[in] generation_buffer The work-in-progress public key for which the calculations will be finalized. Part of
 *                              this buffer will be moved to `key_context`, the rest will be deallocated. The value of
 *                              the pointer will be set to NULL to reflect this.
 * @param[in] key_context       The private key for which these calculations are being done. This context will be
 *                              updated to have the newly generated public key loaded.
 * @retval #XMSS_OKAY    Success.
 * @retval #XMSS_ERR_NULL_POINTER   A NULL pointer was passed.
 * @retval #XMSS_ERR_ALLOC_ERROR    Memory allocation caused an error.
 * @retval #XMSS_ERR_UNFINISHED_PARTITIONS  Not all generation partitions' calculations have been finished.
 * @retval #XMSS_ERR_FAULT_DETECTED A bit error was detected.
 *                                  (Note that bit errors can also cause different errors or segfaults.)
 */
XmssError xmss_finish_calculate_public_key(XmssPublicKeyInternalBlob **public_key,
    XmssKeyGenerationContext **generation_buffer, XmssKeyContext *key_context);

/* === Signing === */

/**
 * @brief
 * Request permission to sign one or more messages.
 *
 * @details
 * Permission will only be granted if the private key partition still contains the requested amount of unused keys.
 * Signatures that are requested must be used in the same session using xmss_sign_message() or they will be lost.
 *
 * A successful request will result in a new blob for the stateful part of the private key partition. This blob MUST be
 * stored in secure storage, overwriting any previous blobs for the stateful part of this private key partition, and
 * (securely) erased from memory. Only when storing this blob has been ensured may the signatures be used. Signing
 * messages before storing the new private key data, or only partially performing the store procedure, can lead to
 * fatal key reuse.
 *
 * The library is written such that a single random bit error cannot cause this function to reserve more signatures than
 * available. It is still possible for a bit error to cause an incorrect number of signatures to be claimed. Before
 * overwriting the stateful blob, check that the correct number of signatures is available, and if not, abort.
 *
 * Calling xmss_request_future_signatures() repeatedly will not cause previously requested but unused signatures to be
 * lost, but will simply increase the number of allowed signatures.
 *
 * @param[in,out] new_key_usage     The blob with the new stateful private key part.
 * @param[in] key_context       The private key for which signatures are to be created.
 * @param[in] signature_count   The number of signatures that will be created.
 * @retval #XMSS_OKAY   Success.
 * @retval #XMSS_ERR_NULL_POINTER   A NULL pointer was passed.
 * @retval #XMSS_ERR_ALLOC_ERROR    Memory allocation caused an error.
 * @retval #XMSS_ERR_BAD_CONTEXT    `key_context` is not a correctly initialized context.
 * @retval #XMSS_ERR_TOO_FEW_SIGNATURES_AVAILABLE   The private key partition does not contain `signature_count` unused
 *                                                  keys.
 * @retval #XMSS_ERR_NO_PUBLIC_KEY   `key_context` does not have a public key loaded.
 * @retval #XMSS_ERR_FAULT_DETECTED A bit error was detected.
 *                                  (Note that bit errors can also cause different errors or segfaults.)
 */
XmssError xmss_request_future_signatures(XmssPrivateKeyStatefulBlob **new_key_usage, XmssKeyContext *key_context,
    uint32_t signature_count);

/**
 * @brief
 * Create a signature for a message.
 *
 * @details
 * This function will only create signatures after a call to xmss_request_future_signatures(), after which at most
 * `signature_count` calls to xmss_sign_message() can succeed.
 *
 * The library is written in such a way that a single random bit error cannot cause this function to output a signature
 * that re-uses a one-time signature key. A single bit error can still cause it to output an invalid signature, in which
 * case all reserved signature go to waste. However, the integrity of previous or future signatures is not compromised.
 *
 * The signature produced by this function must be verified before publishing it.
 *
 * @param[in,out] signature The signature for the message. Care should be taken to store this correctly: a lost
 *                          signature cannot be recovered, only a new signature could be created. The format of the
 *                          signature is as specified in RFC 8391, Section 4.1.8.
 * @param[in] key_context   The private key with which the signature will be made. A public key must have been loaded or
 *                          generated for this private key.
 * @param[in] message       The message of arbitrary length to sign.
 * @retval #XMSS_OKAY   Success.
 * @retval #XMSS_ERR_NULL_POINTER   A NULL pointer was passed.
 * @retval #XMSS_ERR_ALLOC_ERROR    Memory allocation caused an error.
 * @retval #XMSS_ERR_BAD_CONTEXT    `key_context` is not a correctly initialized context.
 * @retval #XMSS_ERR_TOO_FEW_SIGNATURES_AVAILABLE   No additional signatures can be created without calling
 *                                                  xmss_request_future_signatures() first.
 * @retval #XMSS_ERR_NO_PUBLIC_KEY  `key_context` does not have a public key loaded.
 * @retval #XMSS_ERR_FAULT_DETECTED A bit error was detected; note that not all bit errors will be detected.
 *                                  (Note that bit errors can also cause different errors or segfaults.)
 */
XmssError xmss_sign_message(XmssSignatureBlob **signature, XmssKeyContext *key_context, const XmssBuffer *message);

/* === Signature space partitioning === */

/**
 * @brief
 * Partition a private key into two private keys.
 *
 * @details
 * A private key should never be backed up by just copying the securely stored files. Recovering using an offline backup
 * that is a copy of a private key that has been in use is almost guaranteed to lead to fatal key reuse. Backups can be
 * created by dividing the private key into multiple partitions. The stateless parts of the two partitioned private keys
 * remain the same, but their stateful parts ensure that key reuse can't occur.
 *
 * Partitioning a private key creates a second key usage blob which can create `new_partition_size` signatures, and
 * adjusts the loaded private key so it will no longer be able to place those same signatures.
 *
 * A successful partitioning will also result in a new blob for the stateful part of the currently loaded private key.
 * This blob MUST be stored in secure storage, overwriting any previous blobs for the stateful part of this private key,
 * and (securely) erased from memory. Only when storing this blob has been ensured may the new partition be stored and
 * used. Storing or using the new partition before storing the new private key data, or only partially performing the
 * store procedure, can lead to fatal key reuse.
 *
 * After the private key has been partitioned and the new blob for the stateful part of the currently loaded private key
 * has been stored, the returned blob for the stateful part of the new partition should immediately be stored in a
 * secure location. It should be (securely) wiped from memory afterwards, even if either blob can't be stored.
 *
 * New partitions are created from the end of the signature space, whereas requests to create signatures are taken from
 * the beginning. A proper backup scheme, which can utilize xmss_merge_signature_space() to extend the current
 * private key with a part of the backups when the time comes, first creates the last backup partition, then the
 * second-to-last, and so on, every time decreasing the current private key a bit more, making it the first (and
 * presumably active) partition. As long as only the lowest partition is used, two consecutive partitions will be able
 * to be merged.
 *
 * A single bit error cannot cause this function to generate new partitions that exceed the bounds of the previous
 * signature space, or to produce new partitions with overlap. However, a bit error in `new_partition_size` can still
 * cause the resulting new partitions to have incorrect sizes. The size of the new partitions must be checked before
 * overwriting the old.
 *
 * @param[in,out] new_partition             The blob with the stateful part of the new partition's private key.
 * @param[in,out] updated_current_partition The blob with the new stateful private part of the currently loaded private
 *                                          part.
 * @param[in] key_context           The private key to partition into two parts.
 * @param[in] new_partition_size    The number of possible signatures to move to the new partition. The private key must
 *                                  have at least this amount of signatures left.
 * @retval #XMSS_OKAY   Success.
 * @retval #XMSS_ERR_NULL_POINTER   A NULL pointer was passed.
 * @retval #XMSS_ERR_ALLOC_ERROR    Memory allocation caused an error.
 * @retval #XMSS_ERR_BAD_CONTEXT    `key_context` is not a correctly initialized context.
 * @retval #XMSS_ERR_TOO_FEW_SIGNATURES_AVAILABLE   The private key context contains less than `new_partition_size`
 *                                                  unused keys.
 * @retval #XMSS_ERR_FAULT_DETECTED A bit error was detected; note that not all bit errors will be detected.
 *                                  (Note that bit errors can also cause different errors or segfaults.)
 */
XmssError xmss_partition_signature_space(XmssPrivateKeyStatefulBlob **new_partition,
    XmssPrivateKeyStatefulBlob **updated_current_partition, XmssKeyContext *key_context, uint32_t new_partition_size);

/**
 * @brief
 * Merge two partitions of a private key into one private key partition.
 *
 * @details
 * This creates a new private key partition that covers the entire range of the two merged partitions, which replaces
 * the currently loaded private key partition.
 *
 * A successful merge temporarily duplicates the original partitions. Any stored versions of the stateful private key
 * part of the partition that is merged into the current private key partition must immediately be securely destroyed,
 * and the blob (securely) erased from memory. Failure to fully erase this data can lead to fatal key reuse.
 *
 * A successful merge will result in a new blob for the stateful part of the currently loaded private key. This blob
 * must be stored in secure storage, overwriting any previous blobs for the stateful part of this private key. It should
 * be (securely) erased from memory to prevent accidental, fatal key reuse.
 *
 * This function is bit error resilient: A single random bit error cannot cause two partitions to be merged if they are
 * not consecutive.
 *
 * There is no inherent benefit to merging an empty private key partition, just loading the other non-empty partition
 * has the same effect.
 *
 * @param[in,out] new_key_usage     The blob with the new stateful private part of te currently loaded private part.
 * @param[in] key_context           The currently loaded private key partition to extend with an adjust partition.
 * @param[in] partition_extension   The stateful private part of the partition to merge into the currently loaded
 *                                  private key. Both partitions must be for the same private key and must be
 *                                  consecutive.
 * @retval #XMSS_OKAY   Success.
 * @retval #XMSS_ERR_NULL_POINTER   A NULL pointer was passed.
 * @retval #XMSS_ERR_ALLOC_ERROR    Memory allocation caused an error.
 * @retval #XMSS_ERR_INVALID_BLOB   The data in partition_extension is not valid.
 * @retval #XMSS_ERR_BAD_CONTEXT    `key_context` is not a correctly initialized context.
 * @retval #XMSS_ERR_PARTITIONS_NOT_CONSECUTIVE The private key partition in `partition_extension` is not consecutive
 *                                              with the private key partition in `key_context`.
 * @retval #XMSS_ERR_FAULT_DETECTED A bit error was detected.
 *                                  (Note that bit errors can also cause different errors or segfaults.)
 */
XmssError xmss_merge_signature_space(XmssPrivateKeyStatefulBlob **new_key_usage, XmssKeyContext *key_context,
    const XmssPrivateKeyStatefulBlob *partition_extension);

/* === Informationals === */

/**
 * @brief
 * The number of signatures that can still be created with a private key partition.
 *
 * @details
 * Signatures that have already been requested with xmss_request_future_signatures() but have not yet been created
 * with xmss_sign_message() are *not* shown in the number returned by this function.
 *
 * @see xmss_partition_signature_space() for more information about private key partitions.
 *
 * @param[out] total_count      The total number of signatures that can be created by the key in its entirety.
 * @param[out] remaining_count  The number of available signatures in this partition.
 * @param[in] key_context       The private key partition to query.
 * @retval #XMSS_OKAY    Success.
 * @retval #XMSS_ERR_NULL_POINTER   A NULL pointer was passed.
 * @retval #XMSS_ERR_BAD_CONTEXT    `key_context` is not a correctly initialized context.
 * @retval #XMSS_ERR_FAULT_DETECTED A bit error was detected; note that not all bit errors will be detected.
 *                                  (Note that bit errors can also cause different errors or segfaults.)
 */
XmssError xmss_get_signature_count(size_t *total_count, size_t *remaining_count, const XmssKeyContext *key_context);

/**
 * @brief
 * Verify the validity and integrity of a public key blob.
 *
 * @details
 * This function is bit error resilient in that a single random bit error cannot cause it to wrongly output #XMSS_OKAY.
 * If a function checks the return value of this function and bit error resilience is required, the return value should
 * be stored in a volatile variable which is then checked twice.
 *
 * @param[in] pub_key       The public key blob to verify.
 * @param[in] private_key   A stateless private key part to verify against. Providing this verifies that the public key
 *                          was created for this private key. May be NULL.
 * @param[in] key_context   A private key to verify against. Providing this verifies that the public key was created for
 *                          the private key in the key context. May be NULL.
 * @retval #XMSS_OKAY    Success.
 * @retval #XMSS_ERR_NULL_POINTER   `pub_key` is NULL.
 * @retval #XMSS_ERR_ARGUMENT_MISMATCH  `private_key` was passed and `pub_key` does not contain a public key that
 *                                      corresponds to the private key contained in `private_key`, or `key_context` was
 *                                      passed and `pub_key` does not contain a public key that corresponds to the
 *                                      private key loaded in `key_context`.
 * @retval #XMSS_ERR_INVALID_BLOB   The data in `pub_key` is not valid or `private_key` is passed and contains invalid
 *                                  data.
 * @retval #XMSS_ERR_BAD_CONTEXT    `key_context` is passed and is not a correctly initialized context.
 * @retval #XMSS_ERR_FAULT_DETECTED A bit error was detected.
 *                                  (Note that bit errors can also cause different errors or segfaults.)
 */
XmssError xmss_verify_public_key(const XmssPublicKeyInternalBlob *pub_key,
    const XmssPrivateKeyStatelessBlob *private_key, const XmssKeyContext *key_context);

/**
 * @brief
 * Verify the validity and integrity of a stateless private key part.
 *
 * @details
 * This function is bit error resilient in that a single random bit error cannot cause it to wrongly output #XMSS_OKAY.
 * If a function checks the return value of this function and bit error resilience is required, the return value should
 * be stored in a volatile variable which is then checked twice.
 *
 * @param[in] private_key   The private key part to verify.
 * @param[in] context       The signing context that's required for the verification.
 * @retval #XMSS_OKAY   Success.
 * @retval #XMSS_ERR_NULL_POINTER   A NULL pointer was passed.
 * @retval #XMSS_ERR_INVALID_BLOB   `private_key` contains invalid data.
 * @retval #XMSS_ERR_ARGUMENT_MISMATCH  The signing context was created for a different parameter set than the private
 *                                      key blob.
 * @retval #XMSS_ERR_FAULT_DETECTED A bit error was detected.
 *                                  (Note that bit errors can also cause different errors or segfaults.)
 */
XmssError xmss_verify_private_key_stateless(const XmssPrivateKeyStatelessBlob *private_key,
    const XmssSigningContext *context);

/**
 * @brief
 * Verify the validity and integrity of a stateful private key partition part.
 *
 * @details
 * This function is bit error resilient in that a single random bit error cannot cause it to wrongly output #XMSS_OKAY.
 * If a function checks the return value of this function and bit error resilience is required, the return value should
 * be stored in a volatile variable which is then checked twice.
 *
 * @param[in] key_usage         The stateful private key part to verify.
 * @param[in] private_key       A stateless private key part to verify against. Providing this verifies that the two
 *                              private key part are part of the same private key. May be NULL.
 * @param[in] key_context       A private key to verify against. Providing this verifies that the stateful private key
 *                              part corresponds to the stateless private key in the `key_context`. May be NULL if and
 *                              only if `signing_context` is non-NULL.
 * @param[in] signing_context   The signing context, required to perform a verification operation. May be NULL if and
 *                              only if key_context is non-NULL.
 * @retval #XMSS_OKAY   Success.
 * @retval #XMSS_ERR_NULL_POINTER   `key_usage` is NULL, or if both `key_context` and `signing_context` are NULL.
 * @retval #XMSS_ERR_ARGUMENT_MISMATCH  `private_key` was passed and `key_usage` does not contain stateful data that
 *                                      corresponds to the private key contained in `private_key`, or `key_context` was
 *                                      passed and `key_usage` does not contain stateful data that corresponds to the
 *                                      private key loaded in `key_context`.
 * @retval #XMSS_ERR_INVALID_BLOB   The data in `pub_key` is not valid or `private_key` is passed and contains invalid
 *                                  data.
 * @retval #XMSS_ERR_BAD_CONTEXT    `key_context` is passed and not a correctly initialized context.
 * @retval #XMSS_ERR_FAULT_DETECTED A bit error was detected.
 *                                  (Note that bit errors can also cause different errors or segfaults.)
 */
XmssError xmss_verify_private_key_stateful(const XmssPrivateKeyStatefulBlob *key_usage,
    const XmssPrivateKeyStatelessBlob *private_key, const XmssKeyContext *key_context,
    const XmssSigningContext *signing_context);

/**
 * @brief
 * Extract the level of the cache that is stored in a public key blob.
 *
 * @details
 * This function is primarily to support implementations with advanced memory management.
 *
 * @param[out] cache_type   The type of cache as found in the public key blob.
 * @param[out] cache_level  The cache level as found in the public key blob.
 * @param[in] pub_key       The public key blob to query.
 * @retval #XMSS_OKAY    Success.
 * @retval #XMSS_ERR_NULL_POINTER   A NULL pointer was passed.
 * @retval #XMSS_ERR_INVALID_BLOB   The data in `pub_key` is not valid.
 * @retval #XMSS_ERR_FAULT_DETECTED A bit error was detected.
 *                                  (Note that bit errors can also cause different errors or segfaults.)
 */
XmssError xmss_get_caching_in_public_key(XmssCacheType *cache_type, uint32_t *cache_level,
    const XmssPublicKeyInternalBlob *pub_key);

/* === Exportable public key === */

/**
 * @brief
 * Write the public key to an exportable format.
 *
 * @details
 * The internal format contains features like integrity checking. This function will export the public key to the format
 * specified by RFC 8391 Section 4.1.7.
 *
 * @param[in,out] exported_pub_key  The exported public key.
 * @param[in] key_context           The private key to export the public key from. A public key must have been loaded or
 *                                  generated for this private key.
 * @retval #XMSS_OKAY   Success.
 * @retval #XMSS_ERR_NULL_POINTER   A NULL pointer was passed.
 * @retval #XMSS_ERR_BAD_CONTEXT    `key_context` is not a correctly initialized context.
 * @retval #XMSS_ERR_NO_PUBLIC_KEY  `key_context` does not have a public key loaded.
 * @retval #XMSS_ERR_FAULT_DETECTED A bit error was detected.
 *                                  (Note that bit errors can also cause different errors or segfaults.)
 */
XmssError xmss_export_public_key(XmssPublicKey *exported_pub_key, const XmssKeyContext *key_context);

/**
 * @brief
 * Verify the correctness of an exported public key.
 *
 * @details
 * The exportable format does not contain any form of integrity checking. With this function the correctness can be
 * verified.
 *
 * @param[in] exported_pub_key  The exported public key to verify.
 * @param[in] key_context       The private key to verify the public key against. A public key must have been loaded or
 *                              generated for this private key.
 * @retval #XMSS_OKAY   Success.
 * @retval #XMSS_ERR_NULL_POINTER   A NULL pointer was passed.
 * @retval #XMSS_ERR_BAD_CONTEXT    `key_context` is not a correctly initialized context.
 * @retval #XMSS_ERR_NO_PUBLIC_KEY  `key_context` does not have a public key loaded.
 * @retval #XMSS_ERR_ARGUMENT_MISMATCH  `exported_pub_key` seems to be a valid exported public key, but is not the same
 *                                      public key as is loaded in key_context.
 */
XmssError xmss_verify_exported_public_key(const XmssPublicKey *exported_pub_key, const XmssKeyContext *key_context);

#endif /* !XMSS_SIGNING_H_INCLUDED */
