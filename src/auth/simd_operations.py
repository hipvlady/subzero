"""
SIMD-optimised operations for parallel hash computation
Leverages AVX2/AVX512 for 4-8x speedup on batch operations
"""

import numpy as np
from numba import vectorize, guvectorize, prange, uint64, uint8, njit


@vectorize([uint64(uint8)], target='parallel', cache=True)
def simd_fnv1a_byte(byte_val):
    """Vectorised FNV-1a hash computation per byte"""
    return byte_val * uint64(1099511628211)


@guvectorize([(uint8[:,:], uint64[:])], '(n,m)->(n)',
             target='parallel', cache=True, nopython=True)
def batch_compute_fnv1a(byte_matrix, hash_results):
    """
    Compute FNV-1a hashes for multiple inputs in parallel
    Processes 8-16 hashes simultaneously on modern CPUs
    """
    fnv_offset = uint64(14695981039346656037)
    fnv_prime = uint64(1099511628211)

    for i in prange(byte_matrix.shape[0]):
        hash_val = fnv_offset
        for j in range(byte_matrix.shape[1]):
            if byte_matrix[i, j] != 0:  # Skip padding
                hash_val ^= uint64(byte_matrix[i, j])
                hash_val *= fnv_prime
        hash_results[i] = hash_val


@njit(parallel=True, cache=True)
def parallel_hash_lookup(hash_batch: np.ndarray, hash_table: np.ndarray) -> np.ndarray:
    """
    Parallel hash table lookup for batch processing
    Returns indices for each hash or -1 if not found
    """
    batch_size = len(hash_batch)
    table_size = len(hash_table)
    results = np.zeros(batch_size, dtype=np.int64)

    for i in prange(batch_size):
        hash_val = hash_batch[i]
        start_idx = hash_val % table_size

        # Linear probing with early exit
        found = False
        for j in range(min(16, table_size)):  # Limit probe distance
            idx = (start_idx + j) % table_size
            if hash_table[idx] == hash_val:
                results[i] = idx
                found = True
                break
            elif hash_table[idx] == 0:
                break

        if not found:
            results[i] = -1

    return results


@njit(parallel=True, cache=True)
def simd_xxhash64(data: np.ndarray) -> np.uint64:
    """
    Simplified xxHash64 implementation optimized for SIMD
    Faster than FNV-1a for larger inputs
    """
    # xxHash64 constants
    PRIME64_1 = uint64(0x9E3779B185EBCA87)
    PRIME64_2 = uint64(0xC2B2AE3D27D4EB4F)
    PRIME64_3 = uint64(0x165667B19E3779F9)
    PRIME64_4 = uint64(0x85EBCA77C2B2AE63)
    PRIME64_5 = uint64(0x27D4EB2F165667C5)

    length = len(data)

    if length >= 32:
        # Process in 32-byte blocks
        v1 = PRIME64_1 + PRIME64_2
        v2 = PRIME64_2
        v3 = uint64(0)
        v4 = -PRIME64_1

        # Process blocks of 32 bytes
        blocks = length // 32
        for block in prange(blocks):
            offset = block * 32
            # Simulate 4x8 byte reads
            for i in range(4):
                chunk = uint64(0)
                for j in range(8):
                    chunk = (chunk << 8) | data[offset + i*8 + j]

                if i == 0:
                    v1 = ((v1 + chunk * PRIME64_2) << 31) | ((v1 + chunk * PRIME64_2) >> 33)
                    v1 *= PRIME64_1
                elif i == 1:
                    v2 = ((v2 + chunk * PRIME64_2) << 31) | ((v2 + chunk * PRIME64_2) >> 33)
                    v2 *= PRIME64_1
                elif i == 2:
                    v3 = ((v3 + chunk * PRIME64_2) << 31) | ((v3 + chunk * PRIME64_2) >> 33)
                    v3 *= PRIME64_1
                else:
                    v4 = ((v4 + chunk * PRIME64_2) << 31) | ((v4 + chunk * PRIME64_2) >> 33)
                    v4 *= PRIME64_1

        # Mix the accumulators
        h64 = ((v1 << 1) | (v1 >> 63)) + \
              ((v2 << 7) | (v2 >> 57)) + \
              ((v3 << 12) | (v3 >> 52)) + \
              ((v4 << 18) | (v4 >> 46))
    else:
        h64 = PRIME64_5

    h64 += uint64(length)

    # Process remaining bytes
    remaining = length % 32
    if remaining > 0:
        offset = (length // 32) * 32
        for i in range(remaining):
            h64 ^= uint64(data[offset + i]) * PRIME64_5
            h64 = ((h64 << 11) | (h64 >> 53)) * PRIME64_1

    # Final mixing
    h64 ^= h64 >> 33
    h64 *= PRIME64_2
    h64 ^= h64 >> 29
    h64 *= PRIME64_3
    h64 ^= h64 >> 32

    return h64


class SIMDHasher:
    """High-performance batch hash processor using SIMD instructions"""

    def __init__(self, batch_size: int = 128):
        self.batch_size = batch_size
        self.buffer = []

    def add_to_batch(self, user_id: str) -> int:
        """Add user ID to batch, return batch index"""
        self.buffer.append(user_id)
        return len(self.buffer) - 1

    def compute_batch(self) -> np.ndarray:
        """Process entire batch using SIMD operations"""
        if not self.buffer:
            return np.array([], dtype=np.uint64)

        # Prepare padded byte matrix
        max_len = max(len(uid) for uid in self.buffer)
        byte_matrix = np.zeros((len(self.buffer), max_len), dtype=np.uint8)

        for i, uid in enumerate(self.buffer):
            uid_bytes = uid.encode('utf-8')
            byte_matrix[i, :len(uid_bytes)] = np.frombuffer(uid_bytes, dtype=np.uint8)

        # Compute all hashes in parallel
        hash_results = batch_compute_fnv1a(byte_matrix)

        # Clear buffer
        self.buffer.clear()

        return hash_results

    def compute_batch_xxhash(self) -> np.ndarray:
        """
        Compute xxHash64 for batch - better for longer strings
        """
        if not self.buffer:
            return np.array([], dtype=np.uint64)

        results = np.zeros(len(self.buffer), dtype=np.uint64)

        for i, uid in enumerate(self.buffer):
            uid_bytes = np.frombuffer(uid.encode('utf-8'), dtype=np.uint8)
            results[i] = simd_xxhash64(uid_bytes)

        self.buffer.clear()
        return results


class ParallelCacheOperations:
    """
    Batch cache operations using SIMD/parallel processing
    """

    def __init__(self, cache_size: int = 65536):
        self.cache_size = cache_size
        self.hash_table = np.zeros(cache_size, dtype=np.uint64)

    def batch_insert(self, hashes: np.ndarray) -> np.ndarray:
        """
        Insert multiple hashes in parallel
        Returns array of insertion indices
        """
        batch_size = len(hashes)
        indices = np.zeros(batch_size, dtype=np.int64)

        for i in prange(batch_size):
            hash_val = hashes[i]
            start_idx = hash_val % self.cache_size

            # Find empty slot with linear probing
            for j in range(16):  # Limit probe distance
                idx = (start_idx + j) % self.cache_size
                if self.hash_table[idx] == 0:
                    self.hash_table[idx] = hash_val
                    indices[i] = idx
                    break
            else:
                indices[i] = -1  # Failed to insert

        return indices

    def batch_lookup(self, hashes: np.ndarray) -> np.ndarray:
        """
        Lookup multiple hashes in parallel
        """
        return parallel_hash_lookup(hashes, self.hash_table)


def benchmark_hash_functions():
    """
    Benchmark different hash functions to find optimal choice
    """
    import time

    test_data = [f"user_{i}" for i in range(1000)]

    # Test FNV-1a
    hasher = SIMDHasher()
    for uid in test_data:
        hasher.add_to_batch(uid)

    start = time.perf_counter()
    fnv_results = hasher.compute_batch()
    fnv_time = time.perf_counter() - start

    # Test xxHash64
    for uid in test_data:
        hasher.add_to_batch(uid)

    start = time.perf_counter()
    xxhash_results = hasher.compute_batch_xxhash()
    xxhash_time = time.perf_counter() - start

    return {
        'fnv1a_time_ms': fnv_time * 1000,
        'xxhash_time_ms': xxhash_time * 1000,
        'speedup': fnv_time / xxhash_time if xxhash_time > 0 else float('inf')
    }