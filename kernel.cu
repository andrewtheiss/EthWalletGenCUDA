#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <vector>
#include <cuda_runtime.h>
#include <curand_kernel.h>
#include <secp256k1.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

// Helper function to convert binary data to hexadecimal string
std::string toHex(const uint8_t* data, size_t length) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

// CUDA kernel for generating random private keys
__global__ void generatePrivateKeys(uint8_t* d_privateKeys, int numWallets) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < numWallets) {
        curandState state;
        curand_init(clock64(), idx, 0, &state);
        for (int i = 0; i < 32; ++i) {
            d_privateKeys[idx * 32 + i] = curand(&state) % 256;
        }
    }
}

// Class to manage OpenSSL EVP context
class KeccakHasher {
private:
    EVP_MD_CTX* mdctx;
    const EVP_MD* md;

public:
    KeccakHasher() : mdctx(EVP_MD_CTX_new()), md(EVP_sha3_256()) {
        if (!mdctx) throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    ~KeccakHasher() {
        EVP_MD_CTX_free(mdctx);
    }

    void hash(const unsigned char* input, size_t length, unsigned char* output) {
        EVP_DigestInit_ex(mdctx, md, nullptr);
        EVP_DigestUpdate(mdctx, input, length);
        unsigned int digest_length;
        EVP_DigestFinal_ex(mdctx, output, &digest_length);
    }
};

bool addressMatchesTarget(const std::string& address,
    const std::vector<std::string>& prefixes,
    const std::vector<std::string>& suffixes) {
    for (const auto& prefix : prefixes) {
        if (address.substr(2, prefix.length()) == prefix) {
            // If prefix matches, check for suffix match
            for (const auto& suffix : suffixes) {
                if (address.substr(address.length() - suffix.length()) == suffix) {
                    return true; // Both prefix and suffix match
                }
            }
        }
    }
    return false; // No combination of prefix and suffix matched
}

int main() {
    const int batchSize = 1024 * 256;  // Number of wallets to generate per batch
    std::vector<std::string> targetPrefixes = { "bd", "da", "fe"};  // Target address prefixes
    std::vector<std::string> targetSuffixes = { "c0de", "cafe", "face" }; // Target address suffixes

    // Initialize CUDA
    uint8_t* d_privateKeys;
    cudaMalloc(&d_privateKeys, batchSize * 32 * sizeof(uint8_t));

    // Initialize secp256k1 context
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    // Initialize Keccak hasher
    KeccakHasher keccakHasher;

    uint64_t totalAddressesGenerated = 0;
    bool targetFound = false;
    std::string matchedAddress;
    std::string matchedPrivateKey;

    while (!targetFound) {
        // Generate batch of private keys
        generatePrivateKeys << <(batchSize + 255) / 256, 256 >> > (d_privateKeys, batchSize);

        // Copy private keys back to host
        std::vector<uint8_t> h_privateKeys(batchSize * 32);
        cudaMemcpy(h_privateKeys.data(), d_privateKeys, batchSize * 32 * sizeof(uint8_t), cudaMemcpyDeviceToHost);

        // Process batch
        for (int i = 0; i < batchSize; ++i) {
            uint8_t* privateKey = &h_privateKeys[i * 32];

            // Generate public key
            secp256k1_pubkey pubkey;
            if (!secp256k1_ec_pubkey_create(ctx, &pubkey, privateKey)) {
                continue;
            }

            // Serialize public key
            uint8_t serializedPubkey[65];
            size_t pubkeyLen = sizeof(serializedPubkey);
            secp256k1_ec_pubkey_serialize(ctx, serializedPubkey, &pubkeyLen, &pubkey, SECP256K1_EC_UNCOMPRESSED);

            // Hash public key
            uint8_t hash[32];
            keccakHasher.hash(serializedPubkey + 1, 64, hash);

            // Create Ethereum address (last 20 bytes of the hash)
            std::string address = "0x" + toHex(hash + 12, 20);

            totalAddressesGenerated++;

            // Check if address matches target
            if (addressMatchesTarget(address, targetPrefixes, targetSuffixes)) {
                targetFound = true;
                matchedAddress = address;
                matchedPrivateKey = toHex(privateKey, 32);
                break;
            }

            // Print progress every million addresses
            if (totalAddressesGenerated % 1000000 == 0) {
                std::cout << "Generated " << totalAddressesGenerated << " addresses so far..." << std::endl;
            }
        }
    }

    // Print result
    std::cout << "Match found after generating " << totalAddressesGenerated << " addresses!" << std::endl;
    std::cout << "Matching address: " << matchedAddress << std::endl;
    std::cout << "Private key: " << matchedPrivateKey << std::endl;

    // Cleanup
    secp256k1_context_destroy(ctx);
    cudaFree(d_privateKeys);

    return 0;
}