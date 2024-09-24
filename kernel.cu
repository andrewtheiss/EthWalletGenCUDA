// Include necessary headers
#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstring>
#include <algorithm>
#include <mutex>

// CUDA headers
#include <cuda_runtime.h>
#include <curand_kernel.h>

// secp256k1 headers
#include <secp256k1.h>

// Include the CompactFIPS202 implementation
#include "Keccak-readable-and-compact.c"

// Host function to compute Keccak-256 using CompactFIPS202.c
void keccak256_host(const uint8_t* input, size_t inputLen, uint8_t* output) {
    FIPS202_SHA3_256(input, inputLen, output);  // Compute Keccak-256 hash
}

// Function to convert byte array to hex string
std::string toHex(const uint8_t* data, size_t length) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        ss << std::setw(2) << static_cast<unsigned int>(data[i]);
    }
    return ss.str();
}

// Function to compute EIP-55 checksummed address
std::string toChecksumAddress(const std::string& address) {
    // Remove '0x' prefix if present
    std::string addr = address;
    if (addr.substr(0, 2) == "0x" || addr.substr(0, 2) == "0X") {
        addr = addr.substr(2);
    }
    // Convert to lowercase
    std::string addrLower = addr;
    std::transform(addrLower.begin(), addrLower.end(), addrLower.begin(), ::tolower);

    // Compute Keccak-256 hash of the lowercase address
    uint8_t hash[32];
    keccak256_host(reinterpret_cast<const uint8_t*>(addrLower.c_str()), addrLower.length(), hash);

    // Convert hash to hexadecimal string
    std::string hashHex = toHex(hash, 32);

    // Apply checksum
    std::string checksummedAddress = "0x";
    for (size_t i = 0; i < addrLower.length(); ++i) {
        char c = addrLower[i];
        int hashNibble;
        if (hashHex[i] >= '0' && hashHex[i] <= '9') {
            hashNibble = hashHex[i] - '0';
        }
        else if (hashHex[i] >= 'a' && hashHex[i] <= 'f') {
            hashNibble = hashHex[i] - 'a' + 10;
        }
        else if (hashHex[i] >= 'A' && hashHex[i] <= 'F') {
            hashNibble = hashHex[i] - 'A' + 10;
        }
        else {
            hashNibble = 0;
        }
        if ((hashNibble & 0x8) != 0) {
            checksummedAddress += toupper(c);
        }
        else {
            checksummedAddress += c;
        }
    }
    return checksummedAddress;
}

// CUDA kernel to generate private keys
__global__ void generatePrivateKeys(uint8_t* d_privateKeys, unsigned int numKeys) {
    unsigned int idx = blockIdx.x * blockDim.x + threadIdx.x;

    if (idx < numKeys) {
        curandState state;
        // Improved seeding to ensure better randomness
        unsigned long long seed = clock64() + idx + (unsigned long long)gridDim.x * blockDim.x;
        curand_init(seed, 0, 0, &state);

        // Each thread generates one private key (32 bytes)
        for (int i = 0; i < 32; i++) {
            d_privateKeys[idx * 32 + i] = curand(&state) % 256;
        }
    }
}

// Mutex for synchronizing access to shared data
std::mutex dataMutex;

// Host function to process private keys
bool processPrivateKeys(const uint8_t* privateKeys, unsigned int numKeys, const std::string& targetPrefix, const std::string& targetSuffix,
    uint8_t* matchedPrivateKey, uint8_t* matchedAddress, std::atomic<bool>& found) {
    // Create a secp256k1 context
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    for (unsigned int idx = 0; idx < numKeys && !found.load(); ++idx) {
        const uint8_t* privateKey = &privateKeys[idx * 32];

        // Check if private key is valid
        if (!secp256k1_ec_seckey_verify(ctx, privateKey)) {
            continue; // Invalid private key, skip
        }

        // Compute public key
        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, privateKey)) {
            continue; // Failed to create public key, skip
        }

        // Serialize public key in uncompressed format
        uint8_t pubkeySerialized[65];
        size_t pubkeyLen = 65;
        secp256k1_ec_pubkey_serialize(ctx, pubkeySerialized, &pubkeyLen, &pubkey, SECP256K1_EC_UNCOMPRESSED);

        // Compute Keccak-256 hash of the public key (excluding the first byte 0x04)
        uint8_t hash[32];
        keccak256_host(pubkeySerialized + 1, 64, hash);

        // Take last 20 bytes as the address
        uint8_t address[20];
        memcpy(address, hash + 12, 20);

        // Convert address to hexadecimal string
        std::string addressHex = toHex(address, 20);

        // Convert both strings to lowercase for case-insensitive comparison
        std::string lowerAddressHex = addressHex;
        std::transform(lowerAddressHex.begin(), lowerAddressHex.end(), lowerAddressHex.begin(), ::tolower);
        std::string lowerTargetPrefix = targetPrefix;
        std::transform(lowerTargetPrefix.begin(), lowerTargetPrefix.end(), lowerTargetPrefix.begin(), ::tolower);
        std::string lowerTargetSuffix = targetSuffix;
        std::transform(lowerTargetSuffix.begin(), lowerTargetSuffix.end(), lowerTargetSuffix.begin(), ::tolower);

        // Check if address starts or ends with the target substring
        bool prefixMatch = false;
        bool suffixMatch = false;

        if (!lowerTargetPrefix.empty()) {
            prefixMatch = lowerAddressHex.compare(0, lowerTargetPrefix.length(), lowerTargetPrefix) == 0;
        }
        if (!lowerTargetSuffix.empty()) {
            suffixMatch = lowerAddressHex.compare(lowerAddressHex.length() - lowerTargetSuffix.length(), lowerTargetSuffix.length(), lowerTargetSuffix) == 0;
        }

        if (prefixMatch || suffixMatch) {
            // Lock the mutex before writing shared data
            std::lock_guard<std::mutex> lock(dataMutex);

            // Match found
            memcpy(matchedPrivateKey, privateKey, 32);
            memcpy(matchedAddress, address, 20);
            found.store(true, std::memory_order_relaxed);
            secp256k1_context_destroy(ctx);
            return true;
        }
    }

    secp256k1_context_destroy(ctx);
    return false;
}

int main() {
    const std::string targetPrefix = "0000"; // Target prefix to match
    const std::string targetSuffix = "c0de"; // Target suffix to match

    // GPU configurations
    const int blockSize = 256;
    const int numBlocks = 1024;
    unsigned int numKeys = numBlocks * blockSize;

    // Allocate memory for private keys
    uint8_t* h_privateKeys = new uint8_t[numKeys * 32];
    uint8_t* d_privateKeys;
    cudaMalloc(&d_privateKeys, numKeys * 32);

    uint8_t matchedPrivateKey[32];
    uint8_t matchedAddress[20];
    std::atomic<bool> found(false);
    std::atomic<unsigned long long> totalAddressesGenerated(0);

    auto startTime = std::chrono::high_resolution_clock::now();

    // CPU thread for monitoring progress
    std::thread progressThread([&totalAddressesGenerated, &found, startTime]() {
        while (!found.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(10));
            auto currentTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(currentTime - startTime);
            unsigned long long current = totalAddressesGenerated.load();
            double rate = static_cast<double>(current) / duration.count();
            std::cout << "Generated " << current << " addresses in " << duration.count()
                << " seconds (Rate: " << std::fixed << std::setprecision(2) << rate << " addr/s)" << std::endl;
        }
        });

    while (!found.load()) {
        // Step 1: Generate private keys on GPU
        generatePrivateKeys << <numBlocks, blockSize >> > (d_privateKeys, numKeys);
        cudaDeviceSynchronize(); // Ensure kernel execution is complete

        // Step 2: Copy private keys back to host
        cudaMemcpy(h_privateKeys, d_privateKeys, numKeys * 32, cudaMemcpyDeviceToHost);

        // Step 3: Process private keys on host
        if (processPrivateKeys(h_privateKeys, numKeys, targetPrefix, targetSuffix, matchedPrivateKey, matchedAddress, found)) {
            // Verify that the private key corresponds to the address
            std::string addressHex = toHex(matchedAddress, 20);
            std::string checksumAddress = toChecksumAddress(addressHex);

            std::cout << "Match found!" << std::endl;
            std::cout << "Address: " << checksumAddress << std::endl;
            std::cout << "Private Key: 0x" << toHex(matchedPrivateKey, 32) << std::endl;

            // Optionally, generate mnemonic from private key here
            // ...

            break; // Exit the loop after finding a match
        }

        totalAddressesGenerated += numKeys;
    }

    progressThread.join();

    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime);
    std::cout << "Total time: " << duration.count() << " seconds" << std::endl;
    std::cout << "Total addresses generated: " << totalAddressesGenerated << std::endl;

    // Cleanup
    cudaFree(d_privateKeys);
    delete[] h_privateKeys;

    return 0;
}
