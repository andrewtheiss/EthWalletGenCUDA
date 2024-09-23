#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <vector>
#include <cuda_runtime.h>
#include <curand_kernel.h>
#include <secp256k1.h>
#include <openssl/evp.h>
#include <thread>
#include <atomic>
#include <chrono>

__global__ void generateAndCheckAddresses(
    uint64_t* d_found,
    uint8_t* d_matchedPrivateKey,
    uint8_t* d_matchedAddress,
    uint32_t prefixMask,
    uint32_t prefixBits,
    uint32_t suffixMask,
    uint32_t suffixBits,
    uint32_t prefixLength,
    uint32_t suffixLength) {

    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    curandState state;
    curand_init(clock64(), idx, 0, &state);

    uint8_t privateKey[32];
    uint8_t address[20];

    // Generate private key
    for (int i = 0; i < 32; i++) {
        privateKey[i] = curand(&state) % 256;
    }

    // Simulate address generation (placeholder for actual secp256k1 and keccak256 operations)
    // This is a more complex simulation to better represent the randomness of real address generation
    for (int i = 0; i < 20; i++) {
        uint32_t mix = 0;
        for (int j = 0; j < 32; j++) {
            mix ^= privateKey[(i + j) % 32] << (j % 8);
        }
        address[i] = mix & 0xFF;
    }

    // Check prefix and suffix
    uint32_t addrPrefix = (address[0] << 24) | (address[1] << 16) | (address[2] << 8) | address[3];
    uint32_t addrSuffix = (address[16] << 24) | (address[17] << 16) | (address[18] << 8) | address[19];

    if ((addrPrefix & prefixMask) == prefixBits && (addrSuffix & suffixMask) == suffixBits) {
        if (atomicCAS((unsigned long long*)d_found, 0, 1) == 0) {
            memcpy(d_matchedPrivateKey, privateKey, 32);
            memcpy(d_matchedAddress, address, 20);
        }
    }
}

std::string toHex(const uint8_t* data, size_t length) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

int main() {
    const uint32_t prefixBits = 0xBAD00000;  // Example: "bad" prefix
    const uint32_t suffixBits = 0x0000C0DE;  // Example: "c0de" suffix
    const uint32_t prefixMask = 0xFFF00000;  // Mask for 3 bytes
    const uint32_t suffixMask = 0x0000FFFF;  // Mask for 2 bytes
    const uint32_t prefixLength = 3;
    const uint32_t suffixLength = 4;

    uint64_t* d_found;
    uint8_t* d_matchedPrivateKey;
    uint8_t* d_matchedAddress;
    cudaMalloc(&d_found, sizeof(uint64_t));
    cudaMalloc(&d_matchedPrivateKey, 32 * sizeof(uint8_t));
    cudaMalloc(&d_matchedAddress, 20 * sizeof(uint8_t));
    cudaMemset(d_found, 0, sizeof(uint64_t));

    const int blockSize = 256;
    const int numBlocks = 1024;

    std::atomic<bool> found(false);
    std::atomic<uint64_t> totalAddressesGenerated(0);

    auto startTime = std::chrono::high_resolution_clock::now();

    // CPU thread for monitoring progress
    std::thread progressThread([&totalAddressesGenerated, &found, startTime]() {
        while (!found) {
            std::this_thread::sleep_for(std::chrono::seconds(10));
            auto currentTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(currentTime - startTime);
            uint64_t current = totalAddressesGenerated.load();
            double rate = static_cast<double>(current) / duration.count();
            std::cout << "Generated " << current << " addresses in " << duration.count()
                << " seconds (Rate: " << std::fixed << std::setprecision(2) << rate << " addr/s)" << std::endl;
        }
        });

    while (!found) {
        generateAndCheckAddresses << <numBlocks, blockSize >> > (
            d_found, d_matchedPrivateKey, d_matchedAddress,
            prefixMask, prefixBits, suffixMask, suffixBits,
            prefixLength, suffixLength);

        uint64_t h_found;
        cudaMemcpy(&h_found, d_found, sizeof(uint64_t), cudaMemcpyDeviceToHost);

        if (h_found) {
            found = true;
            uint8_t h_matchedPrivateKey[32];
            uint8_t h_matchedAddress[20];
            cudaMemcpy(h_matchedPrivateKey, d_matchedPrivateKey, 32 * sizeof(uint8_t), cudaMemcpyDeviceToHost);
            cudaMemcpy(h_matchedAddress, d_matchedAddress, 20 * sizeof(uint8_t), cudaMemcpyDeviceToHost);

            std::cout << "Match found!" << std::endl;
            std::cout << "Address: 0x" << toHex(h_matchedAddress, 20) << std::endl;
            std::cout << "Private Key: " << toHex(h_matchedPrivateKey, 32) << std::endl;
        }

        totalAddressesGenerated += numBlocks * blockSize;
    }

    progressThread.join();

    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime);
    std::cout << "Total time: " << duration.count() << " seconds" << std::endl;
    std::cout << "Total addresses generated: " << totalAddressesGenerated << std::endl;

    cudaFree(d_found);
    cudaFree(d_matchedPrivateKey);
    cudaFree(d_matchedAddress);

    return 0;
}