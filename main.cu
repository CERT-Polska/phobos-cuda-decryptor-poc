#include <iostream>
#include <chrono>
#include <array>
#include <fstream>
#include <vector>
#include <unordered_set>
#include <cassert>
#include "sha256.cuh"
#include "aes256.h"
#include "bruteforce_range.h"

__device__ const uint8_t key_high[] = {
    0x0d, 0xdb, 0x95, 0x0c, 0x33, 0x68, 0xc0, 0xa0,
    0x06, 0xe9, 0x0c, 0x24, 0x44, 0x88, 0x1b, 0x12,
};

__global__
void aes_decrypt(unsigned int n, Packet packets[], PacketStatus statuses[], uint8_t* ciphertext)
{
    int thread_id = blockIdx.x * blockDim.x + threadIdx.x;
    if (thread_id >= n) {return;}

    // do not decrypt unfinished packets
    if (statuses[thread_id] != PacketStatus::Done) {
        return;
    }

    // Upper half of the key is constant
    uint8_t key[32];
    mycpy16((uint32_t*)key, (uint32_t*)packets[thread_id]);
    mycpy16((uint32_t*)(key+16), (uint32_t*)key_high);

    uint8_t block[16];
    mycpy16((uint32_t*)block, (uint32_t*)ciphertext);

    aes256_context ctx; 
    aes256_init(&ctx, key);
    aes256_decrypt_ecb(&ctx, block);

    mycpy16((uint32_t*)packets[thread_id], (uint32_t*)block);
}

__global__
void sha_rounds(unsigned int n, Packet packets[], PacketStatus statuses[])
{
    int thread_id = blockIdx.x * blockDim.x + threadIdx.x;

    if (statuses[thread_id] == PacketStatus::Done) {
        return;
    }

    if (thread_id >= n) {
        return;
    }

    uint32_t data[8];
    mycpy32(data, (uint32_t*)packets[thread_id]);

    #pragma unroll 8
    for (int i = 0; i < 8; ++i) {
        data[i] = __byte_perm(data[i], 0, 0x123);
    }

    // TODO: Check if the first round is always applied or not
    for (int round=0; round<SHA_ROUNDS; round++) {
        bool is_done = (data[0] & 0xFF000000) == 0 && round != 0;
        sha256_transform(data);

        if (is_done) {
            statuses[thread_id] = PacketStatus::Done;
            break;
        }
    }

    #pragma unroll 8
    for (int i = 0; i < 8; ++i)
        data[i] = __byte_perm(data[i], 0, 0x123);

    mycpy32((uint32_t *)packets[thread_id], data);
}

class PhobosInstance {
    Block16 plaintext_;
    Block16 iv_;
    Block16 ciphertext_;
    Block16 plaintex_cbc_;

public:
    PhobosInstance(Block16 plaintext, Block16 iv, Block16 ciphertext)
        :plaintext_(plaintext), iv_(iv), ciphertext_(ciphertext), plaintex_cbc_(plaintext) {
            for (int x=0; x<16; x++){
                plaintex_cbc_[x] ^= iv[x];
            }
        }

public:
    const Block16 &plaintext() const { return plaintext_; }
    const Block16 &iv() const { return iv_; }
    const Block16 &ciphertext() const { return ciphertext_; }
    const Block16 &plaintext_cbc() const { return plaintex_cbc_; }

    static PhobosInstance load(const std::string &plain, const std::string &encrypted) {
        Block16 plaintext, iv, ciphertext;

        std::ifstream plainf(plain, std::ios::binary);
        plainf.exceptions(std::ifstream::badbit);
        plainf.read(reinterpret_cast<char*>(plaintext.data()), 16);

        std::ifstream cipherf(encrypted, std::ios::binary);
        cipherf.exceptions(std::ifstream::badbit);
        cipherf.read(reinterpret_cast<char*>(ciphertext.data()), 16);

        // Encrypted file format:
        //     data: N bytes
        //     footer: 172 bytes
        // Footer format (interesting fields):
        //      iv: 20:36 bytes
        //      padded_size: 36:40 bytes
        //      encrypted_key: 40:168 bytes
        //      footer_total_size: 168:170 bytes
        cipherf.seekg(-158, std::ios::end);
        cipherf.read(reinterpret_cast<char*>(iv.data()), 16);

        return PhobosInstance(plaintext, iv, ciphertext);
    }
};

// Checks if we found the needle. Returns true if the work is done.
bool find_needle(const PhobosInstance &phobos, Packet packets[], PacketStatus statuses[], uint32_t size) {
    for (int i = 0; i < size; i++) {
        if (statuses[i] != PacketStatus::Done) {
            continue;
        }

        // check if decrypted value matches the iv-xored plaintext
        if (memcmp(packets[i], phobos.plaintext_cbc().data(), 16) == 0) {
            std::cout << "Found... something?\n";
            for(int q=0; q<32; q++){
                printf("%02x", packets[i][q]);
            }
            std::cout << ("\n");
            return true;
        }
    }
    return false;
}

// Rotate finished keys. Returns true if the full range is scanned.
bool rotate_keys(BruteforceRange *range, Packet packets[], PacketStatus statuses[], uint32_t size) {
    bool any_tasks_in_progress = false;
    for (int i = 0; i < size; i++) {
        if (statuses[i] != PacketStatus::Done) {
            any_tasks_in_progress = true;
            continue;
        }
        if (!range->next(packets[i], &statuses[i])) {
            std::cout << "No more things to try!\n";
            return !any_tasks_in_progress;
        }
        any_tasks_in_progress = true;
    }
    return !any_tasks_in_progress;
}

void brute(const PhobosInstance &phobos, BruteforceRange *range) {
    auto gt1 = std::chrono::high_resolution_clock::now();
    std::cout << "Okay, let's crack some keys!\n";

    Packets packets_gpu, packets_cpu;
    uint8_t *ciphertext_gpu;

    cudaMallocHost(&packets_cpu.data, BATCH_SIZE * sizeof(Packet));
    cudaMalloc(&packets_gpu.data, BATCH_SIZE * sizeof(Packet));

    cudaMallocHost(&packets_cpu.statuses, BATCH_SIZE * sizeof(PacketStatus));
    cudaMalloc(&packets_gpu.statuses, BATCH_SIZE * sizeof(PacketStatus));

    cudaMalloc(&ciphertext_gpu, 16);

    // Initialise all the packets to the finished state.
    for (int x=0; x<BATCH_SIZE; x++){
        packets_cpu.statuses[x] = PacketStatus::Done;
    }
    cudaMemcpy(packets_gpu.data, packets_cpu.data, BATCH_SIZE * sizeof(Packet), cudaMemcpyHostToDevice);
    cudaMemcpy(packets_gpu.statuses, packets_cpu.statuses, BATCH_SIZE * sizeof(PacketStatus), cudaMemcpyHostToDevice);
    cudaMemcpy(ciphertext_gpu, phobos.ciphertext().data(), 16, cudaMemcpyHostToDevice);

    while(true) {
        float percent = range->progress() * 100.0;
        std::cout << "\nState: " << range->current() << " (" << percent << "%)\n";
        auto t1 = std::chrono::high_resolution_clock::now();

        std::cout << "Starting the SHA task\n";
        sha_rounds<<<16*2048, 512>>>(BATCH_SIZE, packets_gpu.data, packets_gpu.statuses);

        std::cout << "Starting the AES task\n";
        aes_decrypt<<<16*2048, 512>>>(BATCH_SIZE, packets_gpu.data, packets_gpu.statuses, ciphertext_gpu);

        std::cout << "Waiting for tasks\n";
        cudaMemcpy(packets_cpu.data, packets_gpu.data, BATCH_SIZE * sizeof(Packet), cudaMemcpyDeviceToHost);
        cudaMemcpy(packets_cpu.statuses, packets_gpu.statuses, BATCH_SIZE * sizeof(PacketStatus), cudaMemcpyDeviceToHost);

        std::cout << "Doing the CPU task\n";
        if (find_needle(phobos, packets_cpu.data, packets_cpu.statuses, BATCH_SIZE)) {
            return;
        }
        if (rotate_keys(range, packets_cpu.data, packets_cpu.statuses, BATCH_SIZE)) {
            return;
        }
        std::cout << "CPU task done!\n";

        // copy the next batch of tasks to GPU
        cudaMemcpyAsync(packets_gpu.data, packets_cpu.data, BATCH_SIZE * sizeof(Packet), cudaMemcpyHostToDevice);
        cudaMemcpyAsync(packets_gpu.statuses, packets_cpu.statuses, BATCH_SIZE * sizeof(PacketStatus), cudaMemcpyHostToDevice);

        auto t2 = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>( t2 - t1 ).count();
        std::cout << "Batch has taken: " << ((float)duration/1000000) << "s" << std::endl << std::endl;
    }

    auto gt2 = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>( gt2 - gt1 ).count();
    std::cout << "Total time: " << ((float)duration/1000000) << std::endl;

    cudaFree(packets_cpu.data);
    cudaFree(packets_gpu.data);
    cudaFree(packets_cpu.statuses);
    cudaFree(packets_gpu.statuses);

    return;
}

int main(int argc, char *argv[]) {
    if (argc <= 2) {
        std::cout << "./bruter keyspace [config]" << std::endl;
        std::cout << "./bruter crack [config] [clear_file] [enc_file] [start] [end]" << std::endl;
        return 1;
    }

    BruteforceRange range = BruteforceRange::parse(argv[2]);

    if (std::string(argv[1]) == "keyspace") {
        std::cout << range.keyspace() << std::endl;
        return 0;
    }
    if (std::string(argv[1]) == "crack") {
        char* endx;
        uint64_t start = std::strtoull(argv[5], &endx, 10);
        uint64_t end = std::strtoull(argv[6], &endx, 10);
        range.limits(start, end);
        PhobosInstance phobos = PhobosInstance::load(argv[3], argv[4]);
        brute(phobos, &range);
        return 0;
    }
    std::cout << "No, I don't think I will\n";
    return 2;
}
