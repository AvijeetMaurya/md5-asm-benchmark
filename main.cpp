#include <chrono>
#include <memory>
#include <vector>
#include <iostream>
#include <random>
#include <numeric>
#include <string_view>

struct Packet {
    std::unique_ptr<unsigned char[]> buf;
    int size;
};

void printMD5(unsigned char* out) {
    for (int i = 0; i < 16; ++i) {
        std::cout << std::hex << static_cast<int>(out[i]);
    }
    std::cout << '\n';
}

void randomizeBuffer(std::unique_ptr<unsigned char[]>& buf, int packetSize) {
    for (int i = 0; i < packetSize; ++i) {
        buf[i] = static_cast<unsigned char>(std::rand() % 256);
    }
}

void randomizePackets(std::vector<Packet>& packets) {
    int count = 1000000;
    while (count--) {
        int packetSize = std::rand() % 200 + 100;
        auto buf = std::make_unique<unsigned char[]>(packetSize);
        randomizeBuffer(buf, packetSize);
        packets.push_back({std::move(buf), packetSize});
    }
}

void randomizeIndices(std::vector<int>& indices, int count) {
    indices.resize(count);
    std::iota(indices.begin(), indices.end(), 0);
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(indices.begin(), indices.end(), g);
}

#include <cstring>
#include "md5-x86-asm.h"

template<typename HT>
void md5_init(volatile MD5_STATE<HT>* state) {
	state->A = 0x67452301;
	state->B = 0xefcdab89;
	state->C = 0x98badcfe;
	state->D = 0x10325476;
}

template<typename HT, void(&fn)(MD5_STATE<HT>*, const void*)>
void md5(volatile MD5_STATE<HT>* state, const void* __restrict__ src, size_t len) {
	md5_init<HT>(state);
	char* __restrict__ _src = (char* __restrict__)src;
	uint64_t totalLen = len << 3; // length in bits
	
	for(; len >= 64; len -= 64) {
		fn(state, _src);
		_src += 64;
	}
	len &= 63;
	
	
	// finalize
	char block[64];
	memcpy(block, _src, len);
	block[len++] = 0x80;
	
	// write this in a loop to avoid duplicating the force-inlined process_block function twice
	for(int iter = (len <= 64-8); iter < 2; iter++) {
		if(iter == 0) {
			memset(block + len, 0, 64-len);
			len = 0;
		} else {
			memset(block + len, 0, 64-8 - len);
			memcpy(block + 64-8, &totalLen, 8);
		}
		fn(state, block);
	}
}

template<void(&fn)(MD5_STATE<uint32_t>*, const void*)>
auto externalMD5(std::string_view name, std::vector<Packet>& packets, std::vector<int>& indices) {
    volatile MD5_STATE<uint32_t> hash;
    auto start = std::chrono::system_clock::now();
    for (const int index : indices) {
        md5<uint32_t, fn>(&hash, packets[index].buf.get(), packets[index].size);
    }
    auto end = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    std::cout << name << ": " << elapsed.count() / static_cast<double>(packets.size()) << "ns \n";
    return elapsed.count();
}

#include <openssl/md5.h>

void calculate_md5(const void* buf, size_t buf_size, unsigned char* res) {
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations" 
    MD5(static_cast<const unsigned char*>(buf), buf_size, res);
    #pragma GCC diagnostic pop
}

auto deprecatedMD5(std::vector<Packet>& packets, std::vector<int>& indices) {
    auto start = std::chrono::system_clock::now();
    auto out = std::make_unique<unsigned char[]>(16);
    for (const int index : indices) {
        calculate_md5(packets[index].buf.get(), packets[index].size, out.get());
    }
    auto end = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    std::cout << "openssl deprecated md5: " << elapsed.count() / static_cast<double>(packets.size()) << "ns \n";
    return elapsed.count();
}

int main() {
    std::srand(time(0));
    std::vector<Packet> packets;
    std::vector<int> indices;
    randomizePackets(packets);
    randomizeIndices(indices, packets.size());

    auto baseline = deprecatedMD5(packets, indices);
    std::cout << (static_cast<double>(baseline - externalMD5<md5_block_std>("std", packets, indices)) / baseline) * 100 << "%\n";
    std::cout << (static_cast<double>(baseline - externalMD5<md5_block_gopt>("GOpt", packets, indices)) / baseline) * 100 << "%\n";
    std::cout << (static_cast<double>(baseline - externalMD5<md5_block_ghopt>("GHOpt", packets, indices)) / baseline) * 100 << "%\n";
    std::cout << (static_cast<double>(baseline - externalMD5<md5_block_nolea>("NoLEA", packets, indices)) / baseline) * 100 << "%\n";
    std::cout << (static_cast<double>(baseline - externalMD5<md5_block_noleag>("NoL-G", packets, indices)) / baseline) * 100 << "%\n";
    std::cout << (static_cast<double>(baseline - externalMD5<md5_block_noleagh>("NoL-GH", packets, indices)) / baseline) * 100 << "%\n";
    std::cout << (static_cast<double>(baseline - externalMD5<md5_block_cache4>("Cache4", packets, indices)) / baseline) * 100 << "%\n";
    std::cout << (static_cast<double>(baseline - externalMD5<md5_block_cache8>("Cache8", packets, indices)) / baseline) * 100 << "%\n";
    std::cout << (static_cast<double>(baseline - externalMD5<md5_block_cache_gopt>("Cache8G", packets, indices)) / baseline) * 100 << "%\n";
}