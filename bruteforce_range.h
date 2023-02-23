#pragma once

#include <iostream>
#include <chrono>
#include <array>
#include <fstream>
#include <vector>
#include <unordered_set>
#include <cassert>

enum class PacketStatus : uint32_t {
    InProgress = 1,
    Done = 2,
};

typedef unsigned char Packet[32];

struct Packets
{
    PacketStatus *statuses;
    Packet *data;
};

using Block16 = std::array<uint8_t, 16>;

const int SHA_ROUNDS = 64;
const int BATCH_SIZE = 16 * 1024 * 1024;
// const unsigned int PACKETS_SIZE = BATCH_SIZE * sizeof(Packet);

const uint64_t MAX_TICKS_DIFF = 1000;

template <typename T>
class BruteforceParam {
    T min_;
    T max_;
    T current_;
    T step_;

public:
    BruteforceParam(T min, T max, T step=1) :min_(min), max_(max), current_(min), step_(step) {
        assert(step != 0);
        assert(min <= max);
        assert((max - min) % step == 0);
    }

    T get() const { return current_; }

    T min() const { return min_; }

    T max() const { return max_; }

    T keyspace() const { return (max_ - min_ + step_) / step_; }

    // Increases current. value. Returns false on overflow.
    bool next() {
        if (current_ < max_) {
            current_ += step_;
            return true;
        }
        current_ = min_;
        return false;
    }
};

class BruteforceRange {
    // For work progress calculation
    uint32_t tried_;
    uint32_t keyspace_;

    uint32_t pid_;

    std::vector<uint32_t> tids_;

    uint64_t start_when_;  // start bruting at this chunk
    uint64_t done_when_;  // stop bruting at this chunk

    BruteforceParam<uint32_t> gettickcount_;
    BruteforceParam<uint64_t> filetime_;
    BruteforceParam<uint64_t> perfcounter_;
    BruteforceParam<uint64_t> perfcounter_xor_;

    void perfcounter_xor_set();

    // Moves the internal state one step forward. Returns false if the range is done.
    bool forward();

public:
    BruteforceRange( uint32_t pid, std::vector<uint32_t> tids, BruteforceParam<uint32_t> gettickcount,
            BruteforceParam<uint64_t> filetime, BruteforceParam<uint64_t> perfcounter);

    // Returns false if the range is done, otherwise sets new key in packet.
    bool next(Packet target, PacketStatus *status);

    // How many keys were tried?
    uint64_t current() const;

    // How many keys are there to try?
    uint64_t keyspace() const;

    double progress() const;

    static BruteforceRange parse(std::string path);

    void limits(uint64_t start, uint64_t end);
};
