#include <iostream>
#include <chrono>
#include <array>
#include <fstream>
#include <vector>
#include <unordered_set>
#include <cassert>
#include "bruteforce_range.h"
#include "nlohmann/json.hpp"

using json = nlohmann::json;

// Count how many bits of the suffix are "varying".
// For example, for :
// a=10010001
// b=10010111
// the common prefix is [10010] and the suffix is [001] or [111] - 3 bits
uint64_t variable_suffix_bits(uint64_t a, uint64_t b) {
    uint64_t suffix_len = 0;
    while (a != b) {
        suffix_len += 1;
        a >>= 1;
        b >>= 1;
    }
    return suffix_len;
}

void BruteforceRange::perfcounter_xor_set() {
    uint64_t min_pc = perfcounter_.get();
    uint64_t max_pc = perfcounter_.get() + MAX_TICKS_DIFF;

    uint64_t min_gtc = gettickcount_.min();
    uint64_t max_gtc = gettickcount_.max();

    uint64_t gtc_bits = variable_suffix_bits(min_gtc, max_gtc);

    uint64_t pc_step = uint64_t{1} << gtc_bits;
    uint64_t pc_mask = ~(pc_step - uint64_t{1});

    uint64_t gtc_prefix = (min_gtc & pc_mask);
    uint64_t min_pc2 = min_pc ^ gtc_prefix;
    uint64_t max_pc2 = max_pc ^ gtc_prefix;
    if (max_pc2 < min_pc2) {
        std::swap(min_pc2, max_pc2);
    }

    uint64_t min_pc3 = (min_pc2 & pc_mask);
    uint64_t max_pc3 = (max_pc2 & pc_mask) + pc_step;

    perfcounter_xor_ = BruteforceParam<uint64_t>(min_pc3, max_pc3);
}

// Moves the internal state one step forward. Returns false if the range is done.
bool BruteforceRange::forward() {
    if (perfcounter_xor_.next()) {
        return true;
    }

    tried_++;
    if (perfcounter_.next()) {
        perfcounter_xor_set();
        return true;
    }
    perfcounter_xor_set();

    if (filetime_.next()) {
        return true;
    }

    tids_.pop_back();
    if (tids_.size()) {
        // There are some TIDs to check left.
        return true;
    }

    return false;
}

BruteforceRange::BruteforceRange( uint32_t pid, std::vector<uint32_t> tids, BruteforceParam<uint32_t> gettickcount,
        BruteforceParam<uint64_t> filetime, BruteforceParam<uint64_t> perfcounter)
    :pid_(pid), tids_(tids), gettickcount_(gettickcount), filetime_(filetime), perfcounter_(perfcounter), perfcounter_xor_(0, 0),
    tried_(0) { // hardcoded perfcount_diff
        keyspace_ = tids_.size() * filetime_.keyspace() * perfcounter_.keyspace();
        start_when_ = 0;
        done_when_ = keyspace_;
        perfcounter_xor_set();
    }

// Returns false if the range is done, otherwise sets new key in packet.
bool BruteforceRange::next(Packet target, PacketStatus *status) {
    while (tried_ < start_when_) {
        forward();
    }

    if (!forward() || tried_ > done_when_) {
        *status = PacketStatus::Done;
        return false;
    }

    // prepare the packet for next GPU task
    *status = PacketStatus::InProgress;

    uint32_t key[8];
    key[0] = perfcounter_xor_.get();
    key[1] = (perfcounter_.get() >> 32) & 0xFFFFFFFF;
    key[2] = perfcounter_.get() & 0xFFFFFFFF;
    key[3] = pid_;
    key[4] = tids_.back();
    key[5] = (filetime_.get() >> 32) & 0xFFFFFFFF;
    key[6] = filetime_.get() & 0xFFFFFFFF;
    key[7] = (perfcounter_.get() >> 32) & 0xFFFFFFFF; // with high probability

    memcpy(target, key, 32);

    return true;
}

// How many keys were tried?
uint64_t BruteforceRange::current() const { return tried_; }

// How many keys are there to try?
uint64_t BruteforceRange::keyspace() const { return keyspace_; }

double BruteforceRange::progress() const { 
    uint64_t done = tried_ - start_when_;
    return static_cast<double>(done) / (done_when_ - start_when_ + 1);
}


BruteforceRange BruteforceRange::parse(std::string path) {
    std::ifstream i(path);
    json j;
    i >> j;

    uint32_t pid = j["pid"];
    std::vector<uint32_t> tids = j["tid"];

    json g = j["gettickcount"];
    json p = j["perfcounter"];
    json f = j["filetime"];

    BruteforceParam<uint32_t> gettickcount(g["min"], g["max"], g["step"]);
    BruteforceParam<uint64_t> filetime(f["min"], f["max"], f["step"]);
    BruteforceParam<uint64_t> perfcounter(p["min"], p["max"], p["step"]);

    return BruteforceRange(pid, tids, gettickcount, filetime, perfcounter);
}

void BruteforceRange::limits(uint64_t start, uint64_t end) {
    // TODO do it in a more optimal way
    start_when_ = start;
    done_when_ = end;
}
