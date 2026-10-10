#include <cstdint>
#include <cstdio>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

static const char marker_a[] = "RADARE3_SEARCH_MARKER_ALPHA";
static const char marker_b[] = "RADARE3_SEARCH_MARKER_BETA";
static const char16_t wide_marker[] = u"RADARE3_WIDE_MARKER";

namespace {

uint64_t mix(uint64_t value) {
    for (uint64_t i = 0; i < 48; ++i) {
        if ((value ^ i) & 1) {
            value = (value * 0x9e3779b185ebca87ULL) ^ (value >> 7);
        } else {
            value = (value + 0x517cc1b727220a95ULL) ^ (value << 11);
        }
    }
    return value;
}

class Transform {
  public:
    virtual ~Transform() = default;
    virtual uint64_t apply(uint64_t value) const = 0;
};

class XorShift final : public Transform {
  public:
    uint64_t apply(uint64_t value) const override {
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        return value;
    }
};

class Multiply final : public Transform {
  public:
    explicit Multiply(uint64_t factor) : factor_(factor) {}
    uint64_t apply(uint64_t value) const override { return value * factor_ + 0x9e3779b9ULL; }

  private:
    uint64_t factor_;
};

template <typename T> T accumulate(const std::vector<T> &items) {
    T total = 0;
    for (const T &item : items) {
        total ^= mix(item);
    }
    return total;
}

uint64_t guarded(uint64_t value) {
    if (value & 0x4000) {
        throw std::runtime_error("odd lane");
    }
    return mix(value);
}

} // namespace

int main(int argc, char **argv) {
    std::vector<uint64_t> values;
    values.reserve(512);
    for (uint64_t i = 0; i < 512; ++i) {
        values.push_back(i * 2654435761ULL + static_cast<uint64_t>(argc));
    }

    std::map<uint64_t, uint64_t> table;
    XorShift xorshift;
    Multiply multiply(6364136223846793005ULL);
    const Transform *chain[] = {&xorshift, &multiply};

    uint64_t acc = 0;
    for (uint64_t value : values) {
        for (const Transform *step : chain) {
            value = step->apply(value);
        }
        try {
            acc ^= guarded(value);
        } catch (const std::runtime_error &) {
            acc += value >> 3;
        }
        table[value & 0xff] = acc;
    }

    acc ^= accumulate(values);
    acc += static_cast<uint64_t>(marker_a[0] + marker_b[1] + wide_marker[2]);

    if (argv != nullptr && argv[0] != nullptr && argv[0][0] == '\0') {
        std::fputs(marker_a, stdout);
        std::fputs(marker_b, stdout);
    }

    std::string label = (argv != nullptr && argv[0] != nullptr) ? argv[0] : "r3bench-cpp";
    std::printf("%s %llu\n", label.c_str(), static_cast<unsigned long long>(acc));
    return 0;
}
