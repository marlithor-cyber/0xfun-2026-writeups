#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <z3++.h>

namespace {

constexpr uint64_t A = 2862933555777941757ULL;
constexpr uint64_t C = 3037000493ULL;
constexpr uint32_t A_HI = static_cast<uint32_t>(A >> 32);
constexpr uint32_t A_LO = static_cast<uint32_t>(A);
constexpr uint32_t C_HI = static_cast<uint32_t>(C >> 32);
constexpr uint32_t C_LO = static_cast<uint32_t>(C);

uint64_t next_state(uint64_t state) {
    return A * state + C;
}

uint64_t mod_inverse_odd_64(uint64_t x) {
    uint64_t inv = 1;
    for (int i = 0; i < 6; ++i) {
        inv *= 2 - x * inv;
    }
    return inv;
}

uint64_t recover_seed(const std::vector<uint32_t>& glimpses) {
    if (glimpses.size() < 2) {
        throw std::runtime_error("need at least two glimpses");
    }

    z3::context ctx;
    z3::solver solver = z3::tactic(ctx, "qfbv").mk_solver();

    std::vector<z3::expr> lows;
    lows.reserve(glimpses.size());
    for (size_t i = 0; i < glimpses.size(); ++i) {
        lows.push_back(ctx.bv_const(("x" + std::to_string(i + 1)).c_str(), 32));
    }

    const z3::expr a_hi = ctx.bv_val(A_HI, 32);
    const z3::expr a_lo = ctx.bv_val(A_LO, 32);
    const z3::expr c_hi = ctx.bv_val(C_HI, 32);
    const z3::expr c_lo64 = ctx.bv_val(static_cast<uint64_t>(C_LO), 64);

    for (size_t i = 0; i + 1 < glimpses.size(); ++i) {
        z3::expr xi64 = z3::zext(lows[i], 32);
        z3::expr prod = z3::zext(a_lo, 32) * xi64 + c_lo64;
        z3::expr carry = prod.extract(63, 32);
        z3::expr next_low = prod.extract(31, 0);

        solver.add(lows[i + 1] == next_low);

        z3::expr next_high =
            a_hi * lows[i] + ctx.bv_val(glimpses[i], 32) * a_lo + c_hi + carry;
        solver.add(next_high == ctx.bv_val(glimpses[i + 1], 32));
    }

    if (solver.check() != z3::sat) {
        throw std::runtime_error("no seed satisfies the supplied glimpses");
    }

    z3::model model = solver.get_model();
    uint64_t first_state =
        (static_cast<uint64_t>(glimpses[0]) << 32) |
        static_cast<uint64_t>(model.eval(lows[0]).get_numeral_uint64());

    uint64_t a_inv = mod_inverse_odd_64(A);
    return a_inv * (first_state - C);
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "usage: " << argv[0] << " <g1> <g2> <g3> [more_glimpses...]\n";
        return 1;
    }

    std::vector<uint32_t> glimpses;
    glimpses.reserve(argc - 1);
    for (int i = 1; i < argc; ++i) {
        unsigned long long v = std::stoull(argv[i]);
        if (v > 0xffffffffULL) {
            throw std::runtime_error("glimpse must fit in 32 bits");
        }
        glimpses.push_back(static_cast<uint32_t>(v));
    }

    uint64_t seed = recover_seed(glimpses);
    std::cout << "seed=" << seed << "\n";

    uint64_t cur = seed;
    for (size_t i = 0; i < glimpses.size(); ++i) {
        cur = next_state(cur);
    }

    std::cout << "next_full_states:";
    for (int i = 0; i < 5; ++i) {
        cur = next_state(cur);
        std::cout << (i == 0 ? " " : " ") << cur;
    }
    std::cout << "\n";

    return 0;
}
