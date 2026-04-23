#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "../../secure-indices/core/common.h"

using namespace std;
using namespace osuCrypto;

namespace waldo {

enum class VDCFCompareOp : uint8_t {
    LT = 0,  // x < t
    LE = 1,  // x <= t
    GT = 2,  // x > t
    GE = 3   // x >= t
};

// Minimal vector-output DCF (vDCF):
// Build a vector-output comparison function by packing `vec_dim` scalar DCF keys.
struct VDCFKeyPack {
    uint32_t domain_size = 0;
    uint32_t vec_dim = 0;
    // mode = 0: use scalar dcf keys.
    // mode = 1: constant output share for every x.
    uint8_t mode = 0;

    // serialized scalar DCF key bytes for each vector coordinate
    vector<string> scalar_keys;

    // valid when mode == 1, size must equal vec_dim
    vector<uint128_t> const_values;
};

struct VDCFKeyPair {
    VDCFKeyPack key0;
    VDCFKeyPack key1;
};

class VDCF {
public:
    // Generate vector-output DCF keys for:
    //   f(x) = payload if x op threshold else 0^vec_dim
    // where op in {<, <=, >, >=}.
    static VDCFKeyPair GenCompareVector(
        uint32_t domain_size,
        VDCFCompareOp op,
        uint32_t threshold,
        const vector<uint128_t> &payload);

    // Evaluate one side key on input point `x`.
    // party_id must be 0 or 1.
    static vector<uint128_t> EvalPoint(
        const VDCFKeyPack &keypack,
        uint32_t x,
        uint8_t party_id);

    // Evaluate one side key on full domain [0, domain_size-1].
    // Return shape: [domain_size][vec_dim].
    static vector<vector<uint128_t>> EvalAll(
        const VDCFKeyPack &keypack,
        uint8_t party_id);

    // Evaluate one side key on full domain with flat contiguous layout.
    // Return shape: [domain_size * vec_dim], row-major by x then j.
    static vector<uint128_t> EvalAllFlat(
        const VDCFKeyPack &keypack,
        uint8_t party_id);

    static string SerializeKeyPack(const VDCFKeyPack &keypack);
    static VDCFKeyPack DeserializeKeyPack(const string &blob);
};

}  // namespace waldo
