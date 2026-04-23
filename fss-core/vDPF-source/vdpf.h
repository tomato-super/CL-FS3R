#pragma once

#include <string>
#include <vector>

#include "../../secure-indices/core/common.h"

using namespace std;
using namespace osuCrypto;

namespace waldo {

// Minimal vector-output DPF (vDPF):
// Build a vector-output function by packing `vec_dim` independent scalar DPF keys.
struct VDPFKeyPack {
    uint32_t domain_size;
    uint32_t vec_dim;
    // serialized scalar DPF key bytes for each vector coordinate
    vector<string> scalar_keys;
};

struct VDPFKeyPair {
    VDPFKeyPack key0;
    VDPFKeyPack key1;
};

class VDPF {
public:
    // Generate vector-output DPF keys for:
    //   f(x) = payload if x == target_index else 0^vec_dim
    static VDPFKeyPair GenPointVector(
        uint32_t domain_size,
        uint32_t target_index,
        const vector<uint128_t> &payload);

    // Evaluate one side key on input point `x`.
    // party_id must be 0 or 1.
    static vector<uint128_t> EvalPoint(
        const VDPFKeyPack &keypack,
        uint32_t x,
        uint8_t party_id);
    
    // Evaluate one side key on the full domain [0, domain_size-1].
    // Return shape: [domain_size][vec_dim].
    static vector<vector<uint128_t>> EvalAll(
        const VDPFKeyPack &keypack,
        uint8_t party_id);

    // Evaluate one side key on full domain with flat contiguous layout.
    // Return shape: [domain_size * vec_dim], row-major by x then j.
    static vector<uint128_t> EvalAllFlat(
        const VDPFKeyPack &keypack,
        uint8_t party_id);

    static string SerializeKeyPack(const VDPFKeyPack &keypack);
    static VDPFKeyPack DeserializeKeyPack(const string &blob);
};

}  // namespace waldo
