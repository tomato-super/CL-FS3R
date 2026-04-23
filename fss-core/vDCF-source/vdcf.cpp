#include "vdcf.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <stdexcept>

#include "../../secure-indices/core/keys.h"

namespace {

uint32_t domainDepth(uint32_t domain_size) {
    if (domain_size == 0) {
        throw std::invalid_argument("domain_size must be > 0.");
    }
    uint32_t depth = getDepth(domain_size);
    if ((1u << depth) != domain_size) {
        throw std::invalid_argument("domain_size must be power of 2.");
    }
    return depth;
}

struct DCFPlan {
    bool constant;
    bool constant_true;
    bool strict_gt;
    uint32_t idx;
};

DCFPlan makePlan(uint32_t domain_size, waldo::VDCFCompareOp op, uint32_t t) {
    const uint32_t last = domain_size - 1;
    switch (op) {
        case waldo::VDCFCompareOp::LT:
            if (t == 0) return {true, false, false, 0};
            if (t >= domain_size) return {true, true, false, 0};
            return {false, false, false, t}; // x < t
        case waldo::VDCFCompareOp::LE:
            if (t >= last) return {true, true, false, 0};
            return {false, false, false, t + 1}; // x <= t  <=> x < t+1
        case waldo::VDCFCompareOp::GT:
            if (t >= last) return {true, false, true, 0};
            return {false, false, true, t}; // x > t
        case waldo::VDCFCompareOp::GE:
            if (t == 0) return {true, true, true, 0};
            if (t >= domain_size) return {true, false, true, 0};
            return {false, false, true, t - 1}; // x >= t <=> x > t-1
        default:
            throw std::invalid_argument("Unknown VDCF compare op.");
    }
}

}  // namespace

namespace waldo {

VDCFKeyPair VDCF::GenCompareVector(
    uint32_t domain_size,
    VDCFCompareOp op,
    uint32_t threshold,
    const vector<uint128_t> &payload) {
    if (payload.empty()) {
        throw std::invalid_argument("payload must be non-empty.");
    }

    const uint32_t depth = domainDepth(domain_size);
    const uint64_t gout_bitsize = 125;
    const uint128_t group_mod = (uint128_t(1) << gout_bitsize);
    const bool malicious = false;

    DCFPlan plan = makePlan(domain_size, op, threshold);

    VDCFKeyPair out;
    out.key0.domain_size = domain_size;
    out.key0.vec_dim = (uint32_t)payload.size();
    out.key1.domain_size = domain_size;
    out.key1.vec_dim = (uint32_t)payload.size();

    if (plan.constant) {
        out.key0.mode = 1;
        out.key1.mode = 1;
        out.key0.const_values.resize(payload.size(), 0);
        out.key1.const_values.resize(payload.size(), 0);

        if (plan.constant_true) {
            // share payload into two additive shares so each side keeps only a share.
            std::srand((unsigned)std::time(nullptr));
            PRNG prng(toBlock(std::rand(), std::rand()));
            for (size_t i = 0; i < payload.size(); i++) {
                uint128_t r = randFieldElem(&prng);
                out.key0.const_values[i] = r;
                out.key1.const_values[i] = payload[i] - r;
            }
        }
        return out;
    }

    out.key0.mode = 0;
    out.key1.mode = 0;
    out.key0.scalar_keys.resize(payload.size());
    out.key1.scalar_keys.resize(payload.size());

    for (size_t i = 0; i < payload.size(); i++) {
        dorydb::clkey k;
        k.dcf_generate(
            plan.idx,
            payload[i],
            depth,
            gout_bitsize,
            true,
            group_mod,
            false,
            plan.strict_gt,
            malicious,
            0);
        const size_t key_size = k.get_keysize();
        out.key0.scalar_keys[i].resize(key_size);
        out.key1.scalar_keys[i].resize(key_size);
        k.dcf_serialize(
            depth,
            (uint8_t *)out.key0.scalar_keys[i].data(),
            (uint8_t *)out.key1.scalar_keys[i].data());
    }

    return out;
}

vector<uint128_t> VDCF::EvalPoint(
    const VDCFKeyPack &keypack,
    uint32_t x,
    uint8_t party_id) {
    if (party_id > 1) {
        throw std::invalid_argument("party_id must be 0 or 1.");
    }
    if (x >= keypack.domain_size) {
        throw std::out_of_range("x out of domain range.");
    }

    if (keypack.mode == 1) {
        if (keypack.const_values.size() != keypack.vec_dim) {
            throw std::invalid_argument("const value vector size mismatch.");
        }
        return keypack.const_values;
    }

    if (keypack.scalar_keys.size() != keypack.vec_dim) {
        throw std::invalid_argument("scalar key vector size mismatch.");
    }

    const uint32_t depth = domainDepth(keypack.domain_size);
    const uint64_t gout_bitsize = 125;
    const uint128_t group_mod = (uint128_t(1) << gout_bitsize);
    const bool malicious = false;

    vector<uint128_t> out(keypack.vec_dim, 0);
    for (uint32_t i = 0; i < keypack.vec_dim; i++) {
        dorydb::svkey sk(malicious);
        sk.role = party_id;
        sk.dcf_size = depth + 1;
        sk.dcf_deserialize(depth, (const uint8_t *)keypack.scalar_keys[i].data());
        sk.init = true;
        uint128_t point_val = 0;
        sk.dcf_eval_contig(
            &point_val,
            depth,
            x,
            x,
            gout_bitsize,
            true,
            group_mod,
            false);
        out[i] = point_val;
    }
    return out;
}

vector<vector<uint128_t>> VDCF::EvalAll(
    const VDCFKeyPack &keypack,
    uint8_t party_id) {
    vector<uint128_t> flat = EvalAllFlat(keypack, party_id);
    vector<vector<uint128_t>> out(
        keypack.domain_size, vector<uint128_t>(keypack.vec_dim, 0));
    for (uint32_t x = 0; x < keypack.domain_size; x++) {
        for (uint32_t j = 0; j < keypack.vec_dim; j++) {
            out[x][j] = flat[(size_t)x * (size_t)keypack.vec_dim + (size_t)j];
        }
    }
    return out;
}

vector<uint128_t> VDCF::EvalAllFlat(
    const VDCFKeyPack &keypack,
    uint8_t party_id) {
    if (party_id > 1) {
        throw std::invalid_argument("party_id must be 0 or 1.");
    }

    vector<uint128_t> out((size_t)keypack.domain_size * (size_t)keypack.vec_dim, 0);

    if (keypack.mode == 1) {
        if (keypack.const_values.size() != keypack.vec_dim) {
            throw std::invalid_argument("const value vector size mismatch.");
        }
        for (uint32_t x = 0; x < keypack.domain_size; x++) {
            for (uint32_t j = 0; j < keypack.vec_dim; j++) {
                out[(size_t)x * (size_t)keypack.vec_dim + (size_t)j] = keypack.const_values[j];
            }
        }
        return out;
    }

    if (keypack.scalar_keys.size() != keypack.vec_dim) {
        throw std::invalid_argument("scalar key vector size mismatch.");
    }

    const uint32_t depth = domainDepth(keypack.domain_size);
    const uint64_t gout_bitsize = 125;
    const uint128_t group_mod = (uint128_t(1) << gout_bitsize);
    const bool malicious = false;

    vector<uint128_t> tmp(keypack.domain_size, 0);
    for (uint32_t i = 0; i < keypack.vec_dim; i++) {
        dorydb::svkey sk(malicious);
        sk.role = party_id;
        sk.dcf_size = depth + 1;
        sk.dcf_deserialize(depth, (const uint8_t *)keypack.scalar_keys[i].data());
        sk.init = true;
        std::fill(tmp.begin(), tmp.end(), 0);
        sk.dcf_eval_contig(
            tmp.data(),
            depth,
            0,
            keypack.domain_size - 1,
            gout_bitsize,
            true,
            group_mod,
            false);
        for (uint32_t x = 0; x < keypack.domain_size; x++) {
            out[(size_t)x * (size_t)keypack.vec_dim + (size_t)i] = tmp[x];
        }
    }

    return out;
}

string VDCF::SerializeKeyPack(const VDCFKeyPack &keypack) {
    string out;
    auto append_u32 = [&](uint32_t v) {
        out.append(reinterpret_cast<const char *>(&v), sizeof(uint32_t));
    };
    auto append_u8 = [&](uint8_t v) {
        out.append(reinterpret_cast<const char *>(&v), sizeof(uint8_t));
    };

    append_u32(keypack.domain_size);
    append_u32(keypack.vec_dim);
    append_u8(keypack.mode);

    if (keypack.mode == 1) {
        append_u32((uint32_t)keypack.const_values.size());
        for (const uint128_t &v : keypack.const_values) {
            out.append(reinterpret_cast<const char *>(&v), sizeof(uint128_t));
        }
    } else {
        append_u32((uint32_t)keypack.scalar_keys.size());
        for (const string &k : keypack.scalar_keys) {
            append_u32((uint32_t)k.size());
            out.append(k);
        }
    }

    return out;
}

VDCFKeyPack VDCF::DeserializeKeyPack(const string &blob) {
    size_t off = 0;
    auto read_u32 = [&](uint32_t &v) {
        if (off + sizeof(uint32_t) > blob.size()) {
            throw std::runtime_error("Invalid serialized VDCF keypack.");
        }
        std::memcpy(&v, blob.data() + off, sizeof(uint32_t));
        off += sizeof(uint32_t);
    };
    auto read_u8 = [&](uint8_t &v) {
        if (off + sizeof(uint8_t) > blob.size()) {
            throw std::runtime_error("Invalid serialized VDCF keypack.");
        }
        std::memcpy(&v, blob.data() + off, sizeof(uint8_t));
        off += sizeof(uint8_t);
    };

    VDCFKeyPack pack;
    read_u32(pack.domain_size);
    read_u32(pack.vec_dim);
    read_u8(pack.mode);

    uint32_t n = 0;
    read_u32(n);

    if (pack.mode == 1) {
        pack.const_values.resize(n);
        for (uint32_t i = 0; i < n; i++) {
            if (off + sizeof(uint128_t) > blob.size()) {
                throw std::runtime_error("Invalid serialized VDCF const payload.");
            }
            std::memcpy(&pack.const_values[i], blob.data() + off, sizeof(uint128_t));
            off += sizeof(uint128_t);
        }
    } else {
        pack.scalar_keys.resize(n);
        for (uint32_t i = 0; i < n; i++) {
            uint32_t len = 0;
            read_u32(len);
            if (off + len > blob.size()) {
                throw std::runtime_error("Invalid serialized VDCF key payload.");
            }
            pack.scalar_keys[i].assign(blob.data() + off, blob.data() + off + len);
            off += len;
        }
    }

    if (off != blob.size()) {
        throw std::runtime_error("Invalid serialized VDCF trailing bytes.");
    }
    return pack;
}

}  // namespace waldo
