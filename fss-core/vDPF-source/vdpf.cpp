#include "vdpf.h"

#include <cstring>
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

}  // namespace

namespace waldo {

VDPFKeyPair VDPF::GenPointVector(
    uint32_t domain_size,
    uint32_t target_index,
    const vector<uint128_t> &payload) {
    if (payload.empty()) {
        throw std::invalid_argument("payload must be non-empty.");
    }
    if (target_index >= domain_size) {
        throw std::out_of_range("target_index out of range.");
    }

    const uint32_t depth = domainDepth(domain_size);
    const uint64_t gout_bitsize = 125;
    const uint128_t group_mod = (uint128_t(1) << gout_bitsize);
    const bool malicious = false;

    VDPFKeyPair out;
    out.key0.domain_size = domain_size;
    out.key0.vec_dim = (uint32_t)payload.size();
    out.key1.domain_size = domain_size;
    out.key1.vec_dim = (uint32_t)payload.size();
    out.key0.scalar_keys.resize(payload.size());
    out.key1.scalar_keys.resize(payload.size());

    for (size_t i = 0; i < payload.size(); i++) {
        dorydb::clkey k;
        k.dpf_generate(target_index, payload[i], depth, gout_bitsize, true, group_mod, malicious);
        const size_t key_size = k.get_keysize();
        out.key0.scalar_keys[i].resize(key_size);
        out.key1.scalar_keys[i].resize(key_size);
        k.dpf_serialize(
            depth,
            (uint8_t *)out.key0.scalar_keys[i].data(),
            (uint8_t *)out.key1.scalar_keys[i].data());
    }
    return out;
}

vector<uint128_t> VDPF::EvalPoint(
    const VDPFKeyPack &keypack,
    uint32_t x,
    uint8_t party_id) {
    if (party_id > 1) {
        throw std::invalid_argument("party_id must be 0 or 1.");
    }
    if (x >= keypack.domain_size) {
        throw std::out_of_range("x out of domain range.");
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
        sk.dpf_size = depth + 1;
        sk.dpf_deserialize(depth, (const uint8_t *)keypack.scalar_keys[i].data());
        sk.init = true;
        uint128_t point_val = 0;
        sk.dpf_eval_contig(
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

vector<vector<uint128_t>> VDPF::EvalAll(
    const VDPFKeyPack &keypack,
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

vector<uint128_t> VDPF::EvalAllFlat(
    const VDPFKeyPack &keypack,
    uint8_t party_id) {
    if (party_id > 1) {
        throw std::invalid_argument("party_id must be 0 or 1.");
    }
    if (keypack.scalar_keys.size() != keypack.vec_dim) {
        throw std::invalid_argument("scalar key vector size mismatch.");
    }

    const uint32_t depth = domainDepth(keypack.domain_size);
    const uint64_t gout_bitsize = 125;
    const uint128_t group_mod = (uint128_t(1) << gout_bitsize);
    const bool malicious = false;

    vector<uint128_t> out((size_t)keypack.domain_size * (size_t)keypack.vec_dim, 0);
    vector<uint128_t> tmp(keypack.domain_size, 0);

    for (uint32_t i = 0; i < keypack.vec_dim; i++) {
        dorydb::svkey sk(malicious);
        sk.role = party_id;
        sk.dpf_size = depth + 1;
        sk.dpf_deserialize(depth, (const uint8_t *)keypack.scalar_keys[i].data());
        sk.init = true;
        std::fill(tmp.begin(), tmp.end(), 0);
        sk.dpf_eval_contig(
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

string VDPF::SerializeKeyPack(const VDPFKeyPack &keypack) {
    string out;
    auto append_u32 = [&](uint32_t v) {
        out.append(reinterpret_cast<const char *>(&v), sizeof(uint32_t));
    };
    append_u32(keypack.domain_size);
    append_u32(keypack.vec_dim);
    append_u32((uint32_t)keypack.scalar_keys.size());
    for (const string &k : keypack.scalar_keys) {
        append_u32((uint32_t)k.size());
        out.append(k);
    }
    return out;
}

VDPFKeyPack VDPF::DeserializeKeyPack(const string &blob) {
    size_t off = 0;
    auto read_u32 = [&](uint32_t &v) {
        if (off + sizeof(uint32_t) > blob.size()) {
            throw std::runtime_error("Invalid serialized VDPF keypack.");
        }
        std::memcpy(&v, blob.data() + off, sizeof(uint32_t));
        off += sizeof(uint32_t);
    };

    VDPFKeyPack pack;
    uint32_t n = 0;
    read_u32(pack.domain_size);
    read_u32(pack.vec_dim);
    read_u32(n);
    pack.scalar_keys.resize(n);
    for (uint32_t i = 0; i < n; i++) {
        uint32_t len = 0;
        read_u32(len);
        if (off + len > blob.size()) {
            throw std::runtime_error("Invalid serialized VDPF keypack payload.");
        }
        pack.scalar_keys[i].assign(blob.data() + off, blob.data() + off + len);
        off += len;
    }
    if (off != blob.size()) {
        throw std::runtime_error("Invalid serialized VDPF keypack trailing bytes.");
    }
    return pack;
}

}  // namespace waldo
