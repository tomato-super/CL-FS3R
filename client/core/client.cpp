// Modified by Waldo derivative maintainers on 2026-04-23.
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <string>
#include <math.h>
#include <assert.h>
#include <chrono>
#include <cstdlib>

#include "client.h"
#include "query.h"
#include "../../secure-indices/core/DCFTable.h"
#include "../../secure-indices/core/DPFTable.h"
#include "../../network/core/query.grpc.pb.h"
#include "../../network/core/query.pb.h"
#include "../../secure-indices/core/common.h"
#include "../../fss-core/vDPF-source/vdpf.h"
#include "../../fss-core/vDCF-source/vdcf.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using grpc::CompletionQueue;
using grpc::ClientAsyncResponseReader;

using dbquery::Query;
using dbquery::Aggregate;
using dbquery::InitDCFRequest;
using dbquery::InitDCFResponse;
using dbquery::InitDPFRequest;
using dbquery::InitDPFResponse;
using dbquery::InitListRequest;
using dbquery::InitListResponse;
using dbquery::InitATRequest;
using dbquery::InitATResponse;
using dbquery::UpdateDCFRequest;
using dbquery::BatchedUpdateDCFRequest;
using dbquery::UpdateDCFResponse;
using dbquery::BatchedUpdateDCFResponse;
using dbquery::UpdateDPFRequest;
using dbquery::BatchedUpdateDPFRequest;
using dbquery::UpdateDPFResponse;
using dbquery::BatchedUpdateDPFResponse;
using dbquery::UpdateListRequest;
using dbquery::BatchedUpdateListRequest;
using dbquery::UpdateListResponse;
using dbquery::BatchedUpdateListResponse;
using dbquery::AppendAT1Request;
using dbquery::AppendAT1Response;
using dbquery::AppendAT2Request;
using dbquery::AppendAT2Response;
using dbquery::QueryDCFRequest;
using dbquery::QueryDCFResponse;
using dbquery::QueryATRequest;
using dbquery::QueryATResponse;
using dbquery::QueryAggRequest;
using dbquery::QueryAggResponse;
using dbquery::BaseFilter;
using dbquery::CombinedFilter;


using dbquery::BaseVBFilter;
using dbquery::CombinedVBFilter;
using dbquery::BaseVBFSSFilter;
using dbquery::CombinedVBFSSFilter;
using dbquery::BaseBOFilter;
using dbquery::CombinedBOFilter;
using dbquery::BaseBOFSSFilter;
using dbquery::CombinedBOFSSFilter;
using dbquery::QueryVBAggResponse;
using dbquery::QueryVBAggRequest;
using dbquery::QueryVBFSSAggResponse;
using dbquery::QueryVBFSSAggRequest;
using dbquery::QueryBOAggResponse;
using dbquery::QueryBOAggRequest;
using dbquery::QueryBOFSSAggResponse;
using dbquery::QueryBOFSSAggRequest;
using dbquery::UpdateOneHotTableRequest;
using dbquery::UpdateOneHotTableResponse;
using dbquery::UpdateOneHotTableBatchRequest;
using dbquery::UpdateOneHotTableBatchResponse;
using dbquery::InitOneHotTableRequest;
using dbquery::InitOneHotTableResponse;
using dbquery::InitBOTableRequest;
using dbquery::InitBOTableResponse;
using dbquery::UpdateBOTableRequest;
using dbquery::UpdateBOTableResponse;
using dbquery::UpdateBOTableBatchRequest;
using dbquery::UpdateBOTableBatchResponse;


using namespace dorydb;
using namespace osuCrypto;
using namespace std;

namespace {
// Keep batched protobuf requests comfortably below protobuf's hard 2GB limit.
// We target a conservative payload budget so framing/metadata still fit.
constexpr size_t kTargetBatchPayloadBytes = 64ull * 1024ull * 1024ull;  // 64 MiB

size_t ComputeSafeUpdateChunk(size_t units_per_update) {
    // Each update carries two byte fields with `units_per_update` uint128 elements.
    // payload ~= 2 * units_per_update * sizeof(uint128_t)
    const size_t bytes_per_update = 2ull * units_per_update * sizeof(uint128_t);
    if (bytes_per_update == 0) {
        return UPDATE_CHUNK_SZ;
    }
    const size_t by_bytes = std::max<size_t>(1, kTargetBatchPayloadBytes / bytes_per_update);
    return std::min<size_t>(UPDATE_CHUNK_SZ, by_bytes);
}

}  // namespace

QueryClient::QueryClient(vector<shared_ptr<grpc::Channel>> channels, bool malicious) {
    for (int i = 0; i < NUM_SERVERS; i++) {
        queryStubs.push_back(Query::NewStub(channels[i]));
        aggStubs.push_back(Aggregate::NewStub(channels[i]));
    }
    block seed = toBlock(rand(), rand());
    prng = new PRNG(seed);
    this->malicious = malicious;
}

void QueryClient::RegisterDCFTableMeta(string id, uint32_t windowSize, uint32_t numBuckets) {
    int numBucketsLog = getDepth(numBuckets);
    if (DCFTables.count(id) != 0) {
        delete DCFTables[id];
    }
    DCFTables[id] = new DCFTableClient(id, numBucketsLog, windowSize, malicious);
    alpha = DCFTables[id]->alpha;
}

void QueryClient::AddDCFTable(string id, uint32_t windowSize, uint32_t numBuckets, vector<uint32_t> &data) {
    RegisterDCFTableMeta(id, windowSize, numBuckets);

    /* Initialize table at servers. */
    for (int i = 0; i < NUM_SERVERS; i++) {
        InitDCFRequest req;
        InitDCFResponse resp;
        ClientContext ctx;
        req.set_id(id);
        req.set_window_size(windowSize);
        req.set_num_buckets(numBuckets);
        req.set_malicious(malicious);
        queryStubs[i]->SendDCFInit(&ctx, req, &resp);
    }

    /* Load data. */
    assert(data.size() >= windowSize);

    const size_t chunk_sz = ComputeSafeUpdateChunk(numBuckets);
    for (size_t batch_start = 0; batch_start < windowSize; batch_start += chunk_sz) {
        BatchedUpdateDCFRequest reqs[NUM_SERVERS];
        const size_t batch_end = std::min<size_t>(windowSize, batch_start + chunk_sz);
        const size_t batch_id = batch_start / chunk_sz;
        const size_t batch_cnt = (windowSize + chunk_sz - 1) / chunk_sz;
        printf("batch = %zu/%zu\n", batch_id, batch_cnt);
        for (size_t idx = batch_start; idx < batch_end; idx++) {
            UpdateDCFRequest *tmp_reqs[NUM_SERVERS];
            for (int j = 0; j < NUM_SERVERS; j++) {
                tmp_reqs[j] = reqs[j].add_updates();
            }
            this->DCFUpdate(id, (uint32_t)idx, data[idx], tmp_reqs);
        }

        for (int i = 0; i < NUM_SERVERS; i++) {
            BatchedUpdateDCFResponse resp;
            ClientContext ctx;
            queryStubs[i]->SendDCFBatchedUpdate(&ctx, reqs[i], &resp);
        }
        printf("finished batch %zu/%zu\n", batch_id, batch_cnt);
    }
}

void QueryClient::RegisterDPFTableMeta(string id, uint32_t windowSize, uint32_t numBuckets) {
    int numBucketsLog = getDepth(numBuckets);
    if (DPFTables.count(id) != 0) {
        delete DPFTables[id];
    }
    DPFTables[id] = new DPFTableClient(id, numBucketsLog, windowSize, malicious);
    alpha = DPFTables[id]->alpha;
}

void QueryClient::AddDPFTable(string id, uint32_t windowSize, uint32_t numBuckets, vector<uint32_t> &data) {
    //DCFTables[id] = new Table(id, windowSize, numBuckets);
    RegisterDPFTableMeta(id, windowSize, numBuckets);

    /* Initialize table at servers. */
    for (int i = 0; i < NUM_SERVERS; i++) {
        InitDPFRequest req;
        InitDPFResponse resp;
        ClientContext ctx;
        req.set_id(id);
        req.set_window_size(windowSize);
        req.set_num_buckets(numBuckets);
        req.set_malicious(malicious);
        queryStubs[i]->SendDPFInit(&ctx, req, &resp);
    }

    /* Load data. */
    const size_t chunk_sz = ComputeSafeUpdateChunk(numBuckets);
    for (size_t batch_start = 0; batch_start < windowSize; batch_start += chunk_sz) {
        BatchedUpdateDPFRequest reqs[NUM_SERVERS];
        assert(data.size() >= windowSize);
        const size_t batch_end = std::min<size_t>(windowSize, batch_start + chunk_sz);
        const size_t batch_id = batch_start / chunk_sz;
        const size_t batch_cnt = (windowSize + chunk_sz - 1) / chunk_sz;
        printf("batch = %zu/%zu\n", batch_id, batch_cnt);
        for (size_t idx = batch_start; idx < batch_end; idx++) {
            UpdateDPFRequest *tmp_reqs[NUM_SERVERS];
            for (int j = 0; j < NUM_SERVERS; j++) {
                tmp_reqs[j] = reqs[j].add_updates();
            }
            this->DPFUpdate(id, (uint32_t)idx, data[idx], tmp_reqs);
        }

        for (int i = 0; i < NUM_SERVERS; i++) {
            BatchedUpdateDPFResponse resp;
            ClientContext ctx;
            queryStubs[i]->SendDPFBatchedUpdate(&ctx, reqs[i], &resp);
        }
    }
}

void QueryClient::AddValList(string id, uint32_t windowSize, vector<uint128_t> &data) {
    /* Initialize list at servers. */
    for (int i = 0; i < NUM_SERVERS; i++) {
        InitListRequest req;
        InitListResponse resp;
        ClientContext ctx;
        req.set_id(id);
        req.set_window_size(windowSize);
        queryStubs[i]->SendListInit(&ctx, req, &resp);
    }

    /* Load data. */
    BatchedUpdateListRequest reqs[NUM_SERVERS];
    assert(data.size() >= windowSize);
    for (int batch = 0; batch < windowSize / UPDATE_CHUNK_SZ + 1; batch++) {
        for (int i = 0; i < UPDATE_CHUNK_SZ && batch * UPDATE_CHUNK_SZ + i < windowSize; i++) {
            int idx = batch * UPDATE_CHUNK_SZ + i;
            UpdateListRequest *tmp_reqs[NUM_SERVERS];
            for (int j = 0; j < NUM_SERVERS; j++) {
                tmp_reqs[j] = reqs[j].add_updates();
            }
            this->ValListUpdate(id, idx, data[idx], tmp_reqs);
        }

        for (int i = 0; i < NUM_SERVERS; i++) {
            BatchedUpdateListResponse resp;
            ClientContext ctx;
            queryStubs[i]->SendListBatchedUpdate(&ctx, reqs[i], &resp);
        }
    }
}

void QueryClient::AddAggTree(string id, AggFunc aggFunc, int depth, map<uint64_t, uint128_t> &data) {
    AggTrees[id] = new AggTreeIndexClient(aggFunc, id, depth, malicious);
    alpha = AggTrees[id]->alpha;

    /* Initialize aggregate tree at servers. */
    for (int i = 0; i < NUM_SERVERS; i++) {
        InitATRequest req;
        InitATResponse resp;
        ClientContext ctx;
        req.set_id(id);
        req.set_agg_func(aggFunc);
        req.set_depth(depth);
        queryStubs[i]->SendATInit(&ctx, req, &resp);
    }

    map<uint64_t, uint128_t>::iterator it;
    for (it = data.begin(); it != data.end(); it++) {
        this->AggTreeAppend(id, it->first, it->second);
    }
}

void QueryClient::DCFUpdate(string id, uint32_t idx, uint32_t val, UpdateDCFRequest *reqs[]) {
    uint128_t *raw_data = createIndicatorVector(val, DCFTables[id]->numBuckets);
    uint128_t *data[3];
    data[0] = (uint128_t *)malloc(DCFTables[id]->numBuckets * sizeof(uint128_t));
    data[1] = (uint128_t *)malloc(DCFTables[id]->numBuckets * sizeof(uint128_t));
    data[2] = (uint128_t *)malloc(DCFTables[id]->numBuckets * sizeof(uint128_t));
    splitIntoArithmeticShares(prng, raw_data, DCFTables[id]->numBuckets, data);
 
    for (int i = 0; i < NUM_SERVERS; i++) {
        UpdateDCFResponse resp;
        ClientContext ctx;

        reqs[i]->set_id(id);
        reqs[i]->set_val(idx);
        reqs[i]->set_data0((char *)data[i], sizeof(uint128_t) * DCFTables[id]->numBuckets);
        reqs[i]->set_data1((char *)data[(i + 1) % NUM_SERVERS], sizeof(uint128_t) * DCFTables[id]->numBuckets);
    }
    free(raw_data);
    free(data[0]);
    free(data[1]);
    free(data[2]);
}

void QueryClient::RunDCFUpdate(string id, uint32_t idx, uint32_t val) {
    uint128_t *raw_data = createIndicatorVector(val, DCFTables[id]->numBuckets);
    uint128_t *data[3];
    data[0] = (uint128_t *)malloc(DCFTables[id]->numBuckets * sizeof(uint128_t));
    data[1] = (uint128_t *)malloc(DCFTables[id]->numBuckets * sizeof(uint128_t));
    data[2] = (uint128_t *)malloc(DCFTables[id]->numBuckets * sizeof(uint128_t));
    splitIntoArithmeticShares(prng, raw_data, DCFTables[id]->numBuckets, data);
 
    for (int i = 0; i < NUM_SERVERS; i++) {
        UpdateDCFRequest req;
        UpdateDCFResponse resp;
        ClientContext ctx;

        req.set_id(id);
        req.set_val(idx);
        req.set_data0((char *)data[i], sizeof(uint128_t) * DCFTables[id]->numBuckets);
        req.set_data1((char *)data[(i + 1) % NUM_SERVERS], sizeof(uint128_t) * DCFTables[id]->numBuckets);
        queryStubs[i]->SendDCFUpdate(&ctx, req, &resp);
    }
    free(raw_data);
    free(data[0]);
    free(data[1]);
    free(data[2]);
}



void QueryClient::DPFUpdate(string id, uint32_t idx, uint32_t val, UpdateDPFRequest *reqs[]) {
    uint128_t *raw_data = createIndicatorVector(val, DPFTables[id]->numBuckets);
    uint128_t *data[3];
    data[0] = (uint128_t *)malloc(DPFTables[id]->numBuckets * sizeof(uint128_t));
    data[1] = (uint128_t *)malloc(DPFTables[id]->numBuckets * sizeof(uint128_t));
    data[2] = (uint128_t *)malloc(DPFTables[id]->numBuckets * sizeof(uint128_t));
    splitIntoArithmeticShares(prng, raw_data, DPFTables[id]->numBuckets, data);
 
    for (int i = 0; i < NUM_SERVERS; i++) {
        UpdateDPFRequest req;
        UpdateDPFResponse resp;
        ClientContext ctx;

        reqs[i]->set_id(id);
        reqs[i]->set_val(idx);
        reqs[i]->set_data0((char *)data[i], sizeof(uint128_t) * DPFTables[id]->numBuckets);
        reqs[i]->set_data1((char *)data[(i + 1) % NUM_SERVERS], sizeof(uint128_t) * DPFTables[id]->numBuckets);
    }
    free(raw_data);
    free(data[0]);
    free(data[1]);
    free(data[2]);
}

void QueryClient::RunDPFUpdate(string id, uint32_t idx, uint32_t val) {
    uint128_t *raw_data = createIndicatorVector(val, DPFTables[id]->numBuckets);
    uint128_t *data[3];
    data[0] = (uint128_t *)malloc(DPFTables[id]->numBuckets * sizeof(uint128_t));
    data[1] = (uint128_t *)malloc(DPFTables[id]->numBuckets * sizeof(uint128_t));
    data[2] = (uint128_t *)malloc(DPFTables[id]->numBuckets * sizeof(uint128_t));
    splitIntoArithmeticShares(prng, raw_data, DPFTables[id]->numBuckets, data);
 
    for (int i = 0; i < NUM_SERVERS; i++) {
        UpdateDPFRequest req;
        UpdateDPFResponse resp;
        ClientContext ctx;

        req.set_id(id);
        req.set_val(idx);
        req.set_data0((char *)data[i], sizeof(uint128_t) * DPFTables[id]->numBuckets);
        req.set_data1((char *)data[(i + 1) % NUM_SERVERS], sizeof(uint128_t) * DPFTables[id]->numBuckets);
        queryStubs[i]->SendDPFUpdate(&ctx, req, &resp);
    }
    free(raw_data);
    free(data[0]);
    free(data[1]);
    free(data[2]);
}

void QueryClient::ValListUpdate(string id, uint32_t idx, uint128_t val, UpdateListRequest *reqs[]) {
    uint128_t shares[3];
    splitIntoSingleArithmeticShares(prng, val, shares);
    //cout << "val " << idx << " " << shares[0] << " " << shares[1] << " " << shares[2] << " " << shares[0] + shares[1] + shares[2] << endl;
    
    for (int i = 0; i < NUM_SERVERS; i++) {
        reqs[i]->set_id(id);
        reqs[i]->set_val(idx);
        reqs[i]->set_share0((char *)&shares[i], sizeof(uint128_t));
        reqs[i]->set_share1((char *)&shares[(i + 1) % NUM_SERVERS], sizeof(uint128_t));
    }
}

void QueryClient::AggTreeAppend(string id, uint64_t idx, uint128_t val) {
    uint128_t *parents;
    uint128_t *parentShares0[3];
    uint128_t *parentShares1[3];
    uint128_t *newAggVals;
    uint128_t *newAggValShares[3];
    AppendAT1Request req1[3];
    AppendAT2Request req2[3];
    AppendAT1Response resp1[3];
    AppendAT2Response resp2[3];
    int len;

    for (int i = 0; i < NUM_SERVERS; i++) {
        ClientContext ctx;
        req1[i].set_id(id);
        req1[i].set_idx(idx);
        queryStubs[i]->SendATAppend1(&ctx, req1[i], &resp1[i]);
        parentShares0[i] = (uint128_t *)malloc(resp1[i].parent_shares0_size() * sizeof(uint128_t));
        parentShares1[i] = (uint128_t *)malloc(resp1[i].parent_shares0_size() * sizeof(uint128_t));
        for (int j = 0; j < resp1[i].parent_shares0_size(); j++) {
            memcpy((uint8_t *)&parentShares0[i][j], resp1[i].parent_shares0(j).c_str(), sizeof(uint128_t));
            memcpy((uint8_t *)&parentShares1[i][j], resp1[i].parent_shares1(j).c_str(), sizeof(uint128_t));
        }
    }
    // malicious security check
    for (int i = 0; i < NUM_SERVERS; i++) {
        for (int j = 0; j < resp1[0].parent_shares0_size(); j++) {
            assert (parentShares0[(i + 1) % NUM_SERVERS][j] == parentShares1[i % NUM_SERVERS][j]);
        }
    }

    len = resp1[0].parent_shares0_size();
    parents = (uint128_t *)malloc(len * sizeof(uint128_t));
    newAggVals = (uint128_t *)malloc((len + 1) * sizeof(uint128_t));
    for (int i = 0; i < NUM_SERVERS; i++) {
        newAggValShares[i] = (uint128_t *)malloc((len + 1) * sizeof(uint128_t));
    }

    combineArithmeticShares(parents, len, parentShares0, NUM_SERVERS, true);
    AggTrees[id]->propagateNewVal(val, parents, newAggVals, len + 1);
    splitIntoArithmeticShares(prng, newAggVals, len + 1, newAggValShares);

    for (int i = 0; i < NUM_SERVERS; i++) {
        ClientContext ctx;
        req2[i].set_id(id);
        req2[i].set_idx(idx);
        for (int j = 0; j < resp1[0].parent_shares0_size() + 1; j++) {
            req2[i].add_new_shares0((uint8_t *)&newAggValShares[i][j], sizeof(uint128_t));
            req2[i].add_new_shares1((uint8_t *)&newAggValShares[(i + 1) % NUM_SERVERS][j], sizeof(uint128_t));
        }
        queryStubs[i]->SendATAppend2(&ctx, req2[i], &resp2[i]);
    }
    free(parents);
    free(newAggVals);
    for (int i = 0; i < NUM_SERVERS; i++) {
        free(parentShares0[i]);
        free(parentShares1[i]);
        free(newAggValShares[i]);
    }
}

void QueryClient::GenerateDPFFilter(string id, uint32_t x, BaseFilter *filters[]) {
    uint8_t *k[NUM_SERVERS][2];
    size_t key_len;
    uint64_t gout_bitsize = 125;
    uint128_t one = 1;
    uint128_t group_mod = one << gout_bitsize;
    DPFTables[id]->gen_dpf_table_keys((uint128_t)x, DPFTables[id]->depth, gout_bitsize, true, group_mod);
    DPFTables[id]->serialize_keys(&k[0][0], &k[1][1], &key_len);
    
    DPFTables[id]->gen_dpf_table_keys((uint128_t)x, DPFTables[id]->depth, gout_bitsize, true, group_mod);
    DPFTables[id]->serialize_keys(&k[1][0], &k[2][1], &key_len);
    
    DPFTables[id]->gen_dpf_table_keys((uint128_t)x, DPFTables[id]->depth, gout_bitsize, true, group_mod);
    DPFTables[id]->serialize_keys(&k[2][0], &k[0][1], &key_len);
    
    for (int i = 0; i < NUM_SERVERS; i++) {
        filters[i]->set_id(id);
        filters[i]->set_key0(k[i][0], key_len);
        filters[i]->set_key1(k[i][1], key_len);
        filters[i]->set_is_point(true);
    }
}

void QueryClient::GenerateDCFFilter(string id, uint32_t left_x, uint32_t right_x, BaseFilter *filters[]) {
    uint8_t *k[NUM_SERVERS][2];
    size_t key_len;
    uint64_t gout_bitsize = 125;
    uint128_t one = 1;
    uint128_t group_mod = one << gout_bitsize; 
    DCFTables[id]->gen_dcf_table_keys((uint128_t)left_x, (uint128_t)right_x, DCFTables[id]->depth, gout_bitsize, true, group_mod);
    DCFTables[id]->serialize_keys(&k[0][0], &k[1][1], &key_len);
    
    DCFTables[id]->gen_dcf_table_keys((uint128_t)left_x, (uint128_t)right_x, DCFTables[id]->depth, gout_bitsize, true, group_mod);
    DCFTables[id]->serialize_keys(&k[1][0], &k[2][1], &key_len);
    
    DCFTables[id]->gen_dcf_table_keys((uint128_t)left_x, (uint128_t)right_x, DCFTables[id]->depth, gout_bitsize, true, group_mod);
    DCFTables[id]->serialize_keys(&k[2][0], &k[0][1], &key_len);
    
    //cout << "Created and serialized all DCF keys" << endl;
    for (int i = 0; i < NUM_SERVERS; i++) {
        filters[i]->set_id(id);
        filters[i]->set_key0(k[i][0], key_len);
        filters[i]->set_key1(k[i][1], key_len);
        filters[i]->set_is_point(false);
    }
}

void QueryClient::GenerateBaseFilter(Condition *cond, BaseFilter *filters[]) {
    if (cond->cond_type == POINT_COND) {
        GenerateDPFFilter(cond->table_id, cond->x, filters);
    } else if (cond->cond_type == RANGE_COND) {
        GenerateDCFFilter(cond->table_id, cond->left_x, cond->right_x, filters);
    }
}

void QueryClient::GenerateCombinedFilter(Expression *expr, CombinedFilter *filters[]) {
    for (int i = 0; i < expr->conds.size(); i++) {
        cout << "generating filter for cond " << i << endl;
        BaseFilter *tmp[3];
        for (int j = 0; j < NUM_SERVERS; j++) {
            tmp[j] = filters[j]->add_base_filters();
        }
        GenerateBaseFilter(&expr->conds[i], tmp);
    }
    cout << "generated all base filters" << endl;
    filters[0]->set_op_is_and(expr->op_type == AND_OP);
    filters[1]->set_op_is_and(expr->op_type == AND_OP);
    filters[2]->set_op_is_and(expr->op_type == AND_OP);
}


uint128_t QueryClient::AggQuery(string agg_id, QueryObj &query) {
    CombinedFilter *filters[NUM_SERVERS];
    QueryAggRequest reqs[NUM_SERVERS];
    QueryAggResponse resps[NUM_SERVERS];
    ClientContext ctx[NUM_SERVERS];
    CompletionQueue cq[NUM_SERVERS];
    Status status[NUM_SERVERS];
    unique_ptr<ClientAsyncResponseReader<QueryAggResponse>> rpcs[NUM_SERVERS];
    uint128_t ret = 0;
    uint128_t mac = 0;
    uint128_t lin_comb = 0;
    uint128_t lin_comb_mac = 0;

    for (int i = 0; i < NUM_SERVERS; i++) {
        filters[i] = reqs[i].mutable_combined_filter();
    }
    cout << "going to generate combined filter" << endl;
    GenerateCombinedFilter(query.expr, filters);
    cout << "generated combined filter" << endl;

    for (int i = 0; i < NUM_SERVERS; i++) {
        reqs[i].set_agg_id(agg_id);
        cout << "Query size: " << reqs[i].ByteSizeLong() << "B" << endl;
        rpcs[i] = queryStubs[i]->AsyncSendAggQuery(&ctx[i], reqs[i], &cq[i]);
        rpcs[i]->Finish(&resps[i], &status[i], (void *)1);
    }
 
    uint128_t one = 1;
    uint128_t group_mod = (one << 125);
 
    for (int i = 0; i < NUM_SERVERS; i++) {
        void *got_tag;
        bool ok = false;
        cq[i].Next(&got_tag, &ok);
        if (ok && got_tag == (void *)1) {
            if (status[i].ok()) {
                uint128_t res;
                uint128_t mac_res;
                uint128_t lc_share;
                uint128_t lc_mac_share;
                memcpy((uint8_t *)&res, (const uint8_t *)resps[i].res().c_str(), sizeof(uint128_t));
                memcpy((uint8_t *)&mac_res, (const uint8_t *)resps[i].mac().c_str(), sizeof(uint128_t));
                memcpy((uint8_t *)&lc_share, (const uint8_t *)resps[i].lin_comb().c_str(), sizeof(uint128_t));
                memcpy((uint8_t *)&lc_mac_share, (const uint8_t *)resps[i].lin_comb_mac().c_str(), sizeof(uint128_t));
                ret += res;
                mac += mac_res;
                lin_comb += lc_share;
                lin_comb_mac += lc_mac_share;
            } else {
                cout << "ERROR receiving message " << status[i].error_message().c_str() << endl;
            }
        }
    }
    ret %= group_mod;
    mac %= group_mod;
    lin_comb %= group_mod;
    lin_comb_mac %= group_mod;
    if (malicious) {
        assert ((lin_comb * GetMACAlpha()) % group_mod == lin_comb_mac);
        assert ((ret * GetMACAlpha()) % group_mod == mac);
        cout << "MAC check passed" << endl;
    }

    return ret;
    
}


// 优化1：采用 const reference 避免 string 和 vector 的深度拷贝
uint128_t QueryClient::VBAggQuery(const string& agg_id, const string& table_id, bool is_point, int num_buckets, const vector<uint32_t> &query) {
    using clock = std::chrono::high_resolution_clock;

    QueryVBAggResponse resps[NUM_SERVERS];
    QueryVBAggRequest reqs[NUM_SERVERS];
    ClientContext ctx[NUM_SERVERS];
    Status status[NUM_SERVERS];
    
    // 优化2：只使用一个 CompletionQueue，利用 tag 区分事件
    CompletionQueue cq;
    unique_ptr<ClientAsyncResponseReader<QueryVBAggResponse>> rpcs[NUM_SERVERS];
    CombinedVBFilter *filters[NUM_SERVERS];
    int query_size = query.size();
    if (!is_point) {
        if (query_size % 2 != 0) {
            throw std::invalid_argument("VB-PMS range query expects boundary pairs: [l0, r0, l1, r1, ...].");
        }
        query_size /= 2;
    }

    // 优化3：使用 std::vector 完全取代 malloc/free，彻底消除内存泄漏风险
    vector<vector<uint128_t>> raw_query_vector(query_size, vector<uint128_t>((size_t)num_buckets, 0));
    // 适配旧接口所需的裸指针数组
    vector<uint128_t*> raw_query_ptr(query_size); 

    for(int i = 0; i < NUM_SERVERS; i++) {
        filters[i] = reqs[i].mutable_combined_vbfilter();
    }

    cout << "going to generate combined filter" << endl;
    for (int i = 0; i < query_size; i++) {
        if (is_point) {
            const uint32_t x = query[(size_t)i];
            if (x >= (uint32_t)num_buckets) {
                throw std::out_of_range("VB point query value out of range.");
            }
            raw_query_vector[i][x] = 1;
        } else {
            // Single-sided range only:
            // [0, r]    => x <= r
            // [l, N-1]  => x >= l
            const uint32_t left = query[(size_t)i * 2];
            const uint32_t right = query[(size_t)i * 2 + 1];
            if (left >= (uint32_t)num_buckets || right >= (uint32_t)num_buckets) {
                throw std::out_of_range("VB range boundary out of range.");
            }
            const uint32_t last = (uint32_t)num_buckets - 1;
            if (left == 0) {
                for (uint32_t b = 0; b <= right; b++) {
                    raw_query_vector[i][b] = 1;
                }
            } else if (right == last) {
                for (uint32_t b = left; b < (uint32_t)num_buckets; b++) {
                    raw_query_vector[i][b] = 1;
                }
            } else {
                throw std::invalid_argument("VB-PMS range currently supports single-sided predicates only: [0,r] or [l,N-1].");
            }
        }
        raw_query_ptr[i] = raw_query_vector[i].data();
    }

    GenerateCombinedVBFilter(table_id, raw_query_ptr.data(), query_size, num_buckets, is_point, true, filters);
    cout << "generated combined filter" << endl;

    // 此处开始计时才是包含网络往返的真实时间
    // INIT_TIMER
    // START_TIMER 

    // 发送阶段（仅谓词发送/发起 RPC）
    const auto t_send_begin = clock::now();
    for(int i = 0; i < NUM_SERVERS; i++) {

        cout << "query_size: " << reqs[i].ByteSizeLong() << "B" << endl;

        reqs[i].set_agg_id(agg_id);
        
        // 使用单 CQ，将 tag 设置为服务器索引 (void*)(uintptr_t)i
        rpcs[i] = queryStubs[i]->AsyncSendVBAggQuery(&ctx[i], reqs[i], &cq);
        rpcs[i]->Finish(&resps[i], &status[i], (void*)(uintptr_t)i);
    }
    const auto t_send_end = clock::now();
    const auto predicate_send_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(t_send_end - t_send_begin).count();
    cout << "[QUERY-PROFILE] predicate_send_ms=" << predicate_send_ms << endl;

    uint128_t ret = 0;
    int completed_rpcs = 0;

    INIT_TIMER
    START_TIMER 
    // 接收阶段：真正的异步事件驱动，谁先回来先处理谁
    while (completed_rpcs < NUM_SERVERS) {
        void *got_tag;
        bool ok = false;
        
        // 阻塞等待任何一个服务器响应
        cq.Next(&got_tag, &ok); 
        
        if (ok) {
            int server_idx = (int)(uintptr_t)got_tag;
            
            if (status[server_idx].ok()) {
                // 优化4：严格的越界读取安全检查
                if (resps[server_idx].res().size() == sizeof(uint128_t)) {
                    uint128_t res = 0;
                    memcpy(&res, resps[server_idx].res().data(), sizeof(uint128_t));
                    ret += res;
                } else {
                    cerr << "[Error] Server " << server_idx << " returned invalid payload size." << endl;
                }
            } else {
                cerr << "[Error] Server " << server_idx << " RPC failed: " << status[server_idx].error_message() << endl;
            }
        }
        completed_rpcs++;
    }

    STOP_TIMER("VBAggQuery full RTT finish")

    
    uint128_t one = 1;
    uint128_t group_mod = (one << 125);
    ret %= group_mod;

    return ret;
}

uint128_t QueryClient::BOAggQuery(const string& agg_id, const string& table_id, bool is_and, const vector<uint32_t> &query) {
    return BOAggQuery(agg_id, table_id, true, is_and, query);
}

uint128_t QueryClient::BOAggQuery(const string& agg_id, const string& table_id, bool is_point, bool is_and, const vector<uint32_t> &query) {
    using clock = std::chrono::high_resolution_clock;

    QueryBOAggResponse resps[NUM_SERVERS];
    QueryBOAggRequest reqs[NUM_SERVERS];
    ClientContext ctx[NUM_SERVERS];
    Status status[NUM_SERVERS];
    CompletionQueue cq;
    unique_ptr<ClientAsyncResponseReader<QueryBOAggResponse>> rpcs[NUM_SERVERS];
    CombinedBOFilter *filters[NUM_SERVERS];

    for (int i = 0; i < NUM_SERVERS; i++) {
        filters[i] = reqs[i].mutable_combined_bofilter();
    }
    GenerateCombinedBOFilter(table_id, query, is_point, is_and, filters);

    const auto t_send_begin = clock::now();
    for (int i = 0; i < NUM_SERVERS; i++) {
        reqs[i].set_agg_id(agg_id);
        rpcs[i] = queryStubs[i]->AsyncSendBOAggQuery(&ctx[i], reqs[i], &cq);
        rpcs[i]->Finish(&resps[i], &status[i], (void*)(uintptr_t)i);
    }
    const auto t_send_end = clock::now();
    const auto predicate_send_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(t_send_end - t_send_begin).count();
    cout << "[QUERY-PROFILE] predicate_send_ms=" << predicate_send_ms << endl;

    uint128_t ret = 0;
    int completed = 0;
    while (completed < NUM_SERVERS) {
        void *got_tag;
        bool ok = false;
        cq.Next(&got_tag, &ok);
        if (ok) {
            int server_idx = (int)(uintptr_t)got_tag;
            if (status[server_idx].ok() && resps[server_idx].res().size() == sizeof(uint128_t)) {
                uint128_t tmp = 0;
                memcpy(&tmp, resps[server_idx].res().data(), sizeof(uint128_t));
                ret += tmp;
            }
        }
        completed++;
    }

    uint128_t one = 1;
    uint128_t group_mod = (one << 125);
    return ret % group_mod;
}

uint128_t QueryClient::VBFSSAggQuery(const string& agg_id, const string& table_id, bool is_and, const vector<uint32_t> &query) {
    return VBFSSAggQuery(agg_id, table_id, true, is_and, query);
}

uint128_t QueryClient::VBFSSAggQuery(const string& agg_id, const string& table_id, bool is_point, bool is_and, const vector<uint32_t> &query) {
    using clock = std::chrono::high_resolution_clock;

    QueryVBFSSAggResponse resps[NUM_SERVERS];
    QueryVBFSSAggRequest reqs[NUM_SERVERS];
    ClientContext ctx[NUM_SERVERS];
    Status status[NUM_SERVERS];
    CompletionQueue cq;
    unique_ptr<ClientAsyncResponseReader<QueryVBFSSAggResponse>> rpcs[NUM_SERVERS];
    CombinedVBFSSFilter *filters[NUM_SERVERS];

    for (int i = 0; i < NUM_SERVERS; i++) {
        filters[i] = reqs[i].mutable_combined_vbfssfilter();
    }
    GenerateCombinedVBFSSFilter(table_id, query, is_point, is_and, filters);

    const auto t_send_begin = clock::now();
    for (int i = 0; i < NUM_SERVERS; i++) {
        reqs[i].set_agg_id(agg_id);
        rpcs[i] = queryStubs[i]->AsyncSendVBFSSAggQuery(&ctx[i], reqs[i], &cq);
        rpcs[i]->Finish(&resps[i], &status[i], (void *)(uintptr_t)i);
    }
    const auto t_send_end = clock::now();
    const auto predicate_send_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(t_send_end - t_send_begin).count();
    cout << "[QUERY-PROFILE] predicate_send_ms=" << predicate_send_ms << endl;

    uint128_t ret = 0;
    int completed = 0;
    while (completed < NUM_SERVERS) {
        void *got_tag;
        bool ok = false;
        cq.Next(&got_tag, &ok);
        if (ok) {
            int server_idx = (int)(uintptr_t)got_tag;
            if (status[server_idx].ok() && resps[server_idx].res().size() == sizeof(uint128_t)) {
                uint128_t tmp = 0;
                memcpy(&tmp, resps[server_idx].res().data(), sizeof(uint128_t));
                ret += tmp;
            }
        }
        completed++;
    }

    uint128_t one = 1;
    uint128_t group_mod = (one << 125);
    return ret % group_mod;
}

uint128_t QueryClient::BOFSSAggQuery(const string& agg_id, const string& table_id, bool is_and, const vector<uint32_t> &query) {
    return BOFSSAggQuery(agg_id, table_id, true, is_and, query);
}

uint128_t QueryClient::BOFSSAggQuery(const string& agg_id, const string& table_id, bool is_point, bool is_and, const vector<uint32_t> &query) {
    using clock = std::chrono::high_resolution_clock;
    const bool profile_bofss = (std::getenv("WALDO_PROFILE_BOFSS") != nullptr);
    const auto t_total_begin = clock::now();

    QueryBOFSSAggResponse resps[NUM_SERVERS];
    QueryBOFSSAggRequest reqs[NUM_SERVERS];
    ClientContext ctx[NUM_SERVERS];
    Status status[NUM_SERVERS];
    CompletionQueue cq;
    unique_ptr<ClientAsyncResponseReader<QueryBOFSSAggResponse>> rpcs[NUM_SERVERS];
    CombinedBOFSSFilter *filters[NUM_SERVERS];

    for (int i = 0; i < NUM_SERVERS; i++) {
        filters[i] = reqs[i].mutable_combined_bofssfilter();
    }
    const auto t_keygen_begin = clock::now();
    GenerateCombinedBOFSSFilter(table_id, query, is_point, is_and, filters);
    const auto t_keygen_end = clock::now();

    uint64_t req_total_bytes = 0;
    const auto t_send_begin = clock::now();
    for (int i = 0; i < NUM_SERVERS; i++) {
        reqs[i].set_agg_id(agg_id);
        req_total_bytes += reqs[i].ByteSizeLong();
        rpcs[i] = queryStubs[i]->AsyncSendBOFSSAggQuery(&ctx[i], reqs[i], &cq);
        rpcs[i]->Finish(&resps[i], &status[i], (void *)(uintptr_t)i);
    }
    const auto t_send_end = clock::now();
    const auto predicate_send_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(t_send_end - t_send_begin).count();
    cout << "[QUERY-PROFILE] predicate_send_ms=" << predicate_send_ms << endl;

    const auto t_rpc_wait_begin = clock::now();
    uint128_t ret = 0;
    int completed = 0;
    while (completed < NUM_SERVERS) {
        void *got_tag;
        bool ok = false;
        cq.Next(&got_tag, &ok);
        if (ok) {
            int server_idx = (int)(uintptr_t)got_tag;
            if (status[server_idx].ok() && resps[server_idx].res().size() == sizeof(uint128_t)) {
                uint128_t tmp = 0;
                memcpy(&tmp, resps[server_idx].res().data(), sizeof(uint128_t));
                ret += tmp;
            }
        }
        completed++;
    }
    const auto t_rpc_wait_end = clock::now();
    const auto t_total_end = clock::now();

    if (profile_bofss) {
        const auto keygen_us = std::chrono::duration_cast<std::chrono::microseconds>(t_keygen_end - t_keygen_begin).count();
        const auto rpc_wait_us = std::chrono::duration_cast<std::chrono::microseconds>(t_rpc_wait_end - t_rpc_wait_begin).count();
        const auto total_us = std::chrono::duration_cast<std::chrono::microseconds>(t_total_end - t_total_begin).count();
        std::cout << "[BOFSS-PROFILE][client] "
                  << "is_point=" << (is_point ? 1 : 0)
                  << " num_pred=" << (is_point ? query.size() : query.size() / 2)
                  << " keygen_us=" << keygen_us
                  << " rpc_wait_us=" << rpc_wait_us
                  << " total_us=" << total_us
                  << " req_total_B=" << req_total_bytes
                  << std::endl;
    }

    uint128_t one = 1;
    uint128_t group_mod = (one << 125);
    return ret % group_mod;
}

void QueryClient::GenerateCombinedVBFSSFilter(const string& table_id, const vector<uint32_t> &query, bool is_and, CombinedVBFSSFilter *filters[]) {
    GenerateCombinedVBFSSFilter(table_id, query, true, is_and, filters);
}

void QueryClient::GenerateCombinedVBFSSFilter(const string& table_id, const vector<uint32_t> &query, bool is_point, bool is_and, CombinedVBFSSFilter *filters[]) {
    if (OneHotNumBuckets.count(table_id) == 0) {
        throw std::invalid_argument("OneHot table metadata not found for VBFSS: " + table_id);
    }
    if (query.empty()) {
        throw std::invalid_argument("VBFSS query must contain at least one predicate.");
    }

    const uint32_t numBuckets = OneHotNumBuckets[table_id];
    if (numBuckets == 0) {
        throw std::invalid_argument("numBuckets must be > 0 for VBFSS.");
    }
    auto it_block = VBFSSBlockNum.find(table_id);
    if (it_block == VBFSSBlockNum.end() || it_block->second == 0) {
        throw std::invalid_argument("VBFSS block_num is not set for table: " + table_id);
    }
    const uint32_t blockNum = it_block->second;
    if (blockNum == 0 || numBuckets % blockNum != 0) {
        throw std::invalid_argument("Invalid VBFSS block layout.");
    }
    const uint32_t blockSize = numBuckets / blockNum;

    auto emit_vdpf_leaf = [&](uint32_t predicateIndex, uint32_t blockIndex, const std::vector<uint128_t> &payload) {
        waldo::VDPFKeyPair kp1 = waldo::VDPF::GenPointVector(blockNum, blockIndex, payload);
        waldo::VDPFKeyPair kp2 = waldo::VDPF::GenPointVector(blockNum, blockIndex, payload);
        waldo::VDPFKeyPair kp3 = waldo::VDPF::GenPointVector(blockNum, blockIndex, payload);

        std::string k[NUM_SERVERS][2];
        k[0][0] = waldo::VDPF::SerializeKeyPack(kp1.key0);
        k[1][1] = waldo::VDPF::SerializeKeyPack(kp1.key1);
        k[1][0] = waldo::VDPF::SerializeKeyPack(kp2.key0);
        k[2][1] = waldo::VDPF::SerializeKeyPack(kp2.key1);
        k[2][0] = waldo::VDPF::SerializeKeyPack(kp3.key0);
        k[0][1] = waldo::VDPF::SerializeKeyPack(kp3.key1);

        BaseVBFSSFilter *b0 = filters[0]->add_base_vbfssfilters();
        BaseVBFSSFilter *b1 = filters[1]->add_base_vbfssfilters();
        BaseVBFSSFilter *b2 = filters[2]->add_base_vbfssfilters();
        BaseVBFSSFilter *bases[NUM_SERVERS] = {b0, b1, b2};
        for (int s = 0; s < NUM_SERVERS; s++) {
            bases[s]->set_id(table_id);
            bases[s]->set_domain_size(blockNum);
            bases[s]->set_vec_dim(blockSize);
            bases[s]->set_key0(k[s][0]);
            bases[s]->set_key1(k[s][1]);
            bases[s]->set_predicate_index(predicateIndex);
            bases[s]->set_leaf_type(dbquery::VBFSS_LEAF_VDPF);
        }
    };

    auto emit_vdcf_leaf = [&](uint32_t predicateIndex, waldo::VDCFCompareOp op, uint32_t threshold, const std::vector<uint128_t> &payload) {
        waldo::VDCFKeyPair kp1 = waldo::VDCF::GenCompareVector(blockNum, op, threshold, payload);
        waldo::VDCFKeyPair kp2 = waldo::VDCF::GenCompareVector(blockNum, op, threshold, payload);
        waldo::VDCFKeyPair kp3 = waldo::VDCF::GenCompareVector(blockNum, op, threshold, payload);

        std::string k[NUM_SERVERS][2];
        k[0][0] = waldo::VDCF::SerializeKeyPack(kp1.key0);
        k[1][1] = waldo::VDCF::SerializeKeyPack(kp1.key1);
        k[1][0] = waldo::VDCF::SerializeKeyPack(kp2.key0);
        k[2][1] = waldo::VDCF::SerializeKeyPack(kp2.key1);
        k[2][0] = waldo::VDCF::SerializeKeyPack(kp3.key0);
        k[0][1] = waldo::VDCF::SerializeKeyPack(kp3.key1);

        BaseVBFSSFilter *b0 = filters[0]->add_base_vbfssfilters();
        BaseVBFSSFilter *b1 = filters[1]->add_base_vbfssfilters();
        BaseVBFSSFilter *b2 = filters[2]->add_base_vbfssfilters();
        BaseVBFSSFilter *bases[NUM_SERVERS] = {b0, b1, b2};
        for (int s = 0; s < NUM_SERVERS; s++) {
            bases[s]->set_id(table_id);
            bases[s]->set_domain_size(blockNum);
            bases[s]->set_vec_dim(blockSize);
            bases[s]->set_key0(k[s][0]);
            bases[s]->set_key1(k[s][1]);
            bases[s]->set_predicate_index(predicateIndex);
            bases[s]->set_leaf_type(dbquery::VBFSS_LEAF_VDCF);
        }
    };

    for (int s = 0; s < NUM_SERVERS; s++) {
        filters[s]->set_is_and(is_and);
    }

    if (is_point) {
        // Point mode: one leaf per predicate.
        for (uint32_t pred = 0; pred < (uint32_t)query.size(); pred++) {
            uint32_t x = query[pred];
            if (x >= numBuckets) {
                throw std::out_of_range("VBFSS query value out of range.");
            }
            const uint32_t blockIndex = x / blockSize;
            const uint32_t offsetIndex = x % blockSize;
            vector<uint128_t> payload(blockSize, 0);
            payload[offsetIndex] = 1;
            emit_vdpf_leaf(pred, blockIndex, payload);
        }
        return;
    }

    // Range mode: query is boundary pairs [l0, r0, l1, r1, ...].
    // Single-sided only and implemented by two leaves per predicate:
    // 1) vDCF leaf for full blocks
    // 2) vDPF leaf for boundary block mask
    if (query.size() % 2 != 0) {
        throw std::invalid_argument("VBFSS range query expects boundary pairs.");
    }

    const uint32_t last = numBuckets - 1;
    std::vector<uint128_t> full_block_payload(blockSize, 1);

    const uint32_t num_ranges = (uint32_t)(query.size() / 2);
    for (uint32_t pred = 0; pred < num_ranges; pred++) {
        const uint32_t left = query[(size_t)pred * 2];
        const uint32_t right = query[(size_t)pred * 2 + 1];
        if (left >= numBuckets || right >= numBuckets) {
            throw std::out_of_range("VBFSS range boundary out of range.");
        }

        if (left == 0) {
            // x <= right
            const uint32_t boundary_block = right / blockSize;
            const uint32_t boundary_off = right % blockSize;

            // full blocks: block_index < boundary_block
            emit_vdcf_leaf(pred, waldo::VDCFCompareOp::LT, boundary_block, full_block_payload);

            // boundary block: offset <= boundary_off
            std::vector<uint128_t> boundary_payload(blockSize, 0);
            for (uint32_t j = 0; j <= boundary_off; j++) {
                boundary_payload[j] = 1;
            }
            emit_vdpf_leaf(pred, boundary_block, boundary_payload);
        } else if (right == last) {
            // x >= left
            const uint32_t boundary_block = left / blockSize;
            const uint32_t boundary_off = left % blockSize;

            // full blocks: block_index > boundary_block
            emit_vdcf_leaf(pred, waldo::VDCFCompareOp::GT, boundary_block, full_block_payload);

            // boundary block: offset >= boundary_off
            std::vector<uint128_t> boundary_payload(blockSize, 0);
            for (uint32_t j = boundary_off; j < blockSize; j++) {
                boundary_payload[j] = 1;
            }
            emit_vdpf_leaf(pred, boundary_block, boundary_payload);
        } else {
            throw std::invalid_argument("VBFSS range currently supports single-sided predicates only: [0,r] or [l,N-1].");
        }
    }
}

void QueryClient::SetVBFSSBlockNum(const string& table_id, uint32_t blockNum) {
    if (blockNum == 0) {
        throw std::invalid_argument("VBFSS blockNum must be > 0.");
    }
    VBFSSBlockNum[table_id] = blockNum;
}

void QueryClient::GenerateCombinedVBFilter(
    const std::string& table_id, // 优化1：使用 const 引用，避免 std::string 发生无谓的深拷贝
    uint128_t **raw_query_vector, 
    int num_query, 
    int num_buckets, 
    bool is_point, 
    bool is_and, 
    CombinedVBFilter *filters[]) {

    // 优化2：编译期防御。明确声明此函数高度依赖 3 服务器架构
    // 一旦有人在头文件中将 NUM_SERVERS 改为其他值，编译阶段就会直接报错，防止出现运行时隐式崩溃。
    static_assert(NUM_SERVERS == 3, "This architecture strictly requires exactly 3 servers for RSS.");

    // 优化3：指针有效性前置校验（防卫式编程）
    if (filters == nullptr || raw_query_vector == nullptr) {
        std::cerr << "[Error] Null pointer passed to GenerateCombinedVBFilter." << std::endl;
        return; 
    }

    std::cout << "going to generate filter" << std::endl;

    // 生成每一个 BaseVBFilter
    for(int i = 0; i < num_query; i++) {
        // 优化4：使用 std::vector 替代裸数组 BaseVBFilter *tmp[3]
        // 自动管理内存并初始化为 nullptr，大小严格绑定 NUM_SERVERS
        std::vector<BaseVBFilter*> tmp(NUM_SERVERS, nullptr);

        for(int j = 0; j < NUM_SERVERS; j++) {
            if (filters[j] != nullptr) {
                tmp[j] = filters[j]->add_base_vbfilters();
            } else {
                std::cerr << "[Error] filters[" << j << "] is null." << std::endl;
                // 视业务逻辑而定，此处也可选择抛出异常 throw std::invalid_argument
                return; 
            }
        }
        
        // tmp.data() 返回底层指针数组，完美兼容原有 GenerateBaseVBFilter 函数的签名要求
        GenerateBaseVBFilter(table_id, is_point, num_buckets, raw_query_vector[i], tmp.data());
    }    
    
    std::cout << "generated BaseVBFilter" << std::endl;

    // 优化5：消除末尾硬编码的 0, 1, 2 索引
    // 使用基于 NUM_SERVERS 的循环，统一且安全地设置 is_and 属性
    for(int j = 0; j < NUM_SERVERS; j++) {
        filters[j]->set_is_and(is_and);
    }
}

void QueryClient::GenerateBaseBOFilter(string id, uint32_t x, BaseBOFilter *filters[]) {
    if (BOBlockNum.count(id) == 0 || BOBlockSize.count(id) == 0 || BONumBuckets.count(id) == 0) {
        throw std::invalid_argument("BO table metadata not found: " + id);
    }

    uint32_t blockNum = BOBlockNum[id];
    uint32_t blockSize = BOBlockSize[id];
    uint32_t numBuckets = BONumBuckets[id];
    if (x >= numBuckets) {
        throw std::out_of_range("BO query x out of range.");
    }

    uint32_t blockIndex = x / blockSize;
    uint32_t offsetIndex = x % blockSize;
    uint128_t *raw_block = createIndicatorVector(blockIndex, blockNum);
    uint128_t *raw_offset = createIndicatorVector(offsetIndex, blockSize);
    GenerateBaseBOFilter(id, raw_block, raw_offset, filters);
    free(raw_block);
    free(raw_offset);
}

void QueryClient::GenerateBaseBOFilter(string id, const uint128_t *raw_block, const uint128_t *raw_offset, BaseBOFilter *filters[]) {
    if (BOBlockNum.count(id) == 0 || BOBlockSize.count(id) == 0 || BONumBuckets.count(id) == 0) {
        throw std::invalid_argument("BO table metadata not found: " + id);
    }

    uint32_t blockNum = BOBlockNum[id];
    uint32_t blockSize = BOBlockSize[id];

    for (int i = 0; i < NUM_SERVERS; i++) {
        filters[i]->set_id(id);
    }

    // Keep BO query material generation consistent with VB:
    // for each underlying share index, sample r and send the complementary pair (r, q-r)
    // to the two servers that hold that share index.
    std::vector<uint128_t> tmp_r(std::max(blockNum, blockSize));
    std::vector<uint128_t> tmp_q(std::max(blockNum, blockSize));

    // block share index 1 -> S0:block_share_0, S2:block_share_1
    for (uint32_t i = 0; i < blockNum; i++) {
        tmp_r[i] = randFieldElem(prng);
        tmp_q[i] = raw_block[i] - tmp_r[i];
    }
    filters[0]->set_block_share_0((const uint8_t *)tmp_r.data(), blockNum * sizeof(uint128_t));
    filters[2]->set_block_share_1((const uint8_t *)tmp_q.data(), blockNum * sizeof(uint128_t));

    // block share index 2 -> S0:block_share_1, S1:block_share_0
    for (uint32_t i = 0; i < blockNum; i++) {
        tmp_r[i] = randFieldElem(prng);
        tmp_q[i] = raw_block[i] - tmp_r[i];
    }
    filters[0]->set_block_share_1((const uint8_t *)tmp_r.data(), blockNum * sizeof(uint128_t));
    filters[1]->set_block_share_0((const uint8_t *)tmp_q.data(), blockNum * sizeof(uint128_t));

    // block share index 3 -> S1:block_share_1, S2:block_share_0
    for (uint32_t i = 0; i < blockNum; i++) {
        tmp_r[i] = randFieldElem(prng);
        tmp_q[i] = raw_block[i] - tmp_r[i];
    }
    filters[1]->set_block_share_1((const uint8_t *)tmp_r.data(), blockNum * sizeof(uint128_t));
    filters[2]->set_block_share_0((const uint8_t *)tmp_q.data(), blockNum * sizeof(uint128_t));

    // offset share index 1 -> S0:offset_share_0, S2:offset_share_1
    for (uint32_t i = 0; i < blockSize; i++) {
        tmp_r[i] = randFieldElem(prng);
        tmp_q[i] = raw_offset[i] - tmp_r[i];
    }
    filters[0]->set_offset_share_0((const uint8_t *)tmp_r.data(), blockSize * sizeof(uint128_t));
    filters[2]->set_offset_share_1((const uint8_t *)tmp_q.data(), blockSize * sizeof(uint128_t));

    // offset share index 2 -> S0:offset_share_1, S1:offset_share_0
    for (uint32_t i = 0; i < blockSize; i++) {
        tmp_r[i] = randFieldElem(prng);
        tmp_q[i] = raw_offset[i] - tmp_r[i];
    }
    filters[0]->set_offset_share_1((const uint8_t *)tmp_r.data(), blockSize * sizeof(uint128_t));
    filters[1]->set_offset_share_0((const uint8_t *)tmp_q.data(), blockSize * sizeof(uint128_t));

    // offset share index 3 -> S1:offset_share_1, S2:offset_share_0
    for (uint32_t i = 0; i < blockSize; i++) {
        tmp_r[i] = randFieldElem(prng);
        tmp_q[i] = raw_offset[i] - tmp_r[i];
    }
    filters[1]->set_offset_share_1((const uint8_t *)tmp_r.data(), blockSize * sizeof(uint128_t));
    filters[2]->set_offset_share_0((const uint8_t *)tmp_q.data(), blockSize * sizeof(uint128_t));

}

void QueryClient::GenerateCombinedBOFilter(const string& table_id, const vector<uint32_t> &query, bool is_and, CombinedBOFilter *filters[]) {
    GenerateCombinedBOFilter(table_id, query, true, is_and, filters);
}

void QueryClient::GenerateCombinedBOFilter(const string& table_id, const vector<uint32_t> &query, bool is_point, bool is_and, CombinedBOFilter *filters[]) {
    if (BOBlockNum.count(table_id) == 0 || BOBlockSize.count(table_id) == 0 || BONumBuckets.count(table_id) == 0) {
        throw std::invalid_argument("BO table metadata not found: " + table_id);
    }
    if (query.empty()) {
        throw std::invalid_argument("Empty BO query.");
    }

    const uint32_t numBuckets = BONumBuckets[table_id];
    const uint32_t blockNum = BOBlockNum[table_id];
    const uint32_t blockSize = BOBlockSize[table_id];

    auto emit_materialized_leaf = [&](uint32_t predicate_index,
                                      const std::vector<uint128_t> &block_payload,
                                      const std::vector<uint128_t> &offset_payload) {
        if (block_payload.size() != blockNum || offset_payload.size() != blockSize) {
            throw std::invalid_argument("Invalid BO leaf payload size.");
        }
        BaseBOFilter *tmp[NUM_SERVERS];
        for (int j = 0; j < NUM_SERVERS; j++) {
            tmp[j] = filters[j]->add_base_bofilters();
        }
        GenerateBaseBOFilter(table_id, block_payload.data(), offset_payload.data(), tmp);
        for (int j = 0; j < NUM_SERVERS; j++) {
            tmp[j]->set_predicate_index(predicate_index);
        }
    };

    if (is_point) {
        for (size_t i = 0; i < query.size(); i++) {
            if (query[i] >= numBuckets) {
                throw std::out_of_range("BO point query value out of range.");
            }
            BaseBOFilter *tmp[NUM_SERVERS];
            for (int j = 0; j < NUM_SERVERS; j++) {
                tmp[j] = filters[j]->add_base_bofilters();
            }
            GenerateBaseBOFilter(table_id, query[i], tmp);
            for (int j = 0; j < NUM_SERVERS; j++) {
                tmp[j]->set_predicate_index((uint32_t)i);
            }
        }
        for (int j = 0; j < NUM_SERVERS; j++) {
            filters[j]->set_is_and(is_and);
        }
        return;
    }

    // Range mode: query is [l0, r0, l1, r1, ...].
    if (query.size() % 2 != 0) {
        throw std::invalid_argument("BO range query expects boundary pairs.");
    }
    const size_t num_ranges = query.size() / 2;
    const uint32_t last = numBuckets - 1;
    std::vector<uint128_t> offset_all_ones(blockSize, (uint128_t)1);

    auto make_block_onehot = [&](uint32_t b) {
        std::vector<uint128_t> m(blockNum, 0);
        m[b] = 1;
        return m;
    };
    auto make_block_interval = [&](uint32_t l, uint32_t r) {
        std::vector<uint128_t> m(blockNum, 0);
        for (uint32_t b = l; b <= r; b++) {
            m[b] = 1;
        }
        return m;
    };
    auto make_offset_interval = [&](uint32_t l, uint32_t r) {
        std::vector<uint128_t> m(blockSize, 0);
        for (uint32_t o = l; o <= r; o++) {
            m[o] = 1;
        }
        return m;
    };
    auto make_offset_ge = [&](uint32_t l) {
        std::vector<uint128_t> m(blockSize, 0);
        for (uint32_t o = l; o < blockSize; o++) {
            m[o] = 1;
        }
        return m;
    };
    auto make_offset_le = [&](uint32_t r) {
        std::vector<uint128_t> m(blockSize, 0);
        for (uint32_t o = 0; o <= r; o++) {
            m[o] = 1;
        }
        return m;
    };

    for (size_t i = 0; i < num_ranges; i++) {
        const uint32_t left = query[i * 2];
        const uint32_t right = query[i * 2 + 1];
        if (left >= numBuckets || right >= numBuckets) {
            throw std::out_of_range("BO range boundary out of range.");
        }
        if (left > right) {
            throw std::invalid_argument("BO range requires left <= right.");
        }
        const uint32_t pred = (uint32_t)i;
        const uint32_t bL = left / blockSize;
        const uint32_t oL = left % blockSize;
        const uint32_t bR = right / blockSize;
        const uint32_t oR = right % blockSize;

        // Single-sided upper bound: x <= right
        if (left == 0 && right < last) {
            if (bR > 0) {
                emit_materialized_leaf(pred, make_block_interval(0, bR - 1), offset_all_ones);
            }
            emit_materialized_leaf(pred, make_block_onehot(bR), make_offset_le(oR));
            continue;
        }

        // Single-sided lower bound: x >= left
        if (right == last && left > 0) {
            if (bL + 1 < blockNum) {
                emit_materialized_leaf(pred, make_block_interval(bL + 1, blockNum - 1), offset_all_ones);
            }
            emit_materialized_leaf(pred, make_block_onehot(bL), make_offset_ge(oL));
            continue;
        }

        // General interval [left, right]
        if (bL == bR) {
            emit_materialized_leaf(pred, make_block_onehot(bL), make_offset_interval(oL, oR));
            continue;
        }

        if (oL > 0) {
            emit_materialized_leaf(pred, make_block_onehot(bL), make_offset_ge(oL));
        }
        if (oR + 1 < blockSize) {
            emit_materialized_leaf(pred, make_block_onehot(bR), make_offset_le(oR));
        }

        const uint32_t midL = bL + (oL > 0 ? 1 : 0);
        const uint32_t midR = bR - (oR + 1 < blockSize ? 1 : 0);
        if (midL <= midR) {
            emit_materialized_leaf(pred, make_block_interval(midL, midR), offset_all_ones);
        }
    }

    // Predicate leaves are OR-ed inside predicate, then predicates combine via is_and.
    for (int j = 0; j < NUM_SERVERS; j++) {
        filters[j]->set_is_and(is_and);
    }
}

void QueryClient::GenerateCombinedBOFSSFilter(const string& table_id, const vector<uint32_t> &query, bool is_and, CombinedBOFSSFilter *filters[]) {
    GenerateCombinedBOFSSFilter(table_id, query, true, is_and, filters);
}

void QueryClient::GenerateCombinedBOFSSFilter(const string& table_id, const vector<uint32_t> &query, bool is_point, bool is_and, CombinedBOFSSFilter *filters[]) {
    if (BOBlockNum.count(table_id) == 0 || BOBlockSize.count(table_id) == 0 || BONumBuckets.count(table_id) == 0) {
        throw std::invalid_argument("BO table metadata not found: " + table_id);
    }
    if (query.empty()) {
        throw std::invalid_argument("BOFSS query must contain at least one predicate.");
    }

    const uint32_t blockNum = BOBlockNum[table_id];
    const uint32_t blockSize = BOBlockSize[table_id];
    const uint32_t numBuckets = BONumBuckets[table_id];
    std::vector<uint128_t> scalar_payload(1, (uint128_t)1);

    for (int s = 0; s < NUM_SERVERS; s++) {
        filters[s]->set_is_and(is_and);
    }

    auto gen_vdpf_point_keys = [&](uint32_t domain_size, uint32_t point, std::string (&out)[NUM_SERVERS][2]) {
        // RSS-aligned placement of additive shares:
        // share0 -> (S0.key0, S2.key1)
        // share1 -> (S1.key0, S0.key1)
        // share2 -> (S2.key0, S1.key1)
        waldo::VDPFKeyPair ks0 = waldo::VDPF::GenPointVector(domain_size, point, scalar_payload);
        waldo::VDPFKeyPair ks1 = waldo::VDPF::GenPointVector(domain_size, point, scalar_payload);
        waldo::VDPFKeyPair ks2 = waldo::VDPF::GenPointVector(domain_size, point, scalar_payload);
        out[0][0] = waldo::VDPF::SerializeKeyPack(ks0.key0);
        out[2][1] = waldo::VDPF::SerializeKeyPack(ks0.key1);
        out[1][0] = waldo::VDPF::SerializeKeyPack(ks1.key0);
        out[0][1] = waldo::VDPF::SerializeKeyPack(ks1.key1);
        out[2][0] = waldo::VDPF::SerializeKeyPack(ks2.key0);
        out[1][1] = waldo::VDPF::SerializeKeyPack(ks2.key1);
    };

    auto gen_vdcf_keys = [&](uint32_t domain_size, waldo::VDCFCompareOp op, uint32_t threshold, std::string (&out)[NUM_SERVERS][2]) {
        waldo::VDCFKeyPair ks0 = waldo::VDCF::GenCompareVector(domain_size, op, threshold, scalar_payload);
        waldo::VDCFKeyPair ks1 = waldo::VDCF::GenCompareVector(domain_size, op, threshold, scalar_payload);
        waldo::VDCFKeyPair ks2 = waldo::VDCF::GenCompareVector(domain_size, op, threshold, scalar_payload);
        out[0][0] = waldo::VDCF::SerializeKeyPack(ks0.key0);
        out[2][1] = waldo::VDCF::SerializeKeyPack(ks0.key1);
        out[1][0] = waldo::VDCF::SerializeKeyPack(ks1.key0);
        out[0][1] = waldo::VDCF::SerializeKeyPack(ks1.key1);
        out[2][0] = waldo::VDCF::SerializeKeyPack(ks2.key0);
        out[1][1] = waldo::VDCF::SerializeKeyPack(ks2.key1);
    };

    auto emit_leaf_pair = [&](uint32_t pred,
                              const std::string (&bk)[NUM_SERVERS][2], dbquery::BOFSSPrimitiveType btype,
                              const std::string (&ok)[NUM_SERVERS][2], dbquery::BOFSSPrimitiveType otype) {
        for (int s = 0; s < NUM_SERVERS; s++) {
            BaseBOFSSFilter *bf_block = filters[s]->add_base_bofssfilters();
            bf_block->set_id(table_id);
            bf_block->set_predicate_index(pred);
            bf_block->set_domain_size(blockNum);
            bf_block->set_domain_type(dbquery::BOFSS_DOMAIN_BLOCK);
            bf_block->set_primitive_type(btype);
            bf_block->set_key0(bk[s][0]);
            bf_block->set_key1(bk[s][1]);

            BaseBOFSSFilter *bf_offset = filters[s]->add_base_bofssfilters();
            bf_offset->set_id(table_id);
            bf_offset->set_predicate_index(pred);
            bf_offset->set_domain_size(blockSize);
            bf_offset->set_domain_type(dbquery::BOFSS_DOMAIN_OFFSET);
            bf_offset->set_primitive_type(otype);
            bf_offset->set_key0(ok[s][0]);
            bf_offset->set_key1(ok[s][1]);
        }
    };

    auto emit_point_leaf = [&](uint32_t pred, uint32_t x) {
        if (x >= numBuckets) {
            throw std::out_of_range("BOFSS query value out of range.");
        }
        const uint32_t blockIndex = x / blockSize;
        const uint32_t offsetIndex = x % blockSize;
        std::string bk[NUM_SERVERS][2];
        std::string ok[NUM_SERVERS][2];
        gen_vdpf_point_keys(blockNum, blockIndex, bk);
        gen_vdpf_point_keys(blockSize, offsetIndex, ok);
        emit_leaf_pair(pred, bk, dbquery::BOFSS_PRIMITIVE_VDPF, ok, dbquery::BOFSS_PRIMITIVE_VDPF);
    };

    if (is_point) {
        for (uint32_t pred = 0; pred < (uint32_t)query.size(); pred++) {
            emit_point_leaf(pred, query[pred]);
        }
        return;
    }

    if (query.size() % 2 != 0) {
        throw std::invalid_argument("BOFSS single-sided range expects boundary pairs: [l0,r0,l1,r1,...].");
    }

    // Single-sided only:
    // [0, r]    => x <= r
    // [l, N-1]  => x >= l
    //
    // Per predicate emit two leaves (BO+FSS doc-aligned):
    //  Leaf A: full-block part
    //    - <= : block LT b*, offset TRUE
    //    - >= : block GT b*, offset TRUE
    //  Leaf B: boundary block part
    //    - block EQ b* (VDPF point)
    //    - offset <= o* or >= o* (VDCF compare)
    const uint32_t last = numBuckets - 1;
    const uint32_t num_pred = (uint32_t)(query.size() / 2);
    for (uint32_t pred = 0; pred < num_pred; pred++) {
        const uint32_t left = query[(size_t)pred * 2];
        const uint32_t right = query[(size_t)pred * 2 + 1];
        if (left >= numBuckets || right >= numBuckets) {
            throw std::out_of_range("BOFSS range boundary out of range.");
        }
        std::string bk_full[NUM_SERVERS][2];
        std::string ok_full[NUM_SERVERS][2];
        std::string bk_boundary[NUM_SERVERS][2];
        std::string ok_boundary[NUM_SERVERS][2];

        if (left == 0) {
            const uint32_t b = right / blockSize;
            const uint32_t o = right % blockSize;

            gen_vdcf_keys(blockNum, waldo::VDCFCompareOp::LT, b, bk_full);
            gen_vdcf_keys(blockSize, waldo::VDCFCompareOp::GE, 0, ok_full);
            emit_leaf_pair(pred, bk_full, dbquery::BOFSS_PRIMITIVE_VDCF, ok_full, dbquery::BOFSS_PRIMITIVE_VDCF);

            gen_vdpf_point_keys(blockNum, b, bk_boundary);
            gen_vdcf_keys(blockSize, waldo::VDCFCompareOp::LE, o, ok_boundary);
            emit_leaf_pair(pred, bk_boundary, dbquery::BOFSS_PRIMITIVE_VDPF, ok_boundary, dbquery::BOFSS_PRIMITIVE_VDCF);
        } else if (right == last) {
            const uint32_t b = left / blockSize;
            const uint32_t o = left % blockSize;

            gen_vdcf_keys(blockNum, waldo::VDCFCompareOp::GT, b, bk_full);
            gen_vdcf_keys(blockSize, waldo::VDCFCompareOp::GE, 0, ok_full);
            emit_leaf_pair(pred, bk_full, dbquery::BOFSS_PRIMITIVE_VDCF, ok_full, dbquery::BOFSS_PRIMITIVE_VDCF);

            gen_vdpf_point_keys(blockNum, b, bk_boundary);
            gen_vdcf_keys(blockSize, waldo::VDCFCompareOp::GE, o, ok_boundary);
            emit_leaf_pair(pred, bk_boundary, dbquery::BOFSS_PRIMITIVE_VDPF, ok_boundary, dbquery::BOFSS_PRIMITIVE_VDCF);
        } else {
            throw std::invalid_argument("BOFSS range currently supports single-sided predicates only: [0,r] or [l,N-1].");
        }
    }
}

void QueryClient::AddOneHotTable(string table_id, uint32_t windowSize, uint32_t numBuckets, const vector<uint32_t> &data) {
    RegisterOneHotTableMeta(table_id, numBuckets);
    assert(data.size() >= windowSize);

    for (int i = 0; i < NUM_SERVERS; i++) {
        InitOneHotTableRequest req;
        InitOneHotTableResponse resp;
        ClientContext ctx;
        req.set_table_id(table_id);
        req.set_windowsize(windowSize);
        req.set_numbuckets(numBuckets);
        queryStubs[i]->SendOneHotTableInit(&ctx, req, &resp);
    }

    const size_t chunk_sz = ComputeSafeUpdateChunk(numBuckets);
    for (size_t batch_start = 0; batch_start < windowSize; batch_start += chunk_sz) {
        UpdateOneHotTableBatchRequest reqs[NUM_SERVERS];
        const size_t batch_end = std::min<size_t>(windowSize, batch_start + chunk_sz);
        for (size_t idx = batch_start; idx < batch_end; idx++) {
            UpdateOneHotTableRequest *tmp_reqs[NUM_SERVERS];
            for (int j = 0; j < NUM_SERVERS; j++) {
                tmp_reqs[j] = reqs[j].add_update();
            }
            this->OneHotTableUpdate(table_id, (uint32_t)idx, data[idx], tmp_reqs);
        }

        for (int i = 0; i < NUM_SERVERS; i++) {
            UpdateOneHotTableBatchResponse resp;
            ClientContext ctx;
            queryStubs[i]->SendOneHotTableBatchUpdate(&ctx, reqs[i], &resp);
        }
    }
}

void QueryClient::RegisterOneHotTableMeta(string table_id, uint32_t numBuckets) {
    OneHotNumBuckets[table_id] = numBuckets;
}

void QueryClient::OneHotTableUpdate(string id, uint32_t idx, uint32_t rank_loc, UpdateOneHotTableRequest *reqs[]) {
    uint32_t numBuckets = OneHotNumBuckets[id];
    uint128_t *raw_data = createIndicatorVector(rank_loc, numBuckets);
    uint128_t *shares[NUM_SERVERS];
    for (int i = 0; i < NUM_SERVERS; i++) {
        shares[i] = (uint128_t *)malloc(numBuckets * sizeof(uint128_t));
    }
    splitIntoArithmeticShares(prng, raw_data, numBuckets, shares);

    for (int i = 0; i < NUM_SERVERS; i++) {
        reqs[i]->set_table_id(id);
        reqs[i]->set_rank_loc(idx);
        reqs[i]->set_share_data_0((char *)shares[i], sizeof(uint128_t) * numBuckets);
        reqs[i]->set_share_data_1((char *)shares[(i + 1) % NUM_SERVERS], sizeof(uint128_t) * numBuckets);
    }

    free(raw_data);
    for (int i = 0; i < NUM_SERVERS; i++) {
        free(shares[i]);
    }
}

void QueryClient::AddBOTable(string table_id, uint32_t windowSize, uint32_t numBuckets, uint32_t logBlockNum, const vector<uint32_t> &data) {
    RegisterBOTableMeta(table_id, numBuckets, logBlockNum);
    assert(data.size() >= windowSize);

    for (int i = 0; i < NUM_SERVERS; i++) {
        InitBOTableRequest req;
        InitBOTableResponse resp;
        ClientContext ctx;
        req.set_table_id(table_id);
        req.set_windowsize(windowSize);
        req.set_numbuckets(numBuckets);
        req.set_logblocknum(logBlockNum);
        queryStubs[i]->SendBOTableInit(&ctx, req, &resp);
    }

    const size_t chunk_sz = ComputeSafeUpdateChunk(numBuckets);
    for (size_t batch_start = 0; batch_start < windowSize; batch_start += chunk_sz) {
        UpdateBOTableBatchRequest reqs[NUM_SERVERS];
        const size_t batch_end = std::min<size_t>(windowSize, batch_start + chunk_sz);
        for (size_t idx = batch_start; idx < batch_end; idx++) {
            UpdateBOTableRequest *tmp_reqs[NUM_SERVERS];
            for (int j = 0; j < NUM_SERVERS; j++) {
                tmp_reqs[j] = reqs[j].add_update();
            }
            this->BOTableUpdate(table_id, (uint32_t)idx, data[idx], tmp_reqs);
        }

        for (int i = 0; i < NUM_SERVERS; i++) {
            UpdateBOTableBatchResponse resp;
            ClientContext ctx;
            queryStubs[i]->SendBOTableBatchUpdate(&ctx, reqs[i], &resp);
        }
    }
}

void QueryClient::RegisterBOTableMeta(string table_id, uint32_t numBuckets, uint32_t logBlockNum) {
    if (logBlockNum >= 31) {
        throw std::invalid_argument("logBlockNum is too large.");
    }
    uint32_t blockNum = 1u << logBlockNum;
    if (blockNum == 0 || numBuckets == 0 || numBuckets % blockNum != 0) {
        throw std::invalid_argument("Invalid BO table parameters.");
    }
    BONumBuckets[table_id] = numBuckets;
    BOLogBlockNum[table_id] = logBlockNum;
    BOBlockNum[table_id] = blockNum;
    BOBlockSize[table_id] = numBuckets / blockNum;
}

void QueryClient::BOTableUpdate(string id, uint32_t idx, uint32_t rank_loc, UpdateBOTableRequest *reqs[]) {
    uint32_t blockNum = BOBlockNum[id];
    uint32_t blockSize = BOBlockSize[id];
    uint32_t blockIndex = rank_loc / blockSize;
    uint32_t offsetIndex = rank_loc % blockSize;

    uint128_t *raw_index = createIndicatorVector(blockIndex, blockNum);
    uint128_t *raw_offset = createIndicatorVector(offsetIndex, blockSize);

    uint128_t *index_shares[NUM_SERVERS];
    uint128_t *offset_shares[NUM_SERVERS];
    for (int i = 0; i < NUM_SERVERS; i++) {
        index_shares[i] = (uint128_t *)malloc(blockNum * sizeof(uint128_t));
        offset_shares[i] = (uint128_t *)malloc(blockSize * sizeof(uint128_t));
    }

    splitIntoArithmeticShares(prng, raw_index, blockNum, index_shares);
    splitIntoArithmeticShares(prng, raw_offset, blockSize, offset_shares);

    for (int i = 0; i < NUM_SERVERS; i++) {
        reqs[i]->set_table_id(id);
        reqs[i]->set_rank_loc(idx);
        reqs[i]->set_index_share_data_0((char *)index_shares[i], sizeof(uint128_t) * blockNum);
        reqs[i]->set_index_share_data_1((char *)index_shares[(i + 1) % NUM_SERVERS], sizeof(uint128_t) * blockNum);
        reqs[i]->set_offset_share_data_0((char *)offset_shares[i], sizeof(uint128_t) * blockSize);
        reqs[i]->set_offset_share_data_1((char *)offset_shares[(i + 1) % NUM_SERVERS], sizeof(uint128_t) * blockSize);
    }

    free(raw_index);
    free(raw_offset);
    for (int i = 0; i < NUM_SERVERS; i++) {
        free(index_shares[i]);
        free(offset_shares[i]);
    }
}

void QueryClient::GenerateBaseVBFilter(string id, bool is_point, int num_buckets, uint128_t *raw_query_vector, BaseVBFilter *filters[]) {
    
    filters[0]->set_id(id);
    filters[1]->set_id(id);
    filters[2]->set_id(id);
    
    filters[0]->set_is_point(is_point);
    filters[1]->set_is_point(is_point);
    filters[2]->set_is_point(is_point);

    // 【内存安全修复】使用 std::vector 替代 VLA。
    // 内存被安全地分配在堆 (Heap) 上，彻底杜绝高并发下的栈溢出崩溃。
    std::vector<uint128_t> tmp_r(num_buckets);
    std::vector<uint128_t> tmp_q(num_buckets);
    size_t byte_size = num_buckets * sizeof(uint128_t);

    // r_0
    for(int i = 0; i < num_buckets; i++) {
        tmp_r[i] = randFieldElem(prng);
        // tmp_r[i] = 0;
        tmp_q[i] = raw_query_vector[i] - tmp_r[i];
    }
    filters[0]->set_share_0((const uint8_t *)tmp_r.data(), byte_size);
    filters[2]->set_share_1((const uint8_t *)tmp_q.data(), byte_size);

    // r_1
    for(int i = 0; i < num_buckets; i++) {
        tmp_r[i] = randFieldElem(prng);
        // tmp_r[i] = 0;
        tmp_q[i] = raw_query_vector[i] - tmp_r[i];        
    }
    filters[0]->set_share_1((const uint8_t *)tmp_r.data(), byte_size);
    filters[1]->set_share_0((const uint8_t *)tmp_q.data(), byte_size);

    // r_2
    for(int i = 0; i < num_buckets; i++) {
        tmp_r[i] = randFieldElem(prng);
        // tmp_r[i] = 0;
        tmp_q[i] = raw_query_vector[i] - tmp_r[i];

    }
    filters[1]->set_share_1((const uint8_t *)tmp_r.data(), byte_size);
    filters[2]->set_share_0((const uint8_t *)tmp_q.data(), byte_size);
}

uint128_t *QueryClient::DCFQuery(string id, uint32_t left_x, uint32_t right_x, size_t ret_len) {
    uint128_t *ret = (uint128_t *)malloc(ret_len * sizeof(uint128_t));
    memset(ret, 0, ret_len * sizeof(uint128_t));

    uint8_t *k[NUM_SERVERS][2];
    size_t key_len;
    uint64_t gout_bitsize = 125;
    uint128_t one = 1;
    uint128_t group_mod = one << gout_bitsize; 
    DCFTables[id]->gen_dcf_table_keys((uint128_t)left_x, (uint128_t)right_x, DCFTables[id]->depth, gout_bitsize, true, group_mod);
    DCFTables[id]->serialize_keys(&k[0][0], &k[1][1], &key_len);
    
    DCFTables[id]->gen_dcf_table_keys((uint128_t)left_x, (uint128_t)right_x, DCFTables[id]->depth, gout_bitsize, true, group_mod);
    DCFTables[id]->serialize_keys(&k[1][0], &k[2][1], &key_len);
    
    DCFTables[id]->gen_dcf_table_keys((uint128_t)left_x, (uint128_t)right_x, DCFTables[id]->depth, gout_bitsize, true, group_mod);
    DCFTables[id]->serialize_keys(&k[2][0], &k[0][1], &key_len);
    
    QueryDCFRequest reqs[NUM_SERVERS];
    QueryDCFResponse resps[NUM_SERVERS];
    unique_ptr<ClientAsyncResponseReader<QueryDCFResponse>> rpcs[NUM_SERVERS];
    Status status[NUM_SERVERS];
    ClientContext ctx[NUM_SERVERS];
    CompletionQueue cq[NUM_SERVERS];
    for (int i = 0; i < NUM_SERVERS; i++) {
        reqs[i].set_id(id);
        reqs[i].set_key0(k[i][0], key_len);
        reqs[i].set_key1(k[i][1], key_len);
        rpcs[i] = queryStubs[i]->AsyncSendDCFQuery(&ctx[i], reqs[i], &cq[i]);
    }
    for (int i = 0; i < NUM_SERVERS; i++) {
        void *got_tag;
        bool ok = false;
        rpcs[i]->Finish(&resps[i], &status[i], (void *)1);
        cq[i].Next(&got_tag, &ok);
        if (ok && got_tag == (void *)1) {
            if (status[i].ok()) {
                const uint128_t *res = (const uint128_t *)resps[i].res().c_str();
                for (int i = 0; i < ret_len; i++) {
                    ret[i] += res[i];
                }
            } else {
                printf("ERROR receiving message: %s\n", status[i].error_message().c_str());
            }
        }
    }
    for (int i = 0; i < ret_len; i++) {
        ret[i] %= group_mod;
    }

    return ret;
}

void QueryClient::AggTreeQuery(string id, uint128_t left_x, uint128_t right_x, uint128_t **ret, uint128_t **ret_r) {
    uint8_t *k[NUM_SERVERS][2];
    size_t key_len;
    uint64_t gout_bitsize = 125;
    uint128_t one = 1;
    uint128_t group_mod = (one << gout_bitsize);
    *ret = (uint128_t *)malloc(AggTrees[id]->depth * sizeof(uint128_t));
    *ret_r = (uint128_t *)malloc(AggTrees[id]->depth * sizeof(uint128_t));
    uint128_t mac;
    uint128_t mac_r;
    uint128_t retShares0[NUM_SERVERS];
    uint128_t macShares0[NUM_SERVERS];
    uint128_t retShares0_r[NUM_SERVERS];
    uint128_t macShares0_r[NUM_SERVERS];
    uint128_t retShares[NUM_SERVERS][AggTrees[id]->depth + 1];
    uint128_t macShares[NUM_SERVERS][AggTrees[id]->depth + 1];
    uint128_t retShares_r[NUM_SERVERS][AggTrees[id]->depth + 1];
    uint128_t macShares_r[NUM_SERVERS][AggTrees[id]->depth + 1];

    AggTrees[id]->gen_agg_tree_keys(left_x, right_x, AggTrees[id]->depth, gout_bitsize, true, group_mod);
    AggTrees[id]->serialize_keys(&k[0][0], &k[1][1], &key_len);

    AggTrees[id]->gen_agg_tree_keys(left_x, right_x, AggTrees[id]->depth, gout_bitsize, true, group_mod);
    AggTrees[id]->serialize_keys(&k[1][0], &k[2][1], &key_len);

    AggTrees[id]->gen_agg_tree_keys(left_x, right_x, AggTrees[id]->depth, gout_bitsize, true, group_mod);
    AggTrees[id]->serialize_keys(&k[2][0], &k[0][1], &key_len);

    QueryATRequest reqs[NUM_SERVERS];
    QueryATResponse resps[NUM_SERVERS];
    unique_ptr<ClientAsyncResponseReader<QueryATResponse>> rpcs[NUM_SERVERS];
    Status status[NUM_SERVERS];
    ClientContext ctx[NUM_SERVERS];
    CompletionQueue cq[NUM_SERVERS];
    
    for (int i = 0; i < NUM_SERVERS; i++) {
        reqs[i].set_id(id);
        reqs[i].set_key0(k[i][0], key_len);
        reqs[i].set_key1(k[i][1], key_len);
        rpcs[i] = queryStubs[i]->AsyncSendATQuery(&ctx[i], reqs[i], &cq[i]);
    }
    for (int i = 0; i < NUM_SERVERS; i++) {
        void *got_tag;
        bool ok = false;
        rpcs[i]->Finish(&resps[i], &status[i], (void *)1);
        cq[i].Next(&got_tag, &ok);
        if (ok && got_tag == (void *)1) {
            if (status[i].ok()) {
                memcpy((uint8_t *)&retShares[i], (const uint8_t *)resps[i].res().c_str(), (AggTrees[id]->depth) * sizeof(uint128_t));
                if (malicious) {
                    memcpy((uint8_t *)&macShares[i], (const uint8_t *)resps[i].mac().c_str(), (AggTrees[id]->depth) * sizeof(uint128_t));
                }
                memcpy((uint8_t *)&retShares_r[i], (const uint8_t *)resps[i].res_r().c_str(), (AggTrees[id]->depth) * sizeof(uint128_t));
                if (malicious) {
                    memcpy((uint8_t *)&macShares_r[i], (const uint8_t *)resps[i].mac_r().c_str(), (AggTrees[id]->depth) * sizeof(uint128_t));
                }
            } else {
                printf("ERROR receiving message: %s\n", status[i].error_message().c_str());
            }
        }
    }
    for (int i = 0; i < AggTrees[id]->depth; i++){
        // left
        uint128_t shares[NUM_SERVERS];
        uint128_t shares_r[NUM_SERVERS];
        uint128_t macs[NUM_SERVERS];
        uint128_t macs_r[NUM_SERVERS];
        for (int j = 0; j < NUM_SERVERS; j++) {
            shares[j] = retShares[j][i];
            shares_r[j] = retShares_r[j][i];
            macs[j] = macShares[j][i];
            macs_r[j] = macShares_r[j][i];
        }
        (*ret)[i] = combineSingleArithmeticShares(shares, NUM_SERVERS, false);
        (*ret)[i] %= group_mod;
        // right
        (*ret_r)[i] = combineSingleArithmeticShares(shares_r, NUM_SERVERS, false);
        (*ret_r)[i] %= group_mod;
        if (malicious) {
            // left
            mac = combineSingleArithmeticShares(macs, NUM_SERVERS, false);
            mac %= group_mod;
            assert (((*ret)[i] * GetMACAlpha()) % group_mod == mac);
            // right
            mac_r = combineSingleArithmeticShares(macs_r, NUM_SERVERS, false);
            mac_r %= group_mod;
            assert (((*ret_r)[i] * GetMACAlpha()) % group_mod == mac_r);
        }
    }
    // TODO: assemble shares based on aggregation function
    if (malicious) {
        cout << "MAC check passed" << endl;
    }
}

uint128_t QueryClient::GetMACAlpha(){
    return alpha;
}
