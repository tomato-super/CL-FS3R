// Modified by Waldo derivative maintainers on 2026-04-23.
#include <fstream>
#include <thread>
#include <stdexcept>
#include <chrono>
#include <cstdlib>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <cryptoTools/Crypto/AES.h>
#include "../../secure-indices/core/DCFTable.h"
#include "../../secure-indices/core/DPFTable.h"
#include "../../secure-indices/core/AggTree.h"
#include "../../network/core/query.grpc.pb.h"
#include "../../network/core/query.pb.h"
#include "../../secure-indices/core/common.h"
#include "../../utils/json.hpp"
#include "../../utils/config.h"
#include "../../utils/dorydbconfig.h"
#include "../../fss-core/vDPF-source/vdpf.h"
#include "../../fss-core/vDCF-source/vdcf.h"
#include "server.h"
#include "network-emp/core/io_channel.h"
#include "network-emp/core/net_io_channel.h"
#include "network-emp/core/highspeed_net_io_channel.h"

// #include "../../utils/ThreadPool.h"

// #define USE_EMP

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using grpc::ServerAsyncResponseWriter;
using grpc::ServerCompletionQueue;
using grpc::ChannelArguments;
using dbquery::Query;
using dbquery::Aggregate;
using dbquery::InitSystemRequest;
using dbquery::InitSystemResponse;
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
using dbquery::MultRequest;
using dbquery::MultResponse;
using dbquery::CombinedFilter;
using dbquery::BaseFilter;

using dbquery::QueryVBAggResponse;
using dbquery::QueryVBAggRequest;
using dbquery::QueryVBFSSAggResponse;
using dbquery::QueryVBFSSAggRequest;
using dbquery::CombinedVBFilter;
using dbquery::CombinedVBFSSFilter;
using dbquery::BaseVBFilter;
using dbquery::BaseVBFSSFilter;
using dbquery::CombinedBOFilter;
using dbquery::BaseBOFilter;
using dbquery::CombinedBOFSSFilter;
using dbquery::BaseBOFSSFilter;
using dbquery::QueryBOAggResponse;
using dbquery::QueryBOAggRequest;
using dbquery::QueryBOFSSAggResponse;
using dbquery::QueryBOFSSAggRequest;
using dbquery::InitOneHotTableRequest;
using dbquery::InitOneHotTableResponse;
using dbquery::UpdateOneHotTableRequest;
using dbquery::UpdateOneHotTableResponse;
using dbquery::UpdateOneHotTableBatchRequest;
using dbquery::UpdateOneHotTableBatchResponse;
using dbquery::InitBOTableRequest;
using dbquery::InitBOTableResponse;
using dbquery::UpdateBOTableRequest;
using dbquery::UpdateBOTableResponse;
using dbquery::UpdateBOTableBatchRequest;
using dbquery::UpdateBOTableBatchResponse;


using json = nlohmann::json;

using namespace std;
using namespace osuCrypto;
using namespace emp;


NetIO * emp_io_upstream;
NetIO * emp_io_downstream;

namespace {
template <typename T>
inline void DeleteTablePair(std::pair<T *, T *> &p) {
    delete p.first;
    delete p.second;
    p.first = nullptr;
    p.second = nullptr;
}
}  // namespace



QueryServer::QueryServer(string addrs[], int serverID, int cores, bool malicious) {
    this->serverID = serverID;
    this->malicious = malicious;
    this->cores = cores;
    block seed = toBlock(rand(), rand());
    PRNG prng(seed);
    prfKey0 = prng.get<uint64_t>();
    prfCounter = 0;
    multReceivedShares = NULL;

    // this->thread_core = std::thread::hardware_concurrency(); // 获取物理核心数
    
    // 核心步骤：在系统启动时，直接吃满 CPU 核心数创建永久工作线程
    // this->thread_pool = std::unique_ptr<ThreadPool>(new ThreadPool(this->thread_core));
}

void QueryServer::StartSystemInit(string addrs[]) {
    new CallData(*this, service, cq, INIT);
    sleep(10);
    
    ChannelArguments args;
    args.SetMaxSendMessageSize(-1);
    args.SetMaxReceiveMessageSize(-1);
    nextServerStub = Query::NewStub(grpc::CreateCustomChannel(addrs[(serverID + 1) % NUM_SERVERS], grpc::InsecureChannelCredentials(), args));
    multStub = Aggregate::NewStub(grpc::CreateCustomChannel(addrs[(serverID + 1) % NUM_SERVERS], grpc::InsecureChannelCredentials(), args));
    cout << "connected to " << addrs[(serverID + 1) % NUM_SERVERS] << endl;
    
    int emp_port = 32000;
   
    string next_server_addr = addrs[(serverID + 1) % NUM_SERVERS];
    int psn = next_server_addr.find(":");
    next_server_addr = next_server_addr.substr(0, psn);

    if(serverID == 0){
        cout << "setting up EMP connection as client on address, port " << next_server_addr << " " << (emp_port + serverID) << endl;
        emp_io_upstream = new NetIO(next_server_addr.c_str(), emp_port + serverID);
        cout << "setting up EMP connection as server on address, port " << "0.0.0.0" << " " << (emp_port + (2 % NUM_SERVERS)) << endl;
        emp_io_downstream = new NetIO(nullptr, emp_port + (2 % NUM_SERVERS));
    }    
    else{
        cout << "setting up EMP connection as server on address, port " << "0.0.0.0" << " " << (emp_port + ((serverID - 1) % NUM_SERVERS)) << endl;
        emp_io_downstream = new NetIO(nullptr, emp_port + ((serverID - 1) % NUM_SERVERS));
        cout << "setting up EMP connection as client on address, port " << next_server_addr << " " << (emp_port + serverID) << endl;
        emp_io_upstream = new NetIO(next_server_addr.c_str(), emp_port + serverID);
    }

    cout << "connected EMP NetIO to " << next_server_addr << endl;

    InitSystemRequest req;
    InitSystemResponse resp;
    ClientContext ctx;
    req.set_key((char *)&prfKey0, sizeof(uint128_t));
    multStub->SendSystemInit(&ctx, req, &resp);
}

void QueryServer::FinishSystemInit(const uint8_t *key) {
    memcpy((uint8_t *)&prfKey1, key, sizeof(uint128_t));
    cout << "----- DONE WITH SETUP ------" << endl;
}

void QueryServer::AddValList(string id, uint32_t windowSize) {
    vector<uint128_t> list1(windowSize, 0);
    vector<uint128_t> list2(windowSize, 0);
    ValLists[id] = make_pair(list1, list2);
    ValListWindowPtrs[id] = 0;
}

void QueryServer::DCFAddTable(string id, uint32_t windowSize, uint32_t numBuckets, bool malicious) {
    auto it = DCFTables.find(id);
    if (it != DCFTables.end()) {
        DeleteTablePair(it->second);
    }
    DCFTableServer *s1 = new DCFTableServer(id, getDepth(numBuckets), windowSize, cores, malicious);
    DCFTableServer *s2 = new DCFTableServer(id, getDepth(numBuckets), windowSize, cores, malicious);
    DCFTables[id] = make_pair(s1, s2);
    DCFTableWindowPtrs[id] = 0;
}

void QueryServer::DPFAddTable(string id, uint32_t windowSize, uint32_t numBuckets, bool malicious) {
    auto it = DPFTables.find(id);
    if (it != DPFTables.end()) {
        DeleteTablePair(it->second);
    }
    DPFTableServer *s1 = new DPFTableServer(id, getDepth(numBuckets), windowSize, cores, malicious);
    DPFTableServer *s2 = new DPFTableServer(id, getDepth(numBuckets), windowSize, cores, malicious);
    DPFTables[id] = make_pair(s1, s2);
    DPFTableWindowPtrs[id] = 0;
}

void QueryServer::AddOneHotTable(string id, uint32_t windowSize, uint32_t numBuckets) {
    auto it = OneHotTables.find(id);
    if (it != OneHotTables.end()) {
        DeleteTablePair(it->second);
    }
    OneHotTable *s1 = new OneHotTable(id, windowSize, numBuckets);
    OneHotTable *s2 = new OneHotTable(id, windowSize, numBuckets);
    OneHotTables[id] = make_pair(s1, s2);
    OneHotTableWindowPtrs[id] = 0;
}

void QueryServer::AddOneHotTable(string id, uint32_t windowSize, uint32_t numBuckets, uint32_t logBlockNum) {
    auto it = OneHotTables.find(id);
    if (it != OneHotTables.end()) {
        DeleteTablePair(it->second);
    }
    OneHotTable *s1 = new OneHotTable(id, windowSize, numBuckets, logBlockNum);
    OneHotTable *s2 = new OneHotTable(id, windowSize, numBuckets, logBlockNum);
    OneHotTables[id] = make_pair(s1, s2);
    OneHotTableWindowPtrs[id] = 0;
}

void QueryServer::SetOneHotTableBlockLayout(string id, uint32_t logBlockNum) {
    if (OneHotTables.count(id) == 0) {
        throw std::invalid_argument("OneHotTable is not initialized: " + id);
    }
    OneHotTables[id].first->setBlockLayout(logBlockNum);
    OneHotTables[id].second->setBlockLayout(logBlockNum);
}

void QueryServer::AddBOTable(string id, uint32_t windowSize, uint32_t numBuckets, uint32_t logBlockNum) {
    if (logBlockNum >= 31) {
        throw std::invalid_argument("logBlockNum is too large.");
    }
    uint32_t blockNum = 1u << logBlockNum;
    if (blockNum == 0 || numBuckets == 0) {
        throw std::invalid_argument("Invalid BO table parameters.");
    }
    if (numBuckets % blockNum != 0) {
        throw std::invalid_argument("numBuckets must be divisible by blockNum.");
    }
    uint32_t blockSize = numBuckets / blockNum;

    auto idx_it = BOIndexTables.find(id);
    if (idx_it != BOIndexTables.end()) {
        DeleteTablePair(idx_it->second);
    }
    auto off_it = BOOffsetTables.find(id);
    if (off_it != BOOffsetTables.end()) {
        DeleteTablePair(off_it->second);
    }

    BOIndexTable *idx0 = new BOIndexTable(id, windowSize, blockNum);
    BOIndexTable *idx1 = new BOIndexTable(id, windowSize, blockNum);
    BOOffsetTable *off0 = new BOOffsetTable(id, windowSize, blockSize);
    BOOffsetTable *off1 = new BOOffsetTable(id, windowSize, blockSize);
    BOIndexTables[id] = make_pair(idx0, idx1);
    BOOffsetTables[id] = make_pair(off0, off1);
    BOTableWindowPtrs[id] = 0;
    BOTableMetas[id] = BOTableMeta{windowSize, numBuckets, logBlockNum, blockNum, blockSize};
}

void QueryServer::AggTreeAddIndex(string id, uint32_t depth, AggFunc aggFunc) {
    auto it = AggTrees.find(id);
    if (it != AggTrees.end()) {
        DeleteTablePair(it->second);
    }
    AggTreeIndexServer *s1 = new AggTreeIndexServer(id, depth, aggFunc, cores, malicious);
    AggTreeIndexServer *s2 = new AggTreeIndexServer(id, depth, aggFunc, cores, malicious);
    AggTrees[id] = make_pair(s1, s2);
}

void QueryServer::DCFUpdate(string id, uint32_t loc, const uint128_t *data0, const uint128_t *data1) {
    if (loc == APPEND_LOC) {
        loc = DCFTableWindowPtrs[id];
        DCFTableWindowPtrs[id]++;
    }
    setTableColumn(DCFTables[id].first->table, loc, data0, DCFTables[id].first->numBuckets);
    setTableColumn(DCFTables[id].second->table, loc, data1, DCFTables[id].second->numBuckets);
}

void QueryServer::DPFUpdate(string id, uint32_t loc, const uint128_t *data0, const uint128_t *data1) {
    if (loc == APPEND_LOC) {
        loc = DPFTableWindowPtrs[id];
        DPFTableWindowPtrs[id]++;
    }
    setTableColumn(DPFTables[id].first->table, loc, data0, DPFTables[id].first->numBuckets);
    setTableColumn(DPFTables[id].second->table, loc, data1, DPFTables[id].second->numBuckets);
}

void QueryServer::ValListUpdate(string id, uint32_t loc, uint128_t val0, uint128_t val1) {
    if (loc == APPEND_LOC) {
        loc = ValListWindowPtrs[id];
        ValListWindowPtrs[id]++;
    }
    ValLists[id].first[loc] = val0;
    ValLists[id].second[loc] = val1;
}

void QueryServer::OneHotTableUpdate(string id, uint32_t loc, const uint128_t *share0, const uint128_t *share1) {
    if (loc == APPEND_LOC) {
        loc = OneHotTableWindowPtrs[id];
        OneHotTableWindowPtrs[id]++;
    }
    OneHotTables[id].first->oneHotTableUpdateRank(loc, share0);
    OneHotTables[id].second->oneHotTableUpdateRank(loc, share1);
}

void QueryServer::BOTableUpdate(
    string id,
    uint32_t loc,
    const uint128_t *index_share0,
    const uint128_t *index_share1,
    const uint128_t *offset_share0,
    const uint128_t *offset_share1) {
    if (BOTableMetas.count(id) == 0 || BOIndexTables.count(id) == 0 || BOOffsetTables.count(id) == 0) {
        throw std::invalid_argument("BO table is not initialized: " + id);
    }

    if (loc == APPEND_LOC) {
        loc = BOTableWindowPtrs[id];
        BOTableWindowPtrs[id]++;
    }
    if (loc >= BOTableMetas[id].windowSize) {
        throw std::out_of_range("BO update location out of range.");
    }

    BOIndexTables[id].first->updateRank((int)loc, index_share0);
    BOIndexTables[id].second->updateRank((int)loc, index_share1);
    BOOffsetTables[id].first->updateRank((int)loc, offset_share0);
    BOOffsetTables[id].second->updateRank((int)loc, offset_share1);
}

uint128_t **QueryServer::AggTreeAppend1(string id, int *len) {
    uint128_t **pathShares = (uint128_t **)malloc(2 * sizeof(uint128_t *));
    pathShares[0] = AggTrees[id].first->getAppendPath(len);
    pathShares[1] = AggTrees[id].second->getAppendPath(len);
    return pathShares;
}

void QueryServer::AggTreeAppend2(string id, uint32_t idx, uint128_t *new_shares0, uint128_t *new_shares1) {
    AggTrees[id].first->finishAppend(idx, new_shares0);
    AggTrees[id].second->finishAppend(idx, new_shares1);
}

void QueryServer::DCFQuery(uint128_t **res0, uint128_t **res1, string id, const uint8_t *key0, const uint8_t *key1, uint32_t *len) {
    uint64_t gout_bitsize = 125;
    uint128_t one = 1;
    uint128_t group_mod = one << gout_bitsize;

    uint32_t mac_factor = (DCFTables[id].first->malicious)? 2 : 1;

    *res0 = (uint128_t *)malloc(mac_factor * sizeof(uint128_t) * DCFTables[id].first->windowSize);
    *res1 = (uint128_t *)malloc(mac_factor * sizeof(uint128_t) * DCFTables[id].first->windowSize);
    
    DCFTables[id].first->deserialize_key(key0, true);
    DCFTables[id].second->deserialize_key(key1, false);
  
    // true is to run IC and evaluate a double-sided range 
    DCFTables[id].first->ic_eval_dcf_table(*res0, gout_bitsize, true, group_mod, true, 0);
    DCFTables[id].second->ic_eval_dcf_table(*res1, gout_bitsize, true, group_mod, true, 0);
    
    
    *len = mac_factor * DCFTables[id].first->windowSize;
}


void QueryServer::DPFQuery(uint128_t **res0, uint128_t **res1, string id, const uint8_t *key0, const uint8_t *key1, uint32_t *len) {
    uint64_t gout_bitsize = 125;
    uint128_t one = 1;
    uint128_t group_mod = one << gout_bitsize;
    
    uint32_t mac_factor = (DPFTables[id].first->malicious)? 2 : 1;

    *res0 = (uint128_t *)malloc(mac_factor * sizeof(uint128_t) * DPFTables[id].first->windowSize);
    *res1 = (uint128_t *)malloc(mac_factor * sizeof(uint128_t) * DPFTables[id].first->windowSize);
   
    DPFTables[id].first->deserialize_key(key0, true);
    DPFTables[id].second->deserialize_key(key1, false);
   
    DPFTables[id].first->eval_dpf_table(*res0, gout_bitsize, true, group_mod, 0);
    DPFTables[id].second->eval_dpf_table(*res1, gout_bitsize, true, group_mod, 0);
    
    *len = mac_factor * DPFTables[id].first->windowSize;
}

void QueryServer::DCFQueryRSS(uint128_t **res0, uint128_t **res1, string id, const uint8_t *key0, const uint8_t *key1, uint32_t *len) {
    DCFQuery(res0, res1, id, key0, key1, len);
    throw std::invalid_argument("MAC batch check not implemented");
    RSSReshare(res0, res1, 1, *len, nullptr, nullptr);
}

void QueryServer::DPFQueryRSS(uint128_t **res0, uint128_t **res1, string id, const uint8_t *key0, const uint8_t *key1, uint32_t *len) {
    DPFQuery(res0, res1, id, key0, key1, len);
    throw std::invalid_argument("MAC batch check not implemented");
    RSSReshare(res0, res1, 1, *len, nullptr, nullptr);
}

void QueryServer::RSSReshareInnerLoop(uint128_t *res0, uint128_t *res1, uint32_t numSets, uint32_t len, int idx) {
    for (int j = 0; j < len; j++) {
        res1[j] += res0[j];
        res1[j] += GetNextSecretShareOfZero(idx * numSets + len);
    }
}

void QueryServer::RSSReshareGenRandCoeffs(uint128_t *rand_coeff_shares0, uint128_t *rand_coeff_shares1, uint32_t numSets, uint32_t len, int idx) {
    int val_len = malicious ? len / 2 : len;
    for (int j = 0; j < val_len; j++) {
        GetNextSecretShareOfRandCoeff(rand_coeff_shares0 + j, rand_coeff_shares1 + j, numSets * len + idx * numSets + len);
    }
}

void QueryServer::RSSReshare(uint128_t **res0, uint128_t **res1, uint32_t numSets, uint32_t len, uint128_t* lin_comb_acc, uint128_t* lin_comb_mac_acc) {
    INIT_TIMER;
    START_TIMER;
    uint8_t *sendShares = (uint8_t *)malloc(numSets * len * sizeof(uint128_t));
    
    uint128_t *rand_coeff_shares0;
    uint128_t *rand_coeff_shares1;
    if(malicious) {
        rand_coeff_shares0 = (uint128_t *)malloc(numSets * len * sizeof(uint128_t));
        rand_coeff_shares1 = (uint128_t *)malloc(numSets * len * sizeof(uint128_t));
    } 
    int mac_factor = malicious ? 2 : 1;
    int val_len = malicious ? len / 2 : len;

    vector<thread> workers;
    for (int i = 0; i < numSets; i++) {
        workers.push_back(thread(&QueryServer::RSSReshareInnerLoop, this, res0[i], res1[i], numSets, len, i));
        if(malicious){
            workers.push_back(thread(&QueryServer::RSSReshareGenRandCoeffs, this, rand_coeff_shares0 + (i * val_len), rand_coeff_shares1 + (i * val_len), numSets, len, i));
        }
    }
    for (int i = 0; i < numSets; i++) {
        // Inner loop worker
        workers[mac_factor * i].join();
        if(malicious){
            // Rand coeff gen worker
            workers[(mac_factor * i) + 1].join();
        }
        memcpy(sendShares + (i * len * sizeof(uint128_t)), res1[i], len * sizeof(uint128_t));
    }
    AdjustPRFCounter(mac_factor * numSets * len);
    STOP_TIMER("RSS reshare comp");
    //printf("did all memcpies for rss reshare\n");
#ifndef USE_EMP
    MultRequest req;
    MultResponse resp;
    ClientContext ctx;
    req.set_shares((uint8_t *)sendShares, numSets * sizeof(uint128_t) * len);
    multStub->SendMult(&ctx, req, &resp);
    unique_lock<mutex> lk(multLock);
    if (multReceivedShares == NULL) {
        new CallData(*this, service, cq, MULT);
    }
    while (multReceivedShares == NULL) {
        multCV.wait(lk);
    }
    for (int i = 0; i < numSets; i++) {
        memcpy(res0[i], ((uint8_t *)multReceivedShares) + (i * len * sizeof(uint128_t)), len * sizeof(uint128_t));
    }
    free(multReceivedShares);
#else
    // Using EMP NetIO
    cout << "Sending Mult data via EMP " << (numSets * sizeof(uint128_t) * len) << "bytes" << endl;
    uint128_t* multRcvdShares = (uint128_t*)malloc(numSets * sizeof(uint128_t) * len);
    //thread workers[2];
    if(serverID == 0){
        emp_io_downstream->recv_data(multRcvdShares, numSets * sizeof(uint128_t) * len);
        emp_io_upstream->send_data(sendShares, numSets * sizeof(uint128_t) * len);
    }
    else{
        emp_io_upstream->send_data(sendShares, numSets * sizeof(uint128_t) * len);
        emp_io_downstream->recv_data(multRcvdShares, numSets * sizeof(uint128_t) * len);
    }
    cout << "Done EMP part" << endl;

    for (int i = 0; i < numSets; i++) {
        memcpy(res0[i], ((uint8_t *)multRcvdShares) + (i * len * sizeof(uint128_t)), len * sizeof(uint128_t));
    }
    delete[] multRcvdShares;
#endif
    multReceivedShares = NULL;
    orderCV.notify_one();
    
    if(malicious){
        // Optimistically proceed, but store random linear combination
        // in accumulator for client to later check that RSSReshare was
        // error-free.
        AddToBatchMACCheck(res0, res1, rand_coeff_shares0, rand_coeff_shares1, numSets, len, lin_comb_acc, lin_comb_mac_acc);
        delete[] rand_coeff_shares0;
        delete[] rand_coeff_shares1;
    }
}

void QueryServer::AddToBatchMACCheck(uint128_t** x0, uint128_t** x1, uint128_t* coeff0, uint128_t* coeff1, uint32_t numSets, uint32_t len, uint128_t* lin_comb_acc, uint128_t* lin_comb_mac_acc) {
    int val_len = malicious ? len / 2 : len;
    for (int ns = 0; ns < numSets; ns++) {
        for (int i = 0; i < val_len; i++) {
            *lin_comb_acc += (x0[ns][i] * coeff0[(ns * val_len) + i]);
            *lin_comb_acc += (x1[ns][i] * coeff0[(ns * val_len) + i]);
            *lin_comb_acc += (x0[ns][i] * coeff1[(ns * val_len) + i]);
        }
        // MAC
        for (int i = 0; i < val_len; i++) {
            *lin_comb_mac_acc += (x0[ns][val_len + i] * coeff0[(ns * val_len) + i]);
            *lin_comb_mac_acc += (x1[ns][val_len + i] * coeff0[(ns * val_len) + i]);
            *lin_comb_mac_acc += (x0[ns][val_len + i] * coeff1[(ns * val_len) + i]);
        }
    }
}

void QueryServer::AggTreeQuery(string id, const uint8_t *key0, const uint8_t *key1, uint128_t *ret, uint128_t *mac, uint128_t *ret_r, uint128_t *mac_r, int* dd) {
    uint64_t gout_bitsize = 125;
    // *ret = 0;
    // *mac = 0;
    uint128_t one = 1;
    uint128_t group_mod = one << gout_bitsize;
    int depth = AggTrees[id].first->depth;
    *dd = depth;
    uint8_t mac_factor = malicious ? 2 : 1;
    uint8_t lr_factor = 2;
    uint128_t *res1 = (uint128_t *)malloc(lr_factor * mac_factor * (depth + 1) * sizeof(uint128_t));
    uint128_t *res_child1 = (uint128_t *)malloc(lr_factor * mac_factor * (depth + 1) * sizeof(uint128_t));
    uint128_t *res2 = (uint128_t *)malloc(lr_factor * mac_factor * (depth + 1) * sizeof(uint128_t));
    uint128_t *res_child2 = (uint128_t *)malloc(lr_factor * mac_factor * (depth + 1) * sizeof(uint128_t));
    memset(res1, 0, lr_factor * mac_factor * (depth + 1) * sizeof(uint128_t));
    memset(res_child1, 0, lr_factor * mac_factor * (depth + 1) * sizeof(uint128_t));
    memset(res2, 0, lr_factor * mac_factor * (depth + 1) * sizeof(uint128_t));
    memset(res_child2, 0, lr_factor * mac_factor * (depth + 1) * sizeof(uint128_t));

    AggTrees[id].first->deserialize_key(key0, true);
    AggTrees[id].second->deserialize_key(key1, false);

    AggTrees[id].first->eval_agg_tree(res1, res_child1, gout_bitsize, true, group_mod, true);
    AggTrees[id].second->eval_agg_tree(res2, res_child2, gout_bitsize, true, group_mod, true);

    uint128_t* res1_r = res1 + mac_factor*(depth + 1);
    uint128_t* res2_r = res2 + mac_factor*(depth + 1);
    uint128_t* res_child1_r = res_child1 + mac_factor*(depth + 1);
    uint128_t* res_child2_r = res_child2 + mac_factor*(depth + 1);
    res1[0] += res2[0];
    res1_r[0] += res2_r[0];
    if (malicious) {
        res1[depth] += res2[depth];
        res1_r[depth] += res2_r[depth];
    }
    for (int d = 1; d < depth; d++) {
 
        res1[d] -= res_child1[d-1];
        res2[d] -= res_child2[d-1];
        res1_r[d] -= res_child1_r[d-1];
        res2_r[d] -= res_child2_r[d-1];

        res1[d] += res2[d];
        res1_r[d] += res2_r[d];

        if (malicious) {
            res1[d + depth] -= res_child1[d - 1 + depth];
            res2[d + depth] -= res_child2[d - 1 + depth];
            res1_r[d + depth] -= res_child1_r[d - 1 + depth];
            res2_r[d + depth] -= res_child2_r[d - 1 + depth];

            res1[d + depth] += res2[d + depth];
            res1_r[d + depth] += res2_r[d + depth];
        }
    }
    memcpy(ret, res1, ((depth) * sizeof(uint128_t)));
    memcpy(ret_r, res1_r, ((depth) * sizeof(uint128_t)));
    memcpy(mac, ((uint8_t *)res1) + ((depth) * sizeof(uint128_t)), ((depth) * sizeof(uint128_t)));
    memcpy(mac_r, ((uint8_t *)res1_r) + ((depth) * sizeof(uint128_t)), ((depth) * sizeof(uint128_t)));
    /*ret = res1;
    ret_r = res1_r;
    mac = res1 + depth;
    mac_r = res1_r + depth;*/
}

void QueryServer::AndFilters(uint128_t *shares_out0, uint128_t *shares_out1, uint128_t *shares_x0, uint128_t *shares_x1, uint128_t *shares_y0, uint128_t *shares_y1, uint128_t *zero_shares, uint128_t* coeff0, uint128_t* coeff1, int len, uint128_t* lin_comb_acc, uint128_t* lin_comb_mac_acc) {
    Multiply(shares_out0, shares_out1, shares_x0, shares_x1, shares_y0, shares_y1, zero_shares, coeff0, coeff1, len, lin_comb_acc, lin_comb_mac_acc);
}

void QueryServer::OrFilters(uint128_t *shares_out0, uint128_t *shares_out1, uint128_t *shares_x0, uint128_t *shares_x1, uint128_t *shares_y0, uint128_t *shares_y1, uint128_t *zero_shares, uint128_t* coeff0, uint128_t* coeff1, int len, uint128_t* lin_comb_acc, uint128_t* lin_comb_mac_acc) {
    Multiply(shares_out0, shares_out1, shares_x0, shares_x1, shares_y0, shares_y1, zero_shares, coeff0, coeff1, len, lin_comb_acc, lin_comb_mac_acc);
    for (int i = 0; i < len; i++) {
        shares_out0[i] += shares_x0[i] + shares_y0[i];
        shares_out1[i] += shares_x1[i] + shares_y1[i];
    }
}

void QueryServer::Multiply(uint128_t *shares_out0, uint128_t *shares_out1, uint128_t *shares_x0, uint128_t *shares_x1, uint128_t *shares_y0, uint128_t *shares_y1, uint128_t *zero_shares, uint128_t* coeff0, uint128_t* coeff1, int len, uint128_t* lin_comb_acc, uint128_t* lin_comb_mac_acc) {
    int val_len = malicious ? len / 2 : len;
    uint128_t *tmp = (uint128_t *)malloc(2 * val_len * sizeof(uint128_t));
    //INIT_TIMER;
    //START_TIMER;
    for (int i = 0; i < val_len; i++) {
        shares_out1[i] = (shares_x0[i] * shares_y0[i]);
        shares_out1[i] += (shares_x1[i] * shares_y0[i]);
        shares_out1[i] += (shares_x0[i] * shares_y1[i]);
        shares_out1[i] += zero_shares[i];
        tmp[i] = shares_out1[i];
    }
    if (malicious) {
        for (int i = 0; i < val_len; i++) {
            tmp[i + val_len] = (shares_x0[i + val_len] * shares_y0[i]);
            tmp[i + val_len] += (shares_x1[i + val_len] * shares_y0[i]);
            tmp[i + val_len] += (shares_x0[i + val_len] * shares_y1[i]);
            shares_out1[i + val_len] = tmp[i + val_len];
        }
    }
    //STOP_TIMER("Multiplication time FIRST");
    int mac_factor = malicious ? 2 : 1;

#ifndef USE_EMP
    MultRequest req;
    MultResponse resp;
    ClientContext ctx;
    req.set_shares((uint8_t *)tmp, mac_factor * sizeof(uint128_t) * val_len);
    multStub->SendMult(&ctx, req, &resp);
    unique_lock<mutex> lk(multLock);
    while (multReceivedShares == NULL) {
        multCV.wait(lk);
    }
    INIT_TIMER;
    START_TIMER;
    memcpy(shares_out0, multReceivedShares, mac_factor * sizeof(uint128_t) * val_len);
    STOP_TIMER("Multiplication time SECOND");
    free(tmp);
    free(multReceivedShares);

#else
    // assert(false);
    // Using EMP NetIO
    uint128_t* multRcvdShares = (uint128_t*)malloc(mac_factor * sizeof(uint128_t) * val_len);
    thread workers[2];
    if(serverID == 0){
        emp_io_downstream->recv_data(multRcvdShares, mac_factor * sizeof(uint128_t) * val_len);
        emp_io_upstream->send_data(tmp, mac_factor * sizeof(uint128_t) * val_len);
    }
    else{
        emp_io_upstream->send_data(tmp, mac_factor * sizeof(uint128_t) * val_len);
        emp_io_downstream->recv_data(multRcvdShares, mac_factor * sizeof(uint128_t) * val_len);
    }
    memcpy(shares_out0, multRcvdShares, sizeof(uint128_t) * val_len);
    if (malicious) {
        for (int i = 0; i < val_len; i++) {
            shares_out0[i + val_len] = 2 * multRcvdShares[i + val_len] - multRcvdShares[i + 2 * val_len];
            shares_out1[i + val_len] = 2 * tmp[i + val_len] - tmp[i + 2 * val_len];
        }
    }
    //STOP_TIMER("Multiplication time SECOND");
    free(tmp);
    delete[] multRcvdShares;
#endif
    multReceivedShares = NULL;
    orderCV.notify_one();
    if(malicious){
        // Optimistically proceed, but store random linear combination
        // in accumulator for client to later check that RSSReshare was
        // error-free.
        AddToBatchMACCheckFromMult(shares_out0, shares_out1, coeff0, coeff1, len, lin_comb_acc, lin_comb_mac_acc);
    }
}

void QueryServer::AddToBatchMACCheckFromMult(uint128_t* x0, uint128_t* x1, uint128_t* coeff0, uint128_t* coeff1, uint32_t len, uint128_t* lin_comb_acc, uint128_t* lin_comb_mac_acc) {
    int val_len = malicious ? len / 2 : len;
    for (int i = 0; i < val_len; i++) {
        *lin_comb_acc += (x0[i] * coeff0[i]);
        *lin_comb_acc += (x1[i] * coeff0[i]);
        *lin_comb_acc += (x0[i] * coeff1[i]);
    }
    // MAC
    for (int i = 0; i < val_len; i++) {
        *lin_comb_mac_acc += (x0[val_len + i] * coeff0[i]);
        *lin_comb_mac_acc += (x1[val_len + i] * coeff0[i]);
        *lin_comb_mac_acc += (x0[val_len + i] * coeff1[i]);
    }
}

inline uint128_t QueryServer::GetNextSecretShareOfZero(int idx) {
    uint128_t res0 = prfFieldElem(prfKey0, prfCounter + idx);
    uint128_t res1 = prfFieldElem(prfKey1, prfCounter + idx);
    return res1 - res0;
}

inline void QueryServer::GetNextSecretShareOfRandCoeff(uint128_t *rand_coeff_shares0, uint128_t* rand_coeff_shares1, int idx) {
    rand_coeff_shares0[0] = prfFieldElem(prfKey0, prfCounter + idx);
    rand_coeff_shares1[0] = prfFieldElem(prfKey1, prfCounter + idx);
}

void QueryServer::AdjustPRFCounter(int amount) {
    prfCounter += amount;
}

void QueryServer::FinishMultiply(const uint128_t *shares, int len) {
    unique_lock<mutex> lk(multLock);
    //multLock.lock();
    if (multReceivedShares != NULL) {
        new CallData(*this, service, cq, MULT);
    }
    while (multReceivedShares != NULL) {
        orderCV.wait(lk);
    }
    multReceivedShares = (uint128_t *)malloc(len);
    memcpy(multReceivedShares, shares, len);
    multCV.notify_one();
}

void QueryServer::FillZeroSharesPlusRandCoeff(uint128_t *zero_shares, uint128_t *rand_coeff_shares0, uint128_t* rand_coeff_shares1, int start_loc, int prf_idx, int chunk_size, int bgn) {
    for (int i = 0; i < chunk_size; i++) {
        zero_shares[i + start_loc] = GetNextSecretShareOfZero(prf_idx + i);
    }
    if(malicious && rand_coeff_shares0 != nullptr && rand_coeff_shares1 != nullptr){
        // coeffs are same of MAC part and normal part
        // so only half are needed compared to shares 
        // of zero
        for (int i = 0; i < (chunk_size / 2); i++) {
            GetNextSecretShareOfRandCoeff(rand_coeff_shares0 + i + (start_loc/2), rand_coeff_shares1 + i + (start_loc/2), prf_idx + i + bgn);
        }
    }
}

void QueryServer::EvalFilter(uint128_t **filter0, uint128_t **filter1, const CombinedFilter &filterSpec, uint128_t *lin_comb_accumulator, uint128_t *lin_comb_mac_accumulator) {
    *filter0 = NULL;
    *filter1 = NULL;

    // assuming filters all of same type for now
    uint128_t **res0 = (uint128_t **)malloc(sizeof(uint128_t *) * filterSpec.base_filters_size());
    uint128_t **res1 = (uint128_t **)malloc(sizeof(uint128_t *) * filterSpec.base_filters_size());

    *lin_comb_accumulator = 0;
    *lin_comb_mac_accumulator = 0;

    bool is_point = true;
    string baseFilterID;
    uint64_t gout_bitsize = 125;
    uint128_t one = 1;
    uint128_t group_mod = one << gout_bitsize;
    int mac_factor = malicious ? 2 : 1;
    int len;

    for (int i = 0; i < filterSpec.base_filters_size(); i++) {
        BaseFilter baseFilterSpec = filterSpec.base_filters(i);
        baseFilterID = baseFilterSpec.id();
        int windowSize = baseFilterSpec.is_point() ? DPFTables[baseFilterID].first->windowSize : DCFTables[baseFilterID].first->windowSize;
        len = mac_factor * windowSize;
        
        res0[i] = (uint128_t *)malloc(mac_factor * sizeof(uint128_t) * windowSize);
        res1[i] = (uint128_t *)malloc(mac_factor * sizeof(uint128_t) * windowSize);
   
        if (baseFilterSpec.is_point()) {
            DPFTables[baseFilterID].first->deserialize_key((const uint8_t *)baseFilterSpec.key0().c_str(), true);
            DPFTables[baseFilterID].second->deserialize_key((const uint8_t *)baseFilterSpec.key1().c_str(), false);
            is_point = true;
        } else {
            DCFTables[baseFilterID].first->deserialize_key((const uint8_t *)baseFilterSpec.key0().c_str(), true);
            DCFTables[baseFilterID].second->deserialize_key((const uint8_t *)baseFilterSpec.key1().c_str(), false);
            is_point = false;
        }
    }

    if (is_point) {
        thread workers[2];
        workers[0] = thread(&dorydb::DPFTableServer::parallel_eval_dpf_table, DPFTables[baseFilterID].first, res0, gout_bitsize, true, group_mod);
        workers[1] = thread(&dorydb::DPFTableServer::parallel_eval_dpf_table, DPFTables[baseFilterID].second, res1, gout_bitsize, true, group_mod);
        workers[0].join();
        workers[1].join();
    } else {
        thread workers[2];
        workers[0] = thread(&dorydb::DCFTableServer::parallel_ic_eval_dcf_table, DCFTables[baseFilterID].first, res0, gout_bitsize, true, group_mod, true);
        workers[1] = thread(&dorydb::DCFTableServer::parallel_ic_eval_dcf_table, DCFTables[baseFilterID].second, res1, gout_bitsize, true, group_mod, true);
        workers[0].join();
        workers[1].join();
    }
    
    // Convert 3-out-of-3 shares from FSS part to RSS shares 
    RSSReshare(res0, res1, filterSpec.base_filters_size(), len, lin_comb_accumulator, lin_comb_mac_accumulator);

    // Generate some random values for zero sharing and random coeffs (for batch MAC check)
    uint128_t **zero_shares = (uint128_t **)malloc(filterSpec.base_filters_size() * sizeof(uint128_t*));
    uint128_t **rand_coeff_shares0 = (uint128_t **)malloc(filterSpec.base_filters_size() * sizeof(uint128_t*));
    uint128_t **rand_coeff_shares1 = (uint128_t **)malloc(filterSpec.base_filters_size() * sizeof(uint128_t*));
    vector<thread> workers;
    int numChunks = 4;
    int chunkSize = len / numChunks;
    INIT_TIMER;
    START_TIMER;
    for (int i = 0; i < filterSpec.base_filters_size(); i++) {
        zero_shares[i] = (uint128_t *)malloc(sizeof(uint128_t) * len);
        if(malicious) {
            rand_coeff_shares0[i] = (uint128_t *)malloc(sizeof(uint128_t) * len);
            rand_coeff_shares1[i] = (uint128_t *)malloc(sizeof(uint128_t) * len);
        }
        for (int j = 0; j < numChunks; j++) {
           workers.push_back(thread(&QueryServer::FillZeroSharesPlusRandCoeff, 
                this, zero_shares[i], rand_coeff_shares0[i], rand_coeff_shares1[i], 
                j * chunkSize, i * len + j * chunkSize, chunkSize, filterSpec.base_filters_size() * len));
        }
    }
    for (int i = 0; i < workers.size(); i++) {
        workers[i].join();
    }
    STOP_TIMER("precomputed randomness");
    AdjustPRFCounter(mac_factor * filterSpec.base_filters_size() * len);
   

    for (int i = 0; i < filterSpec.base_filters_size(); i++) {
        BaseFilter baseFilterSpec = filterSpec.base_filters(i);
        int len = mac_factor * (baseFilterSpec.is_point() ? DPFTables[baseFilterSpec.id()].first->windowSize : DCFTables[baseFilterSpec.id()].first->windowSize);

        if (*filter1 != NULL) {
            uint128_t *tmp0 = (uint128_t *)malloc(sizeof(uint128_t) * len);
            uint128_t *tmp1 = (uint128_t *)malloc(sizeof(uint128_t) * len);
            memcpy(tmp0, *filter0, sizeof(uint128_t) * len);
            memcpy(tmp1, *filter1, sizeof(uint128_t) * len);
            if (filterSpec.op_is_and()) {
                AndFilters(*filter0, *filter1, tmp0, tmp1, res0[i], res1[i], zero_shares[i], rand_coeff_shares0[i], rand_coeff_shares1[i], len, lin_comb_accumulator, lin_comb_mac_accumulator);
            } else {
                OrFilters(*filter0, *filter1, tmp0, tmp1, res0[i], res1[i], zero_shares[i], rand_coeff_shares0[i], rand_coeff_shares1[i], len, lin_comb_accumulator, lin_comb_mac_accumulator);
            }
            free(tmp0);
            free(tmp1);
            free(res0[i]);
            free(res1[i]);
        } else {
            *filter0 = res0[i];
            *filter1 = res1[i];
        }
    }
    if(malicious) {
        for (int i = 0; i < filterSpec.base_filters_size(); i++) {
            delete[] rand_coeff_shares0[i];
            delete[] rand_coeff_shares1[i];
        }
    }
}

void QueryServer::AggFilterQuery(string aggID, const CombinedFilter &filterSpec, uint128_t *res, uint128_t *mac, uint128_t *lc, uint128_t *lc_mac) {
    uint128_t *filter0;
    uint128_t *filter1;
    EvalFilter(&filter0, &filter1, filterSpec, lc, lc_mac);
    *res = 0;
    *mac = 0;
    int len = ValLists[aggID].first.size();
    for (int i = 0; i < len; i++) {
        // Get 3oo3 shares
        *res += ValLists[aggID].first[i] * filter0[i];
        *res += ValLists[aggID].second[i] * filter0[i];
        *res += ValLists[aggID].first[i] * filter1[i];
        if (malicious) {
            *mac += ValLists[aggID].first[i] * filter0[i + len];
            *mac += ValLists[aggID].second[i] * filter0[i + len];
            *mac += ValLists[aggID].first[i] * filter1[i + len];
        }
    }
    free(filter0);
    free(filter1);
}

void QueryServer::VBAggFilterQuery(string vbAggID, const CombinedVBFilter &filterSpec, uint128_t &res){

    uint128_t *filter_0;
    uint128_t *filter_1;
    // 计算单谓词与one-hot乘积
    VBEvalFilter(&filter_0, &filter_1, filterSpec);

    res = 0;
    int len = ValLists[vbAggID].first.size();
    for (int i = 0; i < len; i++) {
        // res += filter_0[i];
        // cout << i << ": " << filter_0[i] << " " 
        //             << filter_1[i] << " " 
        //             << ValLists[vbAggID].first[i] << " " 
        //             << ValLists[vbAggID].first[i]
        //             << endl;


        res += ValLists[vbAggID].first[i] * filter_0[i];
        res += ValLists[vbAggID].second[i] * filter_0[i];
        res += ValLists[vbAggID].first[i] * filter_1[i];
    }

    
    free(filter_0);
    free(filter_1);
}

void QueryServer::VBEvalFilter(uint128_t ** filter_0, uint128_t ** filter_1, const CombinedVBFilter & filterSpec) {
    *filter_0 = NULL;
    *filter_1 = NULL;

    uint128_t **res_0 = (uint128_t **)malloc(sizeof(uint128_t *) * filterSpec.base_vbfilters_size());
    uint128_t **res_1 = (uint128_t **)malloc(sizeof(uint128_t *) * filterSpec.base_vbfilters_size());
    

    BaseVBFilter baseVBFilter = filterSpec.base_vbfilters(0);
    string baseFilterID = baseVBFilter.id();
    const int num_eval = filterSpec.base_vbfilters_size();

    int windowSize = 0;
    int numBuckets = 0;

    uint128_t** table_1 = nullptr;
    uint128_t** table_2 = nullptr;
    vector<uint128_t*> onehot_rows_1;
    vector<uint128_t*> onehot_rows_2;
    if (OneHotTables.count(baseFilterID) == 0) {
        throw std::runtime_error("VB query requires OneHotTable, but table is not initialized: " + baseFilterID);
    }
    auto &onehot_pair = OneHotTables[baseFilterID];
    windowSize = onehot_pair.first->windowSize;
    numBuckets = onehot_pair.first->numBuckets;
    onehot_rows_1.resize(windowSize);
    onehot_rows_2.resize(windowSize);
    for (int i = 0; i < windowSize; i++) {
        onehot_rows_1[i] = onehot_pair.first->table[i].data();
        onehot_rows_2[i] = onehot_pair.second->table[i].data();
    }
    table_1 = onehot_rows_1.data();
    table_2 = onehot_rows_2.data();

    for(int i = 0; i < num_eval; i++) {
        res_0[i] = (uint128_t *)malloc(windowSize * sizeof(uint128_t));
        res_1[i] = (uint128_t *)malloc(windowSize * sizeof(uint128_t));
    }

    // Predicate evaluation stage (method-0): decode all query shares once,
    // then compute row-wise dot products against oneHotTable shares.
    size_t expected_bytes = (size_t)numBuckets * sizeof(uint128_t);
    std::vector<uint128_t> query_share_0((size_t)num_eval * (size_t)numBuckets);
    std::vector<uint128_t> query_share_1((size_t)num_eval * (size_t)numBuckets);
    for (int i = 0; i < num_eval; i++) {
        const std::string &share0 = filterSpec.base_vbfilters(i).share_0();
        const std::string &share1 = filterSpec.base_vbfilters(i).share_1();
        if (share0.size() != expected_bytes || share1.size() != expected_bytes) {
            throw std::runtime_error("Invalid BaseVBFilter share size.");
        }
        std::memcpy(query_share_0.data() + ((size_t)i * (size_t)numBuckets), share0.data(), expected_bytes);
        std::memcpy(query_share_1.data() + ((size_t)i * (size_t)numBuckets), share1.data(), expected_bytes);
    }

    INIT_TIMER
    START_TIMER
#pragma omp parallel for collapse(2) schedule(static)
    for (int row = 0; row < windowSize; row++) {
        for (int f = 0; f < num_eval; f++) {
            uint128_t *row_0 = table_1[row];
            uint128_t *row_1 = table_2[row];
            const uint128_t *q0 = query_share_0.data() + ((size_t)f * (size_t)numBuckets);
            const uint128_t *q1 = query_share_1.data() + ((size_t)f * (size_t)numBuckets);
            uint128_t acc0 = 0;
            uint128_t acc1 = 0;
            for (int b = 0; b < numBuckets; b++) {
                acc0 += q0[b] * row_0[b];
                acc1 += q1[b] * row_1[b];
            }
            res_0[f][row] = acc0;
            res_1[f][row] = acc1;
        }
    }
    STOP_TIMER("eval_vb_table finish")

    // RSS ReShare
    RSSReshare(res_0, res_1, filterSpec.base_vbfilters_size(), windowSize, nullptr, nullptr);

    // Fast path: single predicate doesn't need AND/OR composition.
    if (filterSpec.base_vbfilters_size() == 1) {
        *filter_0 = res_0[0];
        *filter_1 = res_1[0];
        free(res_0);
        free(res_1);
        return;
    }

    // Generate zero shares for VB filter operations.
    // Keep the same PRF index layout while removing chunked helper-call overhead.
    uint128_t **zero_shares = (uint128_t **)malloc(num_eval * sizeof(uint128_t*));

    {
        INIT_TIMER
        START_TIMER
        // The 0th predicate is the accumulator seed and does not require zero-shares.
        for (int i = 1; i < num_eval; i++) {
            zero_shares[i] = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
        }
#pragma omp parallel for collapse(2) schedule(static)
        for (int i = 1; i < num_eval; i++) {
            for (int pos = 0; pos < windowSize; pos++) {
                zero_shares[i][pos] = GetNextSecretShareOfZero(i * windowSize + pos);
            }
        }

        STOP_TIMER("vbFilter zero share generate")
    }
    AdjustPRFCounter((num_eval - 1) * windowSize);

    // Combine VB filters with AND/OR operations
    *filter_0 = res_0[0];
    *filter_1 = res_1[0];
    uint128_t *tmp0 = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
    uint128_t *tmp1 = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
    for (int i = 1; i < num_eval; i++) {
        memcpy(tmp0, *filter_0, sizeof(uint128_t) * windowSize);
        memcpy(tmp1, *filter_1, sizeof(uint128_t) * windowSize);

        if (filterSpec.is_and()) {
            AndFilters(*filter_0, *filter_1, tmp0, tmp1, res_0[i], res_1[i],
                      zero_shares[i], nullptr, nullptr, windowSize, nullptr, nullptr);
        } else {
            OrFilters(*filter_0, *filter_1, tmp0, tmp1, res_0[i], res_1[i],
                     zero_shares[i], nullptr, nullptr, windowSize, nullptr, nullptr);
        }
        free(res_0[i]);
        free(res_1[i]);
    }
    free(tmp0);
    free(tmp1);

    for (int i = 1; i < num_eval; i++) {
        free(zero_shares[i]); // 释放每个 zero share 内存块
    }
    free(zero_shares); // 释放 zero_shares 指针数组本身
    
    free(res_0); // 释放 res_0 指针数组本身 (注意：res_0[0] 的内容已转移给 filter_0，这里只释放外层数组)
    free(res_1); // 释放 res_1 指针数组本身
}

void QueryServer::BOAggFilterQuery(string boAggID, const CombinedBOFilter &filterSpec, uint128_t &res) {
    uint128_t *filter_0 = nullptr;
    uint128_t *filter_1 = nullptr;
    BOEvalFilter(&filter_0, &filter_1, filterSpec);

    res = 0;
    int len = ValLists[boAggID].first.size();
    for (int i = 0; i < len; i++) {
        res += ValLists[boAggID].first[i] * filter_0[i];
        res += ValLists[boAggID].second[i] * filter_0[i];
        res += ValLists[boAggID].first[i] * filter_1[i];
    }

    free(filter_0);
    free(filter_1);
}

void QueryServer::BOFSSAggFilterQuery(string boAggID, const CombinedBOFSSFilter &filterSpec, uint128_t &res) {
    using clock = std::chrono::high_resolution_clock;
    const bool profile_bofss = (std::getenv("WALDO_PROFILE_BOFSS") != nullptr);
    const auto t_begin = clock::now();

    uint128_t *filter_0 = nullptr;
    uint128_t *filter_1 = nullptr;
    BOFSSEvalFilter(&filter_0, &filter_1, filterSpec);
    const auto t_after_eval = clock::now();

    res = 0;
    int len = ValLists[boAggID].first.size();
    for (int i = 0; i < len; i++) {
        res += ValLists[boAggID].first[i] * filter_0[i];
        res += ValLists[boAggID].second[i] * filter_0[i];
        res += ValLists[boAggID].first[i] * filter_1[i];
    }
    const auto t_end = clock::now();

    if (profile_bofss) {
        const auto eval_us = std::chrono::duration_cast<std::chrono::microseconds>(t_after_eval - t_begin).count();
        const auto agg_us = std::chrono::duration_cast<std::chrono::microseconds>(t_end - t_after_eval).count();
        const auto total_us = std::chrono::duration_cast<std::chrono::microseconds>(t_end - t_begin).count();
        std::cout << "[BOFSS-PROFILE][server " << serverID << "][agg] "
                  << "eval_us=" << eval_us
                  << " agg_us=" << agg_us
                  << " total_us=" << total_us
                  << " window=" << len
                  << std::endl;
    }

    free(filter_0);
    free(filter_1);
}

void QueryServer::BOFSSEvalFilter(uint128_t **filter_0, uint128_t **filter_1, const CombinedBOFSSFilter &filterSpec) {
    using clock = std::chrono::high_resolution_clock;
    const bool profile_bofss = (std::getenv("WALDO_PROFILE_BOFSS") != nullptr);
    const auto t_eval_begin = clock::now();
    uint64_t parse_us = 0;
    uint64_t key_eval_us = 0;
    uint64_t dot_us = 0;
    uint64_t reshare_us = 0;
    uint64_t leaf_and_us = 0;
    uint64_t leaf_or_us = 0;
    uint64_t pred_combine_us = 0;

    *filter_0 = nullptr;
    *filter_1 = nullptr;
    if (filterSpec.base_bofssfilters_size() == 0) {
        throw std::invalid_argument("Empty BOFSS filter.");
    }

    const std::string &table_id = filterSpec.base_bofssfilters(0).id();
    if (BOTableMetas.count(table_id) == 0) {
        throw std::invalid_argument("BO table metadata not found: " + table_id);
    }
    const BOTableMeta &meta = BOTableMetas[table_id];
    const int windowSize = (int)meta.windowSize;
    const int blockNum = (int)meta.blockNum;
    const int blockSize = (int)meta.blockSize;

    struct LeafKeys {
        const BaseBOFSSFilter *block = nullptr;
        bool block_use_vdcf = false;
        const BaseBOFSSFilter *offset = nullptr;
        bool offset_use_vdcf = false;
    };
    std::vector<std::vector<LeafKeys>> preds;
    const auto t_parse_begin = clock::now();
    for (int i = 0; i < filterSpec.base_bofssfilters_size(); i++) {
        const BaseBOFSSFilter &bf = filterSpec.base_bofssfilters(i);
        if (bf.id() != table_id) {
            throw std::invalid_argument("Mixed table ids in CombinedBOFSSFilter.");
        }
        if (bf.key0().empty() || bf.key1().empty()) {
            throw std::invalid_argument("BOFSS key0/key1 cannot be empty.");
        }
        uint32_t pred_idx = bf.predicate_index();
        if (pred_idx >= preds.size()) {
            preds.resize((size_t)pred_idx + 1);
        }
        if (preds[pred_idx].empty()) {
            preds[pred_idx].push_back(LeafKeys{});
        }
        if (bf.domain_type() == dbquery::BOFSS_DOMAIN_BLOCK) {
            if ((int)bf.domain_size() != blockNum) {
                throw std::invalid_argument("BOFSS block primitive domain_size mismatch.");
            }
            const bool use_vdcf = (bf.primitive_type() == dbquery::BOFSS_PRIMITIVE_VDCF);
            bool placed = false;
            for (auto &leaf : preds[pred_idx]) {
                if (leaf.block == nullptr) {
                    leaf.block = &bf;
                    leaf.block_use_vdcf = use_vdcf;
                    placed = true;
                    break;
                }
            }
            if (!placed) {
                LeafKeys leaf{};
                leaf.block = &bf;
                leaf.block_use_vdcf = use_vdcf;
                preds[pred_idx].push_back(leaf);
            }
        } else if (bf.domain_type() == dbquery::BOFSS_DOMAIN_OFFSET) {
            if ((int)bf.domain_size() != blockSize) {
                throw std::invalid_argument("BOFSS offset primitive domain_size mismatch.");
            }
            const bool use_vdcf = (bf.primitive_type() == dbquery::BOFSS_PRIMITIVE_VDCF);
            bool placed = false;
            for (auto &leaf : preds[pred_idx]) {
                if (leaf.offset == nullptr) {
                    leaf.offset = &bf;
                    leaf.offset_use_vdcf = use_vdcf;
                    placed = true;
                    break;
                }
            }
            if (!placed) {
                LeafKeys leaf{};
                leaf.offset = &bf;
                leaf.offset_use_vdcf = use_vdcf;
                preds[pred_idx].push_back(leaf);
            }
        } else {
            throw std::invalid_argument("Unknown BOFSS domain type.");
        }
    }
    if (preds.empty()) {
        throw std::invalid_argument("No valid BOFSS predicates found.");
    }
    for (size_t i = 0; i < preds.size(); i++) {
        if (preds[i].empty()) {
            throw std::invalid_argument("BOFSS predicate index has no leaves.");
        }
        for (const auto &leaf : preds[i]) {
            if (leaf.block == nullptr || leaf.offset == nullptr) {
                throw std::invalid_argument("BOFSS predicate leaf missing block or offset primitive.");
            }
        }
    }
    const int num_pred = (int)preds.size();
    parse_us = std::chrono::duration_cast<std::chrono::microseconds>(clock::now() - t_parse_begin).count();

    std::vector<uint128_t*> block_rows_0(windowSize), block_rows_1(windowSize);
    std::vector<uint128_t*> offset_rows_0(windowSize), offset_rows_1(windowSize);
    for (int row = 0; row < windowSize; row++) {
        block_rows_0[row] = BOIndexTables[table_id].first->table[row].data();
        block_rows_1[row] = BOIndexTables[table_id].second->table[row].data();
        offset_rows_0[row] = BOOffsetTables[table_id].first->table[row].data();
        offset_rows_1[row] = BOOffsetTables[table_id].second->table[row].data();
    }

    uint128_t **pred_res_0 = (uint128_t **)malloc(sizeof(uint128_t *) * num_pred);
    uint128_t **pred_res_1 = (uint128_t **)malloc(sizeof(uint128_t *) * num_pred);

    auto alloc_zero_share_rows = [&](int nrows) {
        uint128_t **z = (uint128_t **)malloc(sizeof(uint128_t *) * nrows);
        for (int i = 0; i < nrows; i++) {
            z[i] = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
        }
#pragma omp parallel for collapse(2) schedule(static)
        for (int i = 0; i < nrows; i++) {
            for (int pos = 0; pos < windowSize; pos++) {
                z[i][pos] = GetNextSecretShareOfZero(i * windowSize + pos);
            }
        }
        AdjustPRFCounter(nrows * windowSize);
        return z;
    };

    for (int p = 0; p < num_pred; p++) {
        const int leaf_cnt = (int)preds[(size_t)p].size();
        std::vector<uint128_t> q_block_0((size_t)leaf_cnt * (size_t)blockNum, 0);
        std::vector<uint128_t> q_block_1((size_t)leaf_cnt * (size_t)blockNum, 0);
        std::vector<uint128_t> q_offset_0((size_t)leaf_cnt * (size_t)blockSize, 0);
        std::vector<uint128_t> q_offset_1((size_t)leaf_cnt * (size_t)blockSize, 0);

        const auto t_key_eval_begin = clock::now();
        for (int f = 0; f < leaf_cnt; f++) {
            std::vector<uint128_t> blk_eval0;
            std::vector<uint128_t> blk_eval1;
            std::vector<uint128_t> off_eval0;
            std::vector<uint128_t> off_eval1;

            if (preds[(size_t)p][(size_t)f].block_use_vdcf) {
                waldo::VDCFKeyPack b0 = waldo::VDCF::DeserializeKeyPack(preds[(size_t)p][(size_t)f].block->key0());
                waldo::VDCFKeyPack b1 = waldo::VDCF::DeserializeKeyPack(preds[(size_t)p][(size_t)f].block->key1());
                if ((int)b0.domain_size != blockNum || (int)b1.domain_size != blockNum ||
                    b0.vec_dim != 1 || b1.vec_dim != 1) {
                    throw std::invalid_argument("BOFSS VDCF block keypack shape mismatch.");
                }
                blk_eval0 = waldo::VDCF::EvalAllFlat(b0, 0);
                blk_eval1 = waldo::VDCF::EvalAllFlat(b1, 1);
            } else {
                waldo::VDPFKeyPack b0 = waldo::VDPF::DeserializeKeyPack(preds[(size_t)p][(size_t)f].block->key0());
                waldo::VDPFKeyPack b1 = waldo::VDPF::DeserializeKeyPack(preds[(size_t)p][(size_t)f].block->key1());
                if ((int)b0.domain_size != blockNum || (int)b1.domain_size != blockNum ||
                    b0.vec_dim != 1 || b1.vec_dim != 1) {
                    throw std::invalid_argument("BOFSS VDPF block keypack shape mismatch.");
                }
                blk_eval0 = waldo::VDPF::EvalAllFlat(b0, 0);
                blk_eval1 = waldo::VDPF::EvalAllFlat(b1, 1);
            }
            for (int x = 0; x < blockNum; x++) {
                q_block_0[(size_t)f * (size_t)blockNum + (size_t)x] = blk_eval0[(size_t)x];
                q_block_1[(size_t)f * (size_t)blockNum + (size_t)x] = blk_eval1[(size_t)x];
            }

            if (preds[(size_t)p][(size_t)f].offset_use_vdcf) {
                waldo::VDCFKeyPack o0 = waldo::VDCF::DeserializeKeyPack(preds[(size_t)p][(size_t)f].offset->key0());
                waldo::VDCFKeyPack o1 = waldo::VDCF::DeserializeKeyPack(preds[(size_t)p][(size_t)f].offset->key1());
                if ((int)o0.domain_size != blockSize || (int)o1.domain_size != blockSize ||
                    o0.vec_dim != 1 || o1.vec_dim != 1) {
                    throw std::invalid_argument("BOFSS VDCF offset keypack shape mismatch.");
                }
                off_eval0 = waldo::VDCF::EvalAllFlat(o0, 0);
                off_eval1 = waldo::VDCF::EvalAllFlat(o1, 1);
            } else {
                waldo::VDPFKeyPack o0 = waldo::VDPF::DeserializeKeyPack(preds[(size_t)p][(size_t)f].offset->key0());
                waldo::VDPFKeyPack o1 = waldo::VDPF::DeserializeKeyPack(preds[(size_t)p][(size_t)f].offset->key1());
                if ((int)o0.domain_size != blockSize || (int)o1.domain_size != blockSize ||
                    o0.vec_dim != 1 || o1.vec_dim != 1) {
                    throw std::invalid_argument("BOFSS VDPF offset keypack shape mismatch.");
                }
                off_eval0 = waldo::VDPF::EvalAllFlat(o0, 0);
                off_eval1 = waldo::VDPF::EvalAllFlat(o1, 1);
            }
            for (int x = 0; x < blockSize; x++) {
                q_offset_0[(size_t)f * (size_t)blockSize + (size_t)x] = off_eval0[(size_t)x];
                q_offset_1[(size_t)f * (size_t)blockSize + (size_t)x] = off_eval1[(size_t)x];
            }
        }
        key_eval_us += std::chrono::duration_cast<std::chrono::microseconds>(clock::now() - t_key_eval_begin).count();

        uint128_t **block_res_0 = (uint128_t **)malloc(sizeof(uint128_t *) * leaf_cnt);
        uint128_t **block_res_1 = (uint128_t **)malloc(sizeof(uint128_t *) * leaf_cnt);
        uint128_t **offset_res_0 = (uint128_t **)malloc(sizeof(uint128_t *) * leaf_cnt);
        uint128_t **offset_res_1 = (uint128_t **)malloc(sizeof(uint128_t *) * leaf_cnt);
        for (int i = 0; i < leaf_cnt; i++) {
            block_res_0[i] = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
            block_res_1[i] = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
            offset_res_0[i] = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
            offset_res_1[i] = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
        }

        const auto t_dot_begin = clock::now();
#pragma omp parallel for collapse(2) schedule(static)
        for (int row = 0; row < windowSize; row++) {
            for (int f = 0; f < leaf_cnt; f++) {
                const uint128_t *qb0 = q_block_0.data() + ((size_t)f * (size_t)blockNum);
                const uint128_t *qb1 = q_block_1.data() + ((size_t)f * (size_t)blockNum);
                const uint128_t *qo0 = q_offset_0.data() + ((size_t)f * (size_t)blockSize);
                const uint128_t *qo1 = q_offset_1.data() + ((size_t)f * (size_t)blockSize);
                uint128_t bacc0 = 0, bacc1 = 0, oacc0 = 0, oacc1 = 0;
                for (int j = 0; j < blockNum; j++) {
                    bacc0 += qb0[j] * block_rows_0[row][j];
                    bacc1 += qb1[j] * block_rows_1[row][j];
                }
                for (int j = 0; j < blockSize; j++) {
                    oacc0 += qo0[j] * offset_rows_0[row][j];
                    oacc1 += qo1[j] * offset_rows_1[row][j];
                }
                block_res_0[f][row] = bacc0;
                block_res_1[f][row] = bacc1;
                offset_res_0[f][row] = oacc0;
                offset_res_1[f][row] = oacc1;
            }
        }
        dot_us += std::chrono::duration_cast<std::chrono::microseconds>(clock::now() - t_dot_begin).count();

        const auto t_reshare_begin = clock::now();
        {
            const int merged_sets = leaf_cnt * 2;
            uint128_t **merged_0 = (uint128_t **)malloc(sizeof(uint128_t *) * merged_sets);
            uint128_t **merged_1 = (uint128_t **)malloc(sizeof(uint128_t *) * merged_sets);
            for (int i = 0; i < leaf_cnt; i++) {
                merged_0[i] = block_res_0[i];
                merged_1[i] = block_res_1[i];
                merged_0[leaf_cnt + i] = offset_res_0[i];
                merged_1[leaf_cnt + i] = offset_res_1[i];
            }
            RSSReshare(merged_0, merged_1, merged_sets, windowSize, nullptr, nullptr);
            free(merged_0);
            free(merged_1);
        }
        reshare_us += std::chrono::duration_cast<std::chrono::microseconds>(clock::now() - t_reshare_begin).count();

        uint128_t **leaf_res_0 = (uint128_t **)malloc(sizeof(uint128_t *) * leaf_cnt);
        uint128_t **leaf_res_1 = (uint128_t **)malloc(sizeof(uint128_t *) * leaf_cnt);
        uint128_t **zero_shares = alloc_zero_share_rows(leaf_cnt);
        const auto t_leaf_and_begin = clock::now();
        for (int i = 0; i < leaf_cnt; i++) {
            leaf_res_0[i] = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
            leaf_res_1[i] = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
            AndFilters(leaf_res_0[i], leaf_res_1[i],
                       block_res_0[i], block_res_1[i],
                       offset_res_0[i], offset_res_1[i],
                       zero_shares[i], nullptr, nullptr, windowSize, nullptr, nullptr);
            free(block_res_0[i]); free(block_res_1[i]);
            free(offset_res_0[i]); free(offset_res_1[i]);
            free(zero_shares[i]);
        }
        leaf_and_us += std::chrono::duration_cast<std::chrono::microseconds>(clock::now() - t_leaf_and_begin).count();
        free(block_res_0); free(block_res_1);
        free(offset_res_0); free(offset_res_1);
        free(zero_shares);

        // OR within predicate: union of allowed leaves.
        pred_res_0[p] = leaf_res_0[0];
        pred_res_1[p] = leaf_res_1[0];
        if (leaf_cnt > 1) {
            const auto t_leaf_or_begin = clock::now();
            uint128_t **comb_zero = alloc_zero_share_rows(leaf_cnt - 1);
            uint128_t *tmp0 = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
            uint128_t *tmp1 = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
            for (int i = 1; i < leaf_cnt; i++) {
                memcpy(tmp0, pred_res_0[p], sizeof(uint128_t) * windowSize);
                memcpy(tmp1, pred_res_1[p], sizeof(uint128_t) * windowSize);
                OrFilters(pred_res_0[p], pred_res_1[p], tmp0, tmp1,
                          leaf_res_0[i], leaf_res_1[i],
                          comb_zero[i - 1], nullptr, nullptr, windowSize, nullptr, nullptr);
                free(leaf_res_0[i]);
                free(leaf_res_1[i]);
                free(comb_zero[i - 1]);
            }
            free(tmp0);
            free(tmp1);
            free(comb_zero);
            leaf_or_us += std::chrono::duration_cast<std::chrono::microseconds>(clock::now() - t_leaf_or_begin).count();
        }
        free(leaf_res_0);
        free(leaf_res_1);
    }

    if (num_pred == 1) {
        *filter_0 = pred_res_0[0];
        *filter_1 = pred_res_1[0];
        if (profile_bofss) {
            const auto eval_total_us = std::chrono::duration_cast<std::chrono::microseconds>(clock::now() - t_eval_begin).count();
            std::cout << "[BOFSS-PROFILE][server " << serverID << "][eval] "
                      << "num_pred=" << num_pred
                      << " parse_us=" << parse_us
                      << " key_eval_us=" << key_eval_us
                      << " dot_us=" << dot_us
                      << " reshare_us=" << reshare_us
                      << " leaf_and_us=" << leaf_and_us
                      << " leaf_or_us=" << leaf_or_us
                      << " pred_combine_us=0"
                      << " total_us=" << eval_total_us
                      << std::endl;
        }
        free(pred_res_0);
        free(pred_res_1);
        return;
    }

    *filter_0 = pred_res_0[0];
    *filter_1 = pred_res_1[0];
    const auto t_pred_combine_begin = clock::now();
    uint128_t **comb_zero = alloc_zero_share_rows(num_pred - 1);
    uint128_t *tmp0 = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
    uint128_t *tmp1 = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
    for (int i = 1; i < num_pred; i++) {
        memcpy(tmp0, *filter_0, sizeof(uint128_t) * windowSize);
        memcpy(tmp1, *filter_1, sizeof(uint128_t) * windowSize);
        if (filterSpec.is_and()) {
            AndFilters(*filter_0, *filter_1, tmp0, tmp1,
                       pred_res_0[i], pred_res_1[i],
                       comb_zero[i - 1], nullptr, nullptr, windowSize, nullptr, nullptr);
        } else {
            OrFilters(*filter_0, *filter_1, tmp0, tmp1,
                      pred_res_0[i], pred_res_1[i],
                      comb_zero[i - 1], nullptr, nullptr, windowSize, nullptr, nullptr);
        }
        free(pred_res_0[i]);
        free(pred_res_1[i]);
        free(comb_zero[i - 1]);
    }
    free(tmp0);
    free(tmp1);
    free(comb_zero);
    free(pred_res_0);
    free(pred_res_1);
    pred_combine_us = std::chrono::duration_cast<std::chrono::microseconds>(clock::now() - t_pred_combine_begin).count();

    if (profile_bofss) {
        const auto eval_total_us = std::chrono::duration_cast<std::chrono::microseconds>(clock::now() - t_eval_begin).count();
        std::cout << "[BOFSS-PROFILE][server " << serverID << "][eval] "
                  << "num_pred=" << num_pred
                  << " parse_us=" << parse_us
                  << " key_eval_us=" << key_eval_us
                  << " dot_us=" << dot_us
                  << " reshare_us=" << reshare_us
                  << " leaf_and_us=" << leaf_and_us
                  << " leaf_or_us=" << leaf_or_us
                  << " pred_combine_us=" << pred_combine_us
                  << " total_us=" << eval_total_us
                  << std::endl;
    }
}

void QueryServer::VBFSSAggFilterQuery(string vbAggID, const CombinedVBFSSFilter &filterSpec, uint128_t &res) {
    if (filterSpec.base_vbfssfilters_size() <= 0) {
        throw std::invalid_argument("VBFSS filter is empty.");
    }

    const int num_leaf = filterSpec.base_vbfssfilters_size();
    const BaseVBFSSFilter &base = filterSpec.base_vbfssfilters(0);
    const string table_id = base.id();
    if (OneHotTables.count(table_id) == 0) {
        throw std::runtime_error("VBFSS requires OneHotTable, but table is not initialized: " + table_id);
    }

    auto &onehot_pair = OneHotTables[table_id];
    const int windowSize = (int)onehot_pair.first->windowSize;
    const int numBuckets = (int)onehot_pair.first->numBuckets;
    const int blockNum = (int)base.domain_size();
    const int blockSize = (int)base.vec_dim();
    if (blockNum <= 0 || blockSize <= 0 || blockNum * blockSize != numBuckets) {
        throw std::invalid_argument("Invalid VBFSS domain/vec_dim against OneHot table.");
    }

    // Group leaves by predicate index so one predicate can be represented by multiple vDPF instances.
    uint32_t max_pred_idx = 0;
    for (int f = 0; f < num_leaf; f++) {
        max_pred_idx = std::max(max_pred_idx, filterSpec.base_vbfssfilters(f).predicate_index());
    }
    const int num_pred = (int)max_pred_idx + 1;
    std::vector<std::vector<int>> pred_to_leaf((size_t)num_pred);
    for (int f = 0; f < num_leaf; f++) {
        const BaseVBFSSFilter &bf = filterSpec.base_vbfssfilters(f);
        pred_to_leaf[(size_t)bf.predicate_index()].push_back(f);
    }
    for (int p = 0; p < num_pred; p++) {
        if (pred_to_leaf[(size_t)p].empty()) {
            throw std::invalid_argument("VBFSS predicate index has no leaves.");
        }
    }

    // Decode local vDPF keys into per-leaf block vectors once.
    std::vector<uint128_t> q0((size_t)num_leaf * (size_t)blockNum * (size_t)blockSize, 0);
    std::vector<uint128_t> q1((size_t)num_leaf * (size_t)blockNum * (size_t)blockSize, 0);
    for (int f = 0; f < num_leaf; f++) {
        const BaseVBFSSFilter &bf = filterSpec.base_vbfssfilters(f);
        if (bf.id() != table_id) {
            throw std::invalid_argument("Mixed table ids in CombinedVBFSSFilter.");
        }
        if ((int)bf.domain_size() != blockNum || (int)bf.vec_dim() != blockSize) {
            throw std::invalid_argument("Inconsistent VBFSS domain/vec_dim among predicates.");
        }
        if (bf.key0().empty() || bf.key1().empty()) {
            throw std::invalid_argument("VBFSS key0/key1 cannot be empty.");
        }
        std::vector<uint128_t> vecs0;
        std::vector<uint128_t> vecs1;
        if (bf.leaf_type() == dbquery::VBFSS_LEAF_VDCF) {
            waldo::VDCFKeyPack key_slot0 = waldo::VDCF::DeserializeKeyPack(bf.key0());
            waldo::VDCFKeyPack key_slot1 = waldo::VDCF::DeserializeKeyPack(bf.key1());
            if ((int)key_slot0.domain_size != blockNum || (int)key_slot0.vec_dim != blockSize ||
                (int)key_slot1.domain_size != blockNum || (int)key_slot1.vec_dim != blockSize) {
                throw std::invalid_argument("VDCF keypack shape mismatch.");
            }
            vecs0 = waldo::VDCF::EvalAllFlat(key_slot0, 0);
            vecs1 = waldo::VDCF::EvalAllFlat(key_slot1, 1);
        } else {
            waldo::VDPFKeyPack key_slot0 = waldo::VDPF::DeserializeKeyPack(bf.key0());
            waldo::VDPFKeyPack key_slot1 = waldo::VDPF::DeserializeKeyPack(bf.key1());
            if ((int)key_slot0.domain_size != blockNum || (int)key_slot0.vec_dim != blockSize ||
                (int)key_slot1.domain_size != blockNum || (int)key_slot1.vec_dim != blockSize) {
                throw std::invalid_argument("VDPF keypack shape mismatch.");
            }
            vecs0 = waldo::VDPF::EvalAllFlat(key_slot0, 0);
            vecs1 = waldo::VDPF::EvalAllFlat(key_slot1, 1);
        }
        for (int b = 0; b < blockNum; b++) {
            std::memcpy(
                q0.data() + (((size_t)f * (size_t)blockNum + (size_t)b) * (size_t)blockSize),
                vecs0.data() + ((size_t)b * (size_t)blockSize),
                sizeof(uint128_t) * (size_t)blockSize);
            std::memcpy(
                q1.data() + (((size_t)f * (size_t)blockNum + (size_t)b) * (size_t)blockSize),
                vecs1.data() + ((size_t)b * (size_t)blockSize),
                sizeof(uint128_t) * (size_t)blockSize);
        }
    }

    uint128_t **leaf_res_0 = (uint128_t **)malloc(sizeof(uint128_t *) * num_leaf);
    uint128_t **leaf_res_1 = (uint128_t **)malloc(sizeof(uint128_t *) * num_leaf);
    for (int i = 0; i < num_leaf; i++) {
        leaf_res_0[i] = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
        leaf_res_1[i] = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
    }

#pragma omp parallel for collapse(2) schedule(static)
    for (int row = 0; row < windowSize; row++) {
        for (int f = 0; f < num_leaf; f++) {
            uint128_t acc0 = 0;
            uint128_t acc1 = 0;
            const uint128_t *row0 = onehot_pair.first->table[row].data();
            const uint128_t *row1 = onehot_pair.second->table[row].data();
            for (int b = 0; b < blockNum; b++) {
                const uint128_t *qb0 = q0.data() + (((size_t)f * (size_t)blockNum + (size_t)b) * (size_t)blockSize);
                const uint128_t *qb1 = q1.data() + (((size_t)f * (size_t)blockNum + (size_t)b) * (size_t)blockSize);
                const uint128_t *tb0 = row0 + ((size_t)b * (size_t)blockSize);
                const uint128_t *tb1 = row1 + ((size_t)b * (size_t)blockSize);
                for (int j = 0; j < blockSize; j++) {
                    acc0 += qb0[j] * tb0[j];
                    acc1 += qb1[j] * tb1[j];
                }
            }
            leaf_res_0[f][row] = acc0;
            leaf_res_1[f][row] = acc1;
        }
    }

    // Combine leaves within each predicate by addition (disjoint block supports for VB instances).
    uint128_t **pred_res_0 = (uint128_t **)malloc(sizeof(uint128_t *) * num_pred);
    uint128_t **pred_res_1 = (uint128_t **)malloc(sizeof(uint128_t *) * num_pred);
    for (int p = 0; p < num_pred; p++) {
        pred_res_0[p] = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
        pred_res_1[p] = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
    }
#pragma omp parallel for collapse(2) schedule(static)
    for (int p = 0; p < num_pred; p++) {
        for (int row = 0; row < windowSize; row++) {
            uint128_t s0 = 0;
            uint128_t s1 = 0;
            for (int leaf_idx : pred_to_leaf[(size_t)p]) {
                s0 += leaf_res_0[leaf_idx][row];
                s1 += leaf_res_1[leaf_idx][row];
            }
            pred_res_0[p][row] = s0;
            pred_res_1[p][row] = s1;
        }
    }
    for (int i = 0; i < num_leaf; i++) {
        free(leaf_res_0[i]);
        free(leaf_res_1[i]);
    }
    free(leaf_res_0);
    free(leaf_res_1);

    RSSReshare(pred_res_0, pred_res_1, num_pred, windowSize, nullptr, nullptr);

    uint128_t *filter_0 = nullptr;
    uint128_t *filter_1 = nullptr;
    if (num_pred == 1) {
        filter_0 = pred_res_0[0];
        filter_1 = pred_res_1[0];
        free(pred_res_0);
        free(pred_res_1);
    } else {
        uint128_t **zero_shares = (uint128_t **)malloc(num_pred * sizeof(uint128_t *));
        for (int i = 1; i < num_pred; i++) {
            zero_shares[i] = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
        }
#pragma omp parallel for collapse(2) schedule(static)
        for (int i = 1; i < num_pred; i++) {
            for (int pos = 0; pos < windowSize; pos++) {
                zero_shares[i][pos] = GetNextSecretShareOfZero(i * windowSize + pos);
            }
        }
        AdjustPRFCounter((num_pred - 1) * windowSize);

        filter_0 = pred_res_0[0];
        filter_1 = pred_res_1[0];
        uint128_t *tmp0 = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
        uint128_t *tmp1 = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
        for (int i = 1; i < num_pred; i++) {
            memcpy(tmp0, filter_0, sizeof(uint128_t) * windowSize);
            memcpy(tmp1, filter_1, sizeof(uint128_t) * windowSize);
            if (filterSpec.is_and()) {
                AndFilters(filter_0, filter_1, tmp0, tmp1, pred_res_0[i], pred_res_1[i],
                           zero_shares[i], nullptr, nullptr, windowSize, nullptr, nullptr);
            } else {
                OrFilters(filter_0, filter_1, tmp0, tmp1, pred_res_0[i], pred_res_1[i],
                          zero_shares[i], nullptr, nullptr, windowSize, nullptr, nullptr);
            }
            free(pred_res_0[i]);
            free(pred_res_1[i]);
        }
        free(tmp0);
        free(tmp1);
        for (int i = 1; i < num_pred; i++) {
            free(zero_shares[i]);
        }
        free(zero_shares);
        free(pred_res_0);
        free(pred_res_1);
    }

    res = 0;
    int len = ValLists[vbAggID].first.size();
    for (int i = 0; i < len; i++) {
        res += ValLists[vbAggID].first[i] * filter_0[i];
        res += ValLists[vbAggID].second[i] * filter_0[i];
        res += ValLists[vbAggID].first[i] * filter_1[i];
    }
    free(filter_0);
    free(filter_1);
}

void QueryServer::BOEvalFilter(uint128_t **filter_0, uint128_t **filter_1, const CombinedBOFilter &filterSpec) {
    *filter_0 = nullptr;
    *filter_1 = nullptr;
    BOCheckFilter(filterSpec);

    std::vector<std::vector<const BaseBOFilter *>> preds;
    preds.reserve((size_t)filterSpec.base_bofilters_size());
    for (int i = 0; i < filterSpec.base_bofilters_size(); i++) {
        const BaseBOFilter &bf = filterSpec.base_bofilters(i);
        const uint32_t pred_idx = bf.predicate_index();
        if (pred_idx >= preds.size()) {
            preds.resize((size_t)pred_idx + 1);
        }
        preds[(size_t)pred_idx].push_back(&bf);
    }
    for (size_t i = 0; i < preds.size(); i++) {
        if (preds[i].empty()) {
            throw std::invalid_argument("BO predicate index has no leaves.");
        }
    }
    const int num_pred = (int)preds.size();
    int num_eval = 0;
    for (const auto &v : preds) {
        num_eval += (int)v.size();
    }

    const std::string table_id = filterSpec.base_bofilters(0).id();
    const BOTableMeta &meta = BOTableMetas[table_id];
    const int windowSize = (int)meta.windowSize;
    const int blockNum = (int)meta.blockNum;
    const int blockSize = (int)meta.blockSize;

    std::vector<uint128_t*> block_rows_0(windowSize), block_rows_1(windowSize);
    std::vector<uint128_t*> offset_rows_0(windowSize), offset_rows_1(windowSize);
    for (int row = 0; row < windowSize; row++) {
        block_rows_0[row] = BOIndexTables[table_id].first->table[row].data();
        block_rows_1[row] = BOIndexTables[table_id].second->table[row].data();
        offset_rows_0[row] = BOOffsetTables[table_id].first->table[row].data();
        offset_rows_1[row] = BOOffsetTables[table_id].second->table[row].data();
    }

    size_t block_bytes = (size_t)blockNum * sizeof(uint128_t);
    size_t offset_bytes = (size_t)blockSize * sizeof(uint128_t);
    std::vector<uint128_t> q_block_0((size_t)num_eval * (size_t)blockNum);
    std::vector<uint128_t> q_block_1((size_t)num_eval * (size_t)blockNum);
    std::vector<uint128_t> q_offset_0((size_t)num_eval * (size_t)blockSize);
    std::vector<uint128_t> q_offset_1((size_t)num_eval * (size_t)blockSize);

    std::vector<int> eval_pred((size_t)num_eval, 0);
    std::vector<int> eval_leaf((size_t)num_eval, 0);
    int eval_idx = 0;
    for (int p = 0; p < num_pred; p++) {
        for (int lf = 0; lf < (int)preds[(size_t)p].size(); lf++, eval_idx++) {
            eval_pred[(size_t)eval_idx] = p;
            eval_leaf[(size_t)eval_idx] = lf;
        }
    }

    for (int i = 0; i < num_eval; i++) {
        const BaseBOFilter &bf = *preds[(size_t)eval_pred[(size_t)i]][(size_t)eval_leaf[(size_t)i]];
        std::memcpy(q_block_0.data() + ((size_t)i * (size_t)blockNum), bf.block_share_0().data(), block_bytes);
        std::memcpy(q_block_1.data() + ((size_t)i * (size_t)blockNum), bf.block_share_1().data(), block_bytes);
        std::memcpy(q_offset_0.data() + ((size_t)i * (size_t)blockSize), bf.offset_share_0().data(), offset_bytes);
        std::memcpy(q_offset_1.data() + ((size_t)i * (size_t)blockSize), bf.offset_share_1().data(), offset_bytes);
    }

    uint128_t **block_res_0 = (uint128_t **)malloc(sizeof(uint128_t *) * num_eval);
    uint128_t **block_res_1 = (uint128_t **)malloc(sizeof(uint128_t *) * num_eval);
    uint128_t **offset_res_0 = (uint128_t **)malloc(sizeof(uint128_t *) * num_eval);
    uint128_t **offset_res_1 = (uint128_t **)malloc(sizeof(uint128_t *) * num_eval);
    for (int i = 0; i < num_eval; i++) {
        block_res_0[i] = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
        block_res_1[i] = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
        offset_res_0[i] = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
        offset_res_1[i] = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
    }

#pragma omp parallel for collapse(2) schedule(static)
    for (int row = 0; row < windowSize; row++) {
        for (int f = 0; f < num_eval; f++) {
            const uint128_t *qb0 = q_block_0.data() + ((size_t)f * (size_t)blockNum);
            const uint128_t *qb1 = q_block_1.data() + ((size_t)f * (size_t)blockNum);
            const uint128_t *qo0 = q_offset_0.data() + ((size_t)f * (size_t)blockSize);
            const uint128_t *qo1 = q_offset_1.data() + ((size_t)f * (size_t)blockSize);
            uint128_t bacc0 = 0, bacc1 = 0, oacc0 = 0, oacc1 = 0;

            for (int j = 0; j < blockNum; j++) {
                bacc0 += qb0[j] * block_rows_0[row][j];
                bacc1 += qb1[j] * block_rows_1[row][j];
            }
            for (int j = 0; j < blockSize; j++) {
                oacc0 += qo0[j] * offset_rows_0[row][j];
                oacc1 += qo1[j] * offset_rows_1[row][j];
            }
            block_res_0[f][row] = bacc0;
            block_res_1[f][row] = bacc1;
            offset_res_0[f][row] = oacc0;
            offset_res_1[f][row] = oacc1;
        }
    }

    // Convert primitive outputs from 3oo3 to RSS first.
    // Keep RSSReshare implementation unchanged; only fuse caller-side invocations.
    {
        const int merged_sets = num_eval * 2;
        uint128_t **merged_0 = (uint128_t **)malloc(sizeof(uint128_t *) * merged_sets);
        uint128_t **merged_1 = (uint128_t **)malloc(sizeof(uint128_t *) * merged_sets);
        for (int i = 0; i < num_eval; i++) {
            merged_0[i] = block_res_0[i];
            merged_1[i] = block_res_1[i];
            merged_0[num_eval + i] = offset_res_0[i];
            merged_1[num_eval + i] = offset_res_1[i];
        }
        RSSReshare(merged_0, merged_1, merged_sets, windowSize, nullptr, nullptr);
        free(merged_0);
        free(merged_1);
    }

    // For each leaf: (block condition) AND (offset condition)
    uint128_t **leaf_res_0 = (uint128_t **)malloc(sizeof(uint128_t *) * num_eval);
    uint128_t **leaf_res_1 = (uint128_t **)malloc(sizeof(uint128_t *) * num_eval);
    uint128_t **zero_shares = (uint128_t **)malloc(sizeof(uint128_t *) * num_eval);
    for (int i = 0; i < num_eval; i++) {
        leaf_res_0[i] = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
        leaf_res_1[i] = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
        zero_shares[i] = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
    }
#pragma omp parallel for collapse(2) schedule(static)
    for (int i = 0; i < num_eval; i++) {
        for (int pos = 0; pos < windowSize; pos++) {
            zero_shares[i][pos] = GetNextSecretShareOfZero(i * windowSize + pos);
        }
    }
    AdjustPRFCounter(num_eval * windowSize);

    for (int i = 0; i < num_eval; i++) {
        AndFilters(leaf_res_0[i], leaf_res_1[i],
                   block_res_0[i], block_res_1[i],
                   offset_res_0[i], offset_res_1[i],
                   zero_shares[i], nullptr, nullptr, windowSize, nullptr, nullptr);
        free(block_res_0[i]); free(block_res_1[i]);
        free(offset_res_0[i]); free(offset_res_1[i]);
        free(zero_shares[i]);
    }
    free(block_res_0); free(block_res_1);
    free(offset_res_0); free(offset_res_1);
    free(zero_shares);

    std::vector<uint128_t *> pred_res_0((size_t)num_pred, nullptr);
    std::vector<uint128_t *> pred_res_1((size_t)num_pred, nullptr);

    auto alloc_zero_rows = [&](int nrows) {
        uint128_t **z = (uint128_t **)malloc(sizeof(uint128_t *) * nrows);
        for (int i = 0; i < nrows; i++) {
            z[i] = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
        }
#pragma omp parallel for collapse(2) schedule(static)
        for (int i = 0; i < nrows; i++) {
            for (int pos = 0; pos < windowSize; pos++) {
                z[i][pos] = GetNextSecretShareOfZero(i * windowSize + pos);
            }
        }
        AdjustPRFCounter(nrows * windowSize);
        return z;
    };

    eval_idx = 0;
    for (int p = 0; p < num_pred; p++) {
        const int leaf_cnt = (int)preds[(size_t)p].size();
        pred_res_0[(size_t)p] = leaf_res_0[eval_idx];
        pred_res_1[(size_t)p] = leaf_res_1[eval_idx];
        eval_idx++;
        if (leaf_cnt > 1) {
            uint128_t **comb_zero = alloc_zero_rows(leaf_cnt - 1);
            uint128_t *tmp0 = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
            uint128_t *tmp1 = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
            for (int lf = 1; lf < leaf_cnt; lf++, eval_idx++) {
                memcpy(tmp0, pred_res_0[(size_t)p], sizeof(uint128_t) * windowSize);
                memcpy(tmp1, pred_res_1[(size_t)p], sizeof(uint128_t) * windowSize);
                OrFilters(pred_res_0[(size_t)p], pred_res_1[(size_t)p], tmp0, tmp1,
                          leaf_res_0[eval_idx], leaf_res_1[eval_idx],
                          comb_zero[lf - 1], nullptr, nullptr, windowSize, nullptr, nullptr);
                free(leaf_res_0[eval_idx]);
                free(leaf_res_1[eval_idx]);
                free(comb_zero[lf - 1]);
            }
            free(tmp0);
            free(tmp1);
            free(comb_zero);
        }
    }
    free(leaf_res_0);
    free(leaf_res_1);

    if (num_pred == 1) {
        *filter_0 = pred_res_0[0];
        *filter_1 = pred_res_1[0];
        return;
    }

    *filter_0 = pred_res_0[0];
    *filter_1 = pred_res_1[0];
    uint128_t **comb_zero = alloc_zero_rows(num_pred - 1);
    uint128_t *tmp0 = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
    uint128_t *tmp1 = (uint128_t *)malloc(sizeof(uint128_t) * windowSize);
    for (int p = 1; p < num_pred; p++) {
        memcpy(tmp0, *filter_0, sizeof(uint128_t) * windowSize);
        memcpy(tmp1, *filter_1, sizeof(uint128_t) * windowSize);
        if (filterSpec.is_and()) {
            AndFilters(*filter_0, *filter_1, tmp0, tmp1,
                       pred_res_0[(size_t)p], pred_res_1[(size_t)p],
                       comb_zero[p - 1], nullptr, nullptr, windowSize, nullptr, nullptr);
        } else {
            OrFilters(*filter_0, *filter_1, tmp0, tmp1,
                      pred_res_0[(size_t)p], pred_res_1[(size_t)p],
                      comb_zero[p - 1], nullptr, nullptr, windowSize, nullptr, nullptr);
        }
        free(pred_res_0[(size_t)p]);
        free(pred_res_1[(size_t)p]);
        free(comb_zero[p - 1]);
    }
    free(tmp0);
    free(tmp1);
    free(comb_zero);
}

void QueryServer::BOCheckFilter(const CombinedBOFilter &filterSpec) {
    if (filterSpec.base_bofilters_size() == 0) {
        throw std::invalid_argument("Empty BO filter.");
    }

    const std::string &table_id = filterSpec.base_bofilters(0).id();
    if (BOTableMetas.count(table_id) == 0) {
        throw std::invalid_argument("BO table metadata not found: " + table_id);
    }

    const BOTableMeta &meta = BOTableMetas[table_id];
    const size_t block_bytes = (size_t)meta.blockNum * sizeof(uint128_t);
    const size_t offset_bytes = (size_t)meta.blockSize * sizeof(uint128_t);

    for (int i = 0; i < filterSpec.base_bofilters_size(); i++) {
        const BaseBOFilter &bf = filterSpec.base_bofilters(i);
        if (bf.id() != table_id) {
            throw std::invalid_argument("Mixed table ids in CombinedBOFilter.");
        }
        if (bf.block_share_0().size() != block_bytes ||
            bf.block_share_1().size() != block_bytes ||
            bf.offset_share_0().size() != offset_bytes ||
            bf.offset_share_1().size() != offset_bytes) {
            throw std::invalid_argument("Invalid BO filter share size.");
        }
    }
}

// void QueryServer::parallel_eval_vb_table(uint128_t **res, uint128_t** table, int numBuckets, int windowSize, int share_id, const CombinedVBFilter &filterSpec) {
//     int num_eval = filterSpec.base_vbfilters_size();
//     // Use one contiguous buffer to reduce allocation overhead.
//     std::vector<uint128_t> aligned_share_arrays((size_t)num_eval * (size_t)numBuckets);

//     // 计算预期的字节总长度
//     size_t expected_bytes = numBuckets * sizeof(uint128_t);

//     for(int i = 0; i < num_eval; i++) {
//         const std::string& share_byte = (share_id == 0) ? 
//             filterSpec.base_vbfilters(i).share_0() : 
//             filterSpec.base_vbfilters(i).share_1();

//         // 1. 安全校验：防止越界崩溃
//         if (share_byte.size() < expected_bytes) {
//             // 此处必须有错误处理逻辑！可以抛出异常、打印错误日志或直接 return
//             throw std::runtime_error("Invalid Protobuf data: share_byte size is too small.");
//         }

//         std::memcpy(aligned_share_arrays.data() + ((size_t)i * (size_t)numBuckets), share_byte.data(), expected_bytes);
//     }

//     INIT_TIMER
//     START_TIMER

//     // Reuse OpenMP worker threads instead of creating a std::thread per filter.
// #pragma omp parallel for schedule(static)
//     for(int i = 0; i < num_eval; i++) {
//         eval_vb_table(
//             res[i], table, numBuckets, windowSize, share_id,
//             aligned_share_arrays.data() + ((size_t)i * (size_t)numBuckets));
//     }
//     STOP_TIMER("eval_vb_table finish")
// }


// void QueryServer::eval_vb_table(uint128_t *res, uint128_t** table, int numBuckets, int windowSize, int share_id, const uint128_t *filterSpec) {
//     for(int i = 0; i < windowSize; i++) {
//         uint128_t acc = 0;
//         uint128_t *row = table[i];
//         for(int j = 0; j < numBuckets; j++) {
//             acc += filterSpec[j] * row[j];
//         }
//         res[i] = acc;
//     }
// }

CallData::CallData(QueryServer &server, Aggregate::AsyncService *service, ServerCompletionQueue *cq, RpcType type) :
        server(server), service(service), cq(cq), responderMult(&ctx), responderInit(&ctx), status(CREATE), type(type) {
    Proceed();        
}

void CallData::Proceed() {
    if (status == CREATE) {
        status = PROCESS;
        if (type == MULT) {
            service->RequestSendMult(&ctx, &reqMult, &responderMult, cq, cq, this);
        } else if (type == INIT) {
            service->RequestSendSystemInit(&ctx, &reqInit, &responderInit, cq, cq, this);
        }
    } else if (status == PROCESS) {
        if (type == MULT) {
            new CallData(server, service, cq, MULT);
            server.FinishMultiply((const uint128_t *)reqMult.shares().c_str(), reqMult.shares().size());
            responderMult.Finish(respMult, Status::OK, this);
        } else if (type == INIT) {
            new CallData(server, service, cq, INIT);
            server.FinishSystemInit((const uint8_t *)reqInit.key().c_str());
            responderInit.Finish(respInit, Status::OK, this);
        }
        status = FINISH;
    } else {
        assert(status == FINISH);
        delete this;
    }
}

class QueryServiceImpl final : public Query::Service {
    public:
        QueryServer &server;
        
        QueryServiceImpl(QueryServer &server) : server(server) {}

        Status SendDCFInit(ServerContext *context, const InitDCFRequest *req, InitDCFResponse *resp) override {
            printf("Adding DCF table\n");
            cout << req->id() << endl;
            server.DCFAddTable(req->id(), req->window_size(), req->num_buckets(), server.malicious);
            printf("Added DCF table\n");
            return Status::OK;
        }

       Status SendDPFInit(ServerContext *context, const InitDPFRequest *req, InitDPFResponse *resp) override {
            printf("Adding DPF table\n");
            cout << req->id() << endl;
            server.DPFAddTable(req->id(), req->window_size(), req->num_buckets(), server.malicious);
            printf("Added DPF table\n");
            return Status::OK;
        }

        Status SendATInit(ServerContext *context, const InitATRequest *req, InitATResponse *resp) override {
            printf("Adding aggregate tree\n");
            server.AggTreeAddIndex(req->id(), req->depth(), (AggFunc)req->agg_func());
            printf("Added aggregate tree\n");
            return Status::OK;
        }

        Status SendListInit(ServerContext *context, const InitListRequest *req, InitListResponse *resp) override {
            printf("Adding value list\n");
            server.AddValList(req->id(), req->window_size());
            printf("Added value list\n");
            return Status::OK;
        }

        Status SendOneHotTableInit(ServerContext *context, const InitOneHotTableRequest *req, InitOneHotTableResponse *resp) override {
            printf("Adding OneHot table\n");
            server.AddOneHotTable(req->table_id(), req->windowsize(), req->numbuckets());
            printf("Added OneHot table\n");
            return Status::OK;
        }

        Status SendOneHotTableUpdate(ServerContext *context, const UpdateOneHotTableRequest *req, UpdateOneHotTableResponse *resp) override {
            server.OneHotTableUpdate(
                req->table_id(),
                req->rank_loc(),
                (const uint128_t *)req->share_data_0().c_str(),
                (const uint128_t *)req->share_data_1().c_str());
            return Status::OK;
        }

        Status SendOneHotTableBatchUpdate(ServerContext *context, const UpdateOneHotTableBatchRequest *req, UpdateOneHotTableBatchResponse *resp) override {
            for (int i = 0; i < req->update_size(); i++) {
                server.OneHotTableUpdate(
                    req->update(i).table_id(),
                    req->update(i).rank_loc(),
                    (const uint128_t *)req->update(i).share_data_0().c_str(),
                    (const uint128_t *)req->update(i).share_data_1().c_str());
            }
            return Status::OK;
        }

        Status SendBOTableInit(ServerContext *context, const InitBOTableRequest *req, InitBOTableResponse *resp) override {
            server.AddBOTable(req->table_id(), req->windowsize(), req->numbuckets(), req->logblocknum());
            return Status::OK;
        }

        Status SendBOTableUpdate(ServerContext *context, const UpdateBOTableRequest *req, UpdateBOTableResponse *resp) override {
            server.BOTableUpdate(
                req->table_id(),
                req->rank_loc(),
                (const uint128_t *)req->index_share_data_0().c_str(),
                (const uint128_t *)req->index_share_data_1().c_str(),
                (const uint128_t *)req->offset_share_data_0().c_str(),
                (const uint128_t *)req->offset_share_data_1().c_str());
            return Status::OK;
        }

        Status SendBOTableBatchUpdate(ServerContext *context, const UpdateBOTableBatchRequest *req, UpdateBOTableBatchResponse *resp) override {
            for (int i = 0; i < req->update_size(); i++) {
                server.BOTableUpdate(
                    req->update(i).table_id(),
                    req->update(i).rank_loc(),
                    (const uint128_t *)req->update(i).index_share_data_0().c_str(),
                    (const uint128_t *)req->update(i).index_share_data_1().c_str(),
                    (const uint128_t *)req->update(i).offset_share_data_0().c_str(),
                    (const uint128_t *)req->update(i).offset_share_data_1().c_str());
            }
            return Status::OK;
        }

        Status SendDCFBatchedUpdate(ServerContext *context, const BatchedUpdateDCFRequest *req, BatchedUpdateDCFResponse *resp) override {
            for (int i = 0; i < req->updates_size(); i++) {
                server.DCFUpdate(req->updates(i).id(), req->updates(i).val(), (const uint128_t *)req->updates(i).data0().c_str(), (const uint128_t *)req->updates(i).data1().c_str());
            }
            return Status::OK;
        }
        
        Status SendDCFUpdate(ServerContext *context, const UpdateDCFRequest *req, UpdateDCFResponse *resp) override {
            //printf("Processing DCF update\n");
            server.DCFUpdate(req->id(), req->val(), (const uint128_t *)req->data0().c_str(), (const uint128_t *)req->data1().c_str());
            //printf("Finished processing DCF update\n");
            return Status::OK;
        }

        Status SendDPFBatchedUpdate(ServerContext *context, const BatchedUpdateDPFRequest *req, BatchedUpdateDPFResponse *resp) override {
            for (int i = 0; i < req->updates_size(); i++) {
                server.DPFUpdate(req->updates(i).id(), req->updates(i).val(), (const uint128_t *)req->updates(i).data0().c_str(), (const uint128_t *)req->updates(i).data1().c_str());
            }
            return Status::OK;
        }
 
        Status SendDPFUpdate(ServerContext *context, const UpdateDPFRequest *req, UpdateDPFResponse *resp) override {
            server.DPFUpdate(req->id(), req->val(), (const uint128_t *)req->data0().c_str(), (const uint128_t *)req->data1().c_str());
            return Status::OK;
        }

        Status SendATAppend1(ServerContext *context, const AppendAT1Request *req, AppendAT1Response *resp) override {
            int len;
            printf("Processing AggTree append part 1\n");
            uint128_t **parents = server.AggTreeAppend1(req->id(), &len);
            for (int i = 0; i < len; i++) {
                resp->add_parent_shares0((uint8_t *)&parents[0][i], sizeof(uint128_t));
                resp->add_parent_shares1((uint8_t *)&parents[1][i], sizeof(uint128_t));
            }
            free(parents);
            printf("Finished processing AggTree append part 1\n");
            return Status::OK;
        }

        Status SendListBatchedUpdate(ServerContext *context, const BatchedUpdateListRequest *req, BatchedUpdateListResponse *resp) override {
            for (int i = 0; i < req->updates_size(); i++) {
                uint128_t val0, val1;
                memcpy((uint8_t *)&val0, req->updates(i).share0().c_str(), sizeof(uint128_t));
                memcpy((uint8_t *)&val1, req->updates(i).share1().c_str(), sizeof(uint128_t));
                server.ValListUpdate(req->updates(i).id(), req->updates(i).val(), val0, val1);
            }
            return Status::OK; 
        }
 

        Status SendListUpdate(ServerContext *context, const UpdateListRequest *req, UpdateListResponse *resp) override {
            uint128_t val0, val1;
            memcpy((uint8_t *)&val0, req->share0().c_str(), sizeof(uint128_t));
            memcpy((uint8_t *)&val1, req->share1().c_str(), sizeof(uint128_t));
            server.ValListUpdate(req->id(), req->val(), val0, val1);
            return Status::OK;
        }



        Status SendATAppend2(ServerContext *context, const AppendAT2Request *req, AppendAT2Response *resp) override {
            printf("Processing AggTree append part 2\n");
            uint128_t *new_shares0 = (uint128_t *)malloc(req->new_shares0_size() * sizeof(uint128_t));
            uint128_t *new_shares1 = (uint128_t *)malloc(req->new_shares1_size() * sizeof(uint128_t));
            for (int i = 0; i < req->new_shares0_size(); i++) {
                memcpy((uint8_t *)&new_shares0[i], req->new_shares0(i).c_str(), sizeof(uint128_t));
                memcpy((uint8_t *)&new_shares1[i], req->new_shares1(i).c_str(), sizeof(uint128_t));
            }
            server.AggTreeAppend2(req->id(), req->idx(), new_shares0, new_shares1);
            printf("Finished processing AggTree append part 2\n");
            return Status::OK;
        }

        Status SendDCFQuery(ServerContext *context, const QueryDCFRequest *req, QueryDCFResponse *resp) override {
            uint32_t len = 0;
            printf("Received DCF query\n");
            uint128_t *res0;
            uint128_t *res1;
            server.DCFQuery(&res0, &res1, req->id(), (const uint8_t *)req->key0().c_str(), (const uint8_t *)req->key1().c_str(), &len);
            for (int i = 0; i < len; i++) {
                res0[i] += res1[i];
            }
            printf("Finished processing DCF query\n");
            resp->set_res(res0, sizeof(uint128_t) * len);
            free(res0);
            free(res1);
            return Status::OK;
        }

        Status SendATQuery(ServerContext *context, const QueryATRequest *req, QueryATResponse *resp) override {
            printf("Received AggTree query\n");
            int depth = server.AggTrees[req->id()].first->depth;
            uint128_t* res = (uint128_t*)malloc((depth+1)*sizeof(uint128_t));
            uint128_t* mac = (uint128_t*)malloc((depth+1)*sizeof(uint128_t));
            uint128_t* res_r = (uint128_t*)malloc((depth+1)*sizeof(uint128_t));
            uint128_t* mac_r = (uint128_t*)malloc((depth+1)*sizeof(uint128_t));
            server.AggTreeQuery(req->id(), (const uint8_t *)req->key0().c_str(), (const uint8_t *)req->key1().c_str(), res, mac, res_r, mac_r, &depth);
            resp->set_res((uint8_t *)res, (depth)*sizeof(uint128_t));
            resp->set_mac((uint8_t *)mac, (depth)*sizeof(uint128_t));
            resp->set_res_r((uint8_t *)res_r, (depth)*sizeof(uint128_t));
            resp->set_mac_r((uint8_t *)mac_r, (depth)*sizeof(uint128_t));
            printf("Finished processing AggTree query\n");
            return Status::OK;
        }

        Status SendAggQuery(ServerContext *context, const QueryAggRequest *req, QueryAggResponse *resp) {
            printf("Received aggregate query\n");
            uint128_t res, mac, lin_comb, lin_comb_mac;
            lin_comb = 0;
            lin_comb_mac = 0;
            server.AggFilterQuery(req->agg_id(), req->combined_filter(), &res, &mac, &lin_comb, &lin_comb_mac);
            resp->set_res((uint8_t *)&res, sizeof(uint128_t));
            resp->set_mac((uint8_t *)&mac, sizeof(uint128_t));
            resp->set_lin_comb((uint8_t *)&lin_comb, sizeof(uint128_t));
            resp->set_lin_comb_mac((uint8_t *)&lin_comb_mac, sizeof(uint128_t));
            printf("Finished processing aggregate query\n");
            return Status::OK;
        }


        Status SendVBAggQuery(ServerContext *context, const QueryVBAggRequest *req, QueryVBAggResponse *resp) {
            
            cout << "Received VBaggreate query" << endl;
            uint128_t res = 0;
            server.VBAggFilterQuery(req->agg_id(), req->combined_vbfilter(), res);
            resp->set_res((uint8_t *)&res, sizeof(uint128_t)); 
            cout << "Finished processing VBaggregate query" << endl;

            return Status::OK;
        }

        Status SendBOAggQuery(ServerContext *context, const QueryBOAggRequest *req, QueryBOAggResponse *resp) {
            uint128_t res = 0;
            server.BOAggFilterQuery(req->agg_id(), req->combined_bofilter(), res);
            resp->set_res((const uint8_t *)&res, sizeof(uint128_t));
            return Status::OK;
        }

        Status SendVBFSSAggQuery(ServerContext *context, const QueryVBFSSAggRequest *req, QueryVBFSSAggResponse *resp) {
            (void)context;
            uint128_t res = 0;
            server.VBFSSAggFilterQuery(req->agg_id(), req->combined_vbfssfilter(), res);
            resp->set_res((const uint8_t *)&res, sizeof(uint128_t));
            return Status::OK;
        }

        Status SendBOFSSAggQuery(ServerContext *context, const QueryBOFSSAggRequest *req, QueryBOFSSAggResponse *resp) {
            (void)context;
            uint128_t res = 0;
            server.BOFSSAggFilterQuery(req->agg_id(), req->combined_bofssfilter(), res);
            resp->set_res((const uint8_t *)&res, sizeof(uint128_t));
            return Status::OK;
        }

       

};

void handleAsyncRpcs(QueryServer &server, Aggregate::AsyncService &service, unique_ptr<ServerCompletionQueue> &cq) {
    new CallData(server, &service, cq.get(), INIT);
    new CallData(server, &service, cq.get(), MULT);
    void *tag;
    bool ok;
    while (true) {
        assert(cq->Next(&tag, &ok));
        assert(ok);
        static_cast<CallData*>(tag)->Proceed();
    }
}
 

void runServer(string publicAddrs[], string bindAddr, int serverID, int cores, bool malicious) {
    QueryServer s(publicAddrs, serverID, cores, malicious);
    QueryServiceImpl queryService(s);
    Aggregate::AsyncService asyncService;

    grpc::EnableDefaultHealthCheckService(true);
    grpc::reflection::InitProtoReflectionServerBuilderPlugin();

    ServerBuilder queryBuilder;
    queryBuilder.SetMaxReceiveMessageSize(-1);
    queryBuilder.AddListeningPort(bindAddr, grpc::InsecureServerCredentials());
    queryBuilder.RegisterService(&queryService);
    queryBuilder.RegisterService(&asyncService);
    unique_ptr<ServerCompletionQueue> cq(queryBuilder.AddCompletionQueue());
    unique_ptr<Server> queryServer(queryBuilder.BuildAndStart());

    s.service = &asyncService;
    s.cq = cq.get();
    thread t(handleAsyncRpcs, ref(s), ref(asyncService), ref(cq));
    s.StartSystemInit(publicAddrs);
    t.join();
}

int main(int argc, char *argv[]) {
    ifstream config_stream(argv[1]);
    json config;
    config_stream >> config;

    string addrs[NUM_SERVERS];
    for (int i = 0; i < NUM_SERVERS; i++) {
        addrs[i] = config[ADDRS][i];
    }
    string bindAddr = "0.0.0.0:" + string(config[PORT]);
    assert(argc == 2);
    int server_num = config[SERVER_NUM];
    assert(server_num == 0 || server_num == 1 || server_num == 2);
    runServer(addrs, bindAddr, server_num, config[CORES], config[MALICIOUS]);
}
