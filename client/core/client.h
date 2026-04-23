// Modified by Waldo derivative maintainers on 2026-04-23.
#ifndef CLIENT_H
#define CLIENT_H

#include <grpcpp/grpcpp.h>
//#include "../libs/grpc/include/grpc/impl/codegen/port_platform.h"
#include "../../network/core/query.grpc.pb.h"
//#include "table.h"

#include "../libPSI/libPSI/PIR/BgiPirClient.h"
#include "../libPSI/libPSI/PIR/BgiPirServer.h"

#include "../../secure-indices/core/DCFTable.h"
#include "../../secure-indices/core/DPFTable.h"
#include "../../secure-indices/core/AggTree.h"
#include "../../secure-indices/core/common.h"
#include "query.h"

// #include <BgiPirClient.h>
// #include <BgiPirServer.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/TestCollection.h>

#include <map>
#include <string>
#include <vector>

#define UPDATE_CHUNK_SZ 10000

using namespace osuCrypto;
using namespace std;
using namespace dorydb;
using dbquery::Query;
using dbquery::Aggregate;
using dbquery::CombinedFilter;
using dbquery::BaseFilter;
using dbquery::UpdateDCFRequest;
using dbquery::UpdateDPFRequest;
using dbquery::UpdateListRequest;
using grpc::Channel;
using grpc::ClientContext;
typedef unsigned __int128 bgi_uint128_t;

using dbquery::CombinedVBFilter;
using dbquery::BaseVBFilter;
using dbquery::CombinedVBFSSFilter;
using dbquery::BaseVBFSSFilter;
using dbquery::CombinedBOFilter;
using dbquery::BaseBOFilter;
using dbquery::CombinedBOFSSFilter;
using dbquery::BaseBOFSSFilter;
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


class QueryClient
{
public:
    QueryClient(vector<shared_ptr<grpc::Channel>> channels, bool malicious = false);

    void AddDCFTable(string id, uint32_t windowSize, uint32_t numBuckets, vector<uint32_t> &data);
    void AddDPFTable(string id, uint32_t windowSize, uint32_t numBuckets, vector<uint32_t> &data);
    void RegisterDCFTableMeta(string id, uint32_t windowSize, uint32_t numBuckets);
    void RegisterDPFTableMeta(string id, uint32_t windowSize, uint32_t numBuckets);
    void AddValList(string id, uint32_t windowSize, vector<uint128_t> &data);
    void AddAggTree(string id, AggFunc aggFunc, int depth, map<uint64_t, uint128_t> &data);
    void DCFUpdate(string id, uint32_t idx, uint32_t val, UpdateDCFRequest *reqs[]);
    void RunDCFUpdate(string id, uint32_t idx, uint32_t val);
    void DPFUpdate(string id, uint32_t idx, uint32_t val, UpdateDPFRequest *reqs[]);
    void RunDPFUpdate(string id, uint32_t idx, uint32_t val);
    void ValListUpdate(string id, uint32_t idx, uint128_t val, UpdateListRequest *reqs[]);
    void AggTreeAppend(string id, uint64_t idx, uint128_t val);

    uint128_t *DCFQuery(string id, uint32_t left_x, uint32_t right_x, size_t ret_len);
    void AggTreeQuery(string id, uint128_t left_x, uint128_t right_x, uint128_t **ret, uint128_t **ret_r);

    uint128_t AggQuery(string agg_id, QueryObj &query);
    void GenerateCombinedFilter(Expression *expr, CombinedFilter *filters[]);
    void GenerateBaseFilter(Condition *cond, BaseFilter *filters[]);
    void GenerateDPFFilter(string table_id, uint32_t x, BaseFilter *filters[]);
    void GenerateDCFFilter(string table_id, uint32_t left_x, uint32_t right_x, BaseFilter *filters[]);

    uint128_t GetMACAlpha();

    uint128_t VBAggQuery(const string& agg_id, const string& table_id, bool is_point, int num_buckets, const vector<uint32_t> &query);
    uint128_t VBFSSAggQuery(const string& agg_id, const string& table_id, bool is_point, bool is_and, const vector<uint32_t> &query);
    uint128_t VBFSSAggQuery(const string& agg_id, const string& table_id, bool is_and, const vector<uint32_t> &query);
    uint128_t BOAggQuery(const string& agg_id, const string& table_id, bool is_point, bool is_and, const vector<uint32_t> &query);
    uint128_t BOAggQuery(const string& agg_id, const string& table_id, bool is_and, const vector<uint32_t> &query);
    uint128_t BOFSSAggQuery(const string& agg_id, const string& table_id, bool is_point, bool is_and, const vector<uint32_t> &query);
    uint128_t BOFSSAggQuery(const string& agg_id, const string& table_id, bool is_and, const vector<uint32_t> &query);
    void GenerateBaseVBFilter(string id, bool is_point, int num_buckets, uint128_t *raw_query_vector, BaseVBFilter *filters[]);
    void GenerateCombinedVBFilter(const string& table_id, uint128_t **raw_query_vector, int num_query, int num_buckets, bool is_point, bool is_and, CombinedVBFilter *filters[]);
    void GenerateCombinedVBFSSFilter(const string& table_id, const vector<uint32_t> &query, bool is_point, bool is_and, CombinedVBFSSFilter *filters[]);
    void GenerateCombinedVBFSSFilter(const string& table_id, const vector<uint32_t> &query, bool is_and, CombinedVBFSSFilter *filters[]);
    void GenerateBaseBOFilter(string id, const uint128_t *raw_block, const uint128_t *raw_offset, BaseBOFilter *filters[]);
    void GenerateCombinedBOFilter(const string& table_id, const vector<uint32_t> &query, bool is_point, bool is_and, CombinedBOFilter *filters[]);
    void GenerateBaseBOFilter(string id, uint32_t x, BaseBOFilter *filters[]);
    void GenerateCombinedBOFilter(const string& table_id, const vector<uint32_t> &query, bool is_and, CombinedBOFilter *filters[]);
    void GenerateCombinedBOFSSFilter(const string& table_id, const vector<uint32_t> &query, bool is_point, bool is_and, CombinedBOFSSFilter *filters[]);
    void GenerateCombinedBOFSSFilter(const string& table_id, const vector<uint32_t> &query, bool is_and, CombinedBOFSSFilter *filters[]);
    void SetVBFSSBlockNum(const string& table_id, uint32_t blockNum);
    void AddOneHotTable(string table_id, uint32_t windowSize, uint32_t numBuckets, const vector<uint32_t> &data);
    void RegisterOneHotTableMeta(string table_id, uint32_t numBuckets);
    void OneHotTableUpdate(string id, uint32_t idx, uint32_t rank_loc, UpdateOneHotTableRequest *reqs[]);
    void AddBOTable(string table_id, uint32_t windowSize, uint32_t numBuckets, uint32_t logBlockNum, const vector<uint32_t> &data);
    void RegisterBOTableMeta(string table_id, uint32_t numBuckets, uint32_t logBlockNum);
    void BOTableUpdate(string id, uint32_t idx, uint32_t rank_loc, UpdateBOTableRequest *reqs[]);


    private:
    vector<unique_ptr<dbquery::Query::Stub>> queryStubs;
    vector<unique_ptr<dbquery::Aggregate::Stub>> aggStubs;
    PRNG *prng;
    uint128_t modulus;
    bool malicious;
    uint128_t alpha;
    // std::unique_ptr<dbquery::QueryDCF::Stub> DCFstub_;
    map<string, DPFTableClient*> DPFTables;
    map<string, DCFTableClient*> DCFTables;
    map<string, AggTreeIndexClient*> AggTrees;
    map<string, uint32_t> OneHotNumBuckets;
    map<string, uint32_t> BONumBuckets;
    map<string, uint32_t> BOLogBlockNum;
    map<string, uint32_t> BOBlockNum;
    map<string, uint32_t> BOBlockSize;
    map<string, uint32_t> VBFSSBlockNum;

    uint8_t *RunCondition(Condition *cond, size_t ret_len);
    uint8_t *RecurseExpression(Expression *expr, size_t ret_len);

};
#endif
