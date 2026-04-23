// Modified by Waldo derivative maintainers on 2026-04-23.
#include <string>
#include <vector>
#include <fstream>
#include <functional>
#include <unordered_map>
#include "../core/client.h"
#include "../core/query.h"
#include "../../secure-indices/core/common.h"
#include "../../utils/json.hpp"
#include "../../utils/config.h"

using grpc::Channel;

using json = nlohmann::json;

using namespace dorydb;
using namespace std;

static bool g_send_table = true;

bool VBNonFSSAggTestImpl(QueryClient *client, int windowSize, int numBuckets, int filter_nums, int reps, bool vb_is_point, const vector<uint32_t> &vbquery, vector<uint32_t> &times) {
    // 1. 初始化测试数据
    vector<uint128_t> data_vals(windowSize, (uint128_t)1);
    vector<uint32_t> oneHotVals(windowSize, (uint32_t)1);
    // 提前声明常量字符串，彻底剥离计时器内部的内存分配开销
    const string vals_table_name = "test_vb_vals";
    const string onehot_table_name = "test_vb_dpf";

    // 2. 数据注入阶段（不计入查询耗时）
    if (g_send_table) {
        cout << "[Setup] Pushing data to servers..." << endl;
        client->AddValList(vals_table_name, windowSize, data_vals);
        client->AddOneHotTable(onehot_table_name, windowSize, numBuckets, oneHotVals);
        cout << "[Setup] Data push complete." << endl;
    } else {
        client->RegisterOneHotTableMeta(onehot_table_name, (uint32_t)numBuckets);
        cout << "[Setup] Reuse existing VB-PMS tables (skip upload)." << endl;
    }

    uint128_t ret = 0;
    
    // 3. 核心计时循环
    for(int i = 0; i < reps; i++) {
        INIT_TIMER;
        START_TIMER;
        // 直接传递常量引用，消除所有不必要的深拷贝
        uint128_t current_res = client->VBAggQuery(
            vals_table_name, 
            onehot_table_name, 
            vb_is_point, 
            numBuckets, 
            vbquery
        );
        
        // 使用异或累加结果，强制编译器保留每一次调用的返回值，防止激进优化
        cout << "ret = " <<  current_res << endl;
        uint32_t t = STOP_TIMER_();
        // 对齐 DPF 的 results.dat 统计口径：每次查询单独计时并入表。
        times.push_back(t);
    }

    return true;
}

bool VBNonFSSPointAggTest(QueryClient *client, int windowSize, int numBuckets, int filter_nums, int reps, uint32_t vb_point_x, vector<uint32_t> &times) {
    vector<uint32_t> vbquery((size_t)filter_nums, vb_point_x);
    return VBNonFSSAggTestImpl(client, windowSize, numBuckets, filter_nums, reps, true, vbquery, times);
}

bool VBNonFSSRangeAggTest(QueryClient *client, int windowSize, int numBuckets, int filter_nums, int reps, uint32_t vb_range_left, uint32_t vb_range_right, vector<uint32_t> &times) {
    vector<uint32_t> vbquery((size_t)filter_nums * 2, 0);
    for (int i = 0; i < filter_nums; i++) {
        vbquery[(size_t)i * 2] = vb_range_left;
        vbquery[(size_t)i * 2 + 1] = vb_range_right;
    }
    return VBNonFSSAggTestImpl(client, windowSize, numBuckets, filter_nums, reps, false, vbquery, times);
}

bool VBFSSAggTestImpl(QueryClient *client, int windowSize, int numBuckets, int logBlockNum, int reps, bool vb_is_point, const vector<uint32_t> &vbquery, vector<uint32_t> &times) {
    vector<uint128_t> data_vals(windowSize, (uint128_t)1);
    vector<uint32_t> oneHotVals(windowSize, (uint32_t)1);
    bool is_and = true;

    const string vals_table_name = "test_vbfss_vals";
    const string onehot_table_name = "test_vbfss_tbl";
    const uint32_t blockNum = (uint32_t)(1u << logBlockNum);

    if (g_send_table) {
        cout << "[Setup] Pushing VB-FSS data to servers..." << endl;
        client->AddValList(vals_table_name, windowSize, data_vals);
        client->AddOneHotTable(onehot_table_name, windowSize, numBuckets, oneHotVals);
        client->SetVBFSSBlockNum(onehot_table_name, blockNum);
        cout << "[Setup] VB-FSS data push complete." << endl;
    } else {
        client->RegisterOneHotTableMeta(onehot_table_name, (uint32_t)numBuckets);
        client->SetVBFSSBlockNum(onehot_table_name, blockNum);
        cout << "[Setup] Reuse existing VB-FSS tables (skip upload)." << endl;
    }

    for (int i = 0; i < reps; i++) {
        INIT_TIMER;
        START_TIMER;
        uint128_t current_res = client->VBFSSAggQuery(vals_table_name, onehot_table_name, vb_is_point, is_and, vbquery);
        cout << "ret = " << current_res << endl;
        uint32_t t = STOP_TIMER_();
        cout << "------------------------------------" << endl;
        cout << "[STOPPING TIMER] Total RUNTIME of VBFSSAggQuery full RTT finish: " << t << " millisec " << endl;
        times.push_back(t);
    }

    return true;
}

bool VBFSSPointAggTest(QueryClient *client, int windowSize, int numBuckets, int logBlockNum, int filter_nums, int reps, uint32_t vb_point_x, vector<uint32_t> &times) {
    vector<uint32_t> vbquery((size_t)filter_nums, vb_point_x);
    return VBFSSAggTestImpl(client, windowSize, numBuckets, logBlockNum, reps, true, vbquery, times);
}

bool VBFSSRangeAggTest(QueryClient *client, int windowSize, int numBuckets, int logBlockNum, int filter_nums, int reps, uint32_t vb_range_left, uint32_t vb_range_right, vector<uint32_t> &times) {
    vector<uint32_t> vbquery((size_t)filter_nums * 2, 0);
    for (int i = 0; i < filter_nums; i++) {
        vbquery[(size_t)i * 2] = vb_range_left;
        vbquery[(size_t)i * 2 + 1] = vb_range_right;
    }
    return VBFSSAggTestImpl(client, windowSize, numBuckets, logBlockNum, reps, false, vbquery, times);
}

bool boNonFSSAggTestImpl(QueryClient *client, int windowSize, int numBuckets, int logBlockNum, int reps, bool bo_is_point, const vector<uint32_t> &boquery, vector<uint32_t> &times) {
    vector<uint128_t> data_vals(windowSize, (uint128_t)1);
    vector<uint32_t> boVals(windowSize, (uint32_t)1);
    bool is_and = true;

    const string vals_table_name = "test_bo_vals";
    const string bo_table_name = "test_bo_tbl";

    if (g_send_table) {
        cout << "[Setup] Pushing BO data to servers..." << endl;
        client->AddValList(vals_table_name, windowSize, data_vals);
        client->AddBOTable(bo_table_name, windowSize, numBuckets, logBlockNum, boVals);
        cout << "[Setup] BO data push complete." << endl;
    } else {
        client->RegisterBOTableMeta(bo_table_name, (uint32_t)numBuckets, (uint32_t)logBlockNum);
        cout << "[Setup] Reuse existing BO-PMS tables (skip upload)." << endl;
    }

    for (int i = 0; i < reps; i++) {
        INIT_TIMER;
        START_TIMER;
        uint128_t agg = client->BOAggQuery(vals_table_name, bo_table_name, bo_is_point, is_and, boquery);
        cout << "bo agg = " << agg << endl;
        uint32_t t = STOP_TIMER_();
        cout << "------------------------------------" << endl;
        cout << "[STOPPING TIMER] Total RUNTIME of BOAggQuery full RTT finish: " << t << " millisec " << endl;
        times.push_back(t);
    }

    return true;
}

bool boNonFSSPointAggTest(QueryClient *client, int windowSize, int numBuckets, int logBlockNum, int filter_nums, int reps, uint32_t bo_point_x, vector<uint32_t> &times) {
    vector<uint32_t> boquery((size_t)filter_nums, bo_point_x);
    return boNonFSSAggTestImpl(client, windowSize, numBuckets, logBlockNum, reps, true, boquery, times);
}

bool boNonFSSRangeAggTest(QueryClient *client, int windowSize, int numBuckets, int logBlockNum, int filter_nums, int reps, uint32_t bo_range_left, uint32_t bo_range_right, vector<uint32_t> &times) {
    vector<uint32_t> boquery((size_t)filter_nums * 2, 0);
    for (int i = 0; i < filter_nums; i++) {
        boquery[(size_t)i * 2] = bo_range_left;
        boquery[(size_t)i * 2 + 1] = bo_range_right;
    }
    return boNonFSSAggTestImpl(client, windowSize, numBuckets, logBlockNum, reps, false, boquery, times);
}

bool boFSSAggTestImpl(QueryClient *client, int windowSize, int numBuckets, int logBlockNum, int reps, bool bo_is_point, const vector<uint32_t> &boquery, vector<uint32_t> &times) {
    vector<uint128_t> data_vals(windowSize, (uint128_t)1);
    vector<uint32_t> boVals(windowSize, (uint32_t)1);
    bool is_and = true;

    const string vals_table_name = "test_bofss_vals";
    const string bo_table_name = "test_bofss_tbl";

    if (g_send_table) {
        cout << "[Setup] Pushing BO-FSS data to servers..." << endl;
        client->AddValList(vals_table_name, windowSize, data_vals);
        client->AddBOTable(bo_table_name, windowSize, numBuckets, logBlockNum, boVals);
        cout << "[Setup] BO-FSS data push complete." << endl;
    } else {
        client->RegisterBOTableMeta(bo_table_name, (uint32_t)numBuckets, (uint32_t)logBlockNum);
        cout << "[Setup] Reuse existing BO-FSS tables (skip upload)." << endl;
    }

    for (int i = 0; i < reps; i++) {
        INIT_TIMER;
        START_TIMER;
        uint128_t agg = client->BOFSSAggQuery(vals_table_name, bo_table_name, bo_is_point, is_and, boquery);
        cout << "bo agg = " << agg << endl;
        uint32_t t = STOP_TIMER_();
        cout << "------------------------------------" << endl;
        cout << "[STOPPING TIMER] Total RUNTIME of BOFSSAggQuery full RTT finish: " << t << " millisec " << endl;
        times.push_back(t);
    }

    return true;
}

bool boFSSPointAggTest(QueryClient *client, int windowSize, int numBuckets, int logBlockNum, int filter_nums, int reps, uint32_t bo_point_x, vector<uint32_t> &times) {
    vector<uint32_t> boquery((size_t)filter_nums, bo_point_x);
    return boFSSAggTestImpl(client, windowSize, numBuckets, logBlockNum, reps, true, boquery, times);
}

bool boFSSRangeAggTest(QueryClient *client, int windowSize, int numBuckets, int logBlockNum, int filter_nums, int reps, uint32_t bo_range_left, uint32_t bo_range_right, vector<uint32_t> &times) {
    vector<uint32_t> boquery((size_t)filter_nums * 2, 0);
    for (int i = 0; i < filter_nums; i++) {
        boquery[(size_t)i * 2] = bo_range_left;
        boquery[(size_t)i * 2 + 1] = bo_range_right;
    }
    return boFSSAggTestImpl(client, windowSize, numBuckets, logBlockNum, reps, false, boquery, times);
}



bool dpfAggTest(QueryClient *client, int numBuckets, int windowSize, int numConds, int reps, vector<uint32_t> &times) {
    QueryObj q;
    q.agg_table_id = "test_vals";
    vector<Condition> conds;
    for (int i = 0; i < numConds; i++) {
        Condition cond;
        cond.table_id = "test_dpf";
        cond.cond_type = POINT_COND;
        cond.x = 1;
        conds.push_back(cond);
    }
    Expression expr;
    expr.op_type = numConds == 1 ? NO_OP : AND_OP;
    vector<Expression> emptyExprs;
    expr.exprs = emptyExprs;
    expr.conds = conds;
    q.expr = &expr;

    vector<uint128_t> dataVals(windowSize, (uint128_t)1);
    vector<uint32_t> dcfVals(windowSize, (uint32_t)1);

    if (g_send_table) {
        client->AddValList(string("test_vals"), windowSize, dataVals);
        client->AddDPFTable(string("test_dpf"), windowSize, numBuckets, dcfVals);
    } else {
        client->RegisterDPFTableMeta(string("test_dpf"), (uint32_t)windowSize, (uint32_t)numBuckets);
        cout << "[Setup] Reuse existing DPF tables (skip upload)." << endl;
    }

    for (int i = 0; i < reps; i++) {
        INIT_TIMER;
        START_TIMER;
        uint128_t agg = client->AggQuery(q.agg_table_id, q);
        cout << "agg = " << agg << endl;
        uint32_t t = STOP_TIMER_();
        // 与 VB 路径一致，显式输出单次 query 的 full RTT。
        cout << "------------------------------------" << endl;
        cout << "[STOPPING TIMER] Total RUNTIME of AggQuery full RTT finish: " << t << " millisec " << endl;
        times.push_back(t);
    }

    return true;
}

bool dpfThroughput(QueryClient *client, int numBuckets, int windowSize, int numConds, vector<uint32_t> &times, int numAppends, int numSearches, int seconds) {
    QueryObj q;
    q.agg_table_id = "test_vals";
    vector<Condition> conds;
    for (int i = 0; i < numConds; i++) {
        Condition cond;
        cond.table_id = "test_dpf";
        cond.cond_type = POINT_COND;
        cond.x = 1;
        conds.push_back(cond);
    }
    Expression expr;
    expr.op_type = numConds == 1 ? NO_OP : AND_OP;
    vector<Expression> emptyExprs;
    expr.exprs = emptyExprs;
    expr.conds = conds;
    q.expr = &expr;

    vector<uint128_t> dataVals(windowSize, (uint128_t)1);
    vector<uint32_t> dcfVals(windowSize, (uint32_t)1);

    if (g_send_table) {
        client->AddValList(string("test_vals"), windowSize, dataVals);
        client->AddDPFTable(string("test_dpf"), windowSize, numBuckets, dcfVals);
    } else {
        client->RegisterDPFTableMeta(string("test_dpf"), (uint32_t)windowSize, (uint32_t)numBuckets);
        cout << "[Setup] Reuse existing DPF tables (skip upload)." << endl;
    }

    uint32_t totalMs = 0.0;
    
    while (totalMs < seconds * 1000) {
        for (int j = 0; j < numSearches && totalMs < seconds * 1000; j++) {
            INIT_TIMER;
            START_TIMER;
            uint128_t agg = client->AggQuery(q.agg_table_id, q);
            uint32_t time = STOP_TIMER_();
            times.push_back(time);
            totalMs += time;
        } for (int j = 0; j < numAppends && totalMs < seconds * 1000; j++) {
            INIT_TIMER;
            START_TIMER;
            client->RunDPFUpdate("test_dpf", 0, 1);
            uint32_t time = STOP_TIMER_();
            times.push_back(time);
            totalMs += time;
        }
    }

    return true;
}



bool dcfAggTest(QueryClient *client, int numBuckets, int windowSize, int numConds, int reps, uint32_t dcf_range_left, uint32_t dcf_range_right, vector<uint32_t> &times) {
    QueryObj q;
    q.agg_table_id = "test_vals";
    vector<Condition> conds;
    for (int i = 0; i < numConds; i++) {
        Condition cond;
        cond.table_id = "test_dcf";
        cond.cond_type = RANGE_COND;
        cond.left_x = dcf_range_left;
        cond.right_x = dcf_range_right;
        conds.push_back(cond);
    }
    Expression expr;
    expr.op_type = numConds == 1 ? NO_OP : AND_OP;
    vector<Expression> emptyExprs;
    expr.exprs = emptyExprs;
    expr.conds = conds;
    q.expr = &expr;
    cout << "finished making query object" << endl;

    vector<uint128_t> dataVals(windowSize, (uint128_t)1);
    vector<uint32_t> dcfVals(windowSize, (uint32_t)1);

    if (g_send_table) {
        client->AddValList(string("test_vals"), windowSize, dataVals);
        client->AddDCFTable(string("test_dcf"), windowSize, numBuckets, dcfVals);
        cout << "finished setup" << endl;
    } else {
        client->RegisterDCFTableMeta(string("test_dcf"), (uint32_t)windowSize, (uint32_t)numBuckets);
        cout << "[Setup] Reuse existing DCF tables (skip upload)." << endl;
    }

    for (int i = 0; i < reps; i++) {
        INIT_TIMER;
        START_TIMER;
        uint128_t agg = client->AggQuery(q.agg_table_id, q);
        cout << "agg = " << agg << endl;
        uint32_t t = STOP_TIMER_();
        cout << "------------------------------------" << endl;
        cout << "[STOPPING TIMER] Total RUNTIME of AggQuery full RTT finish: " << t << " millisec " << endl;
        times.push_back(t);
    }

    return true;
}

bool dcfThroughput(QueryClient *client, int numBuckets, int windowSize, int numConds, uint32_t dcf_range_left, uint32_t dcf_range_right, vector<uint32_t> &times, int numAppends, int numSearches, int seconds) {
    QueryObj q;
    q.agg_table_id = "test_vals";
    vector<Condition> conds;
    for (int i = 0; i < numConds; i++) {
        Condition cond;
        cond.table_id = "test_dcf";
        cond.cond_type = RANGE_COND;
        cond.left_x = dcf_range_left;
        cond.right_x = dcf_range_right;
        conds.push_back(cond);
    }
    Expression expr;
    expr.op_type = numConds == 1 ? NO_OP : AND_OP;
    vector<Expression> emptyExprs;
    expr.exprs = emptyExprs;
    expr.conds = conds;
    q.expr = &expr;
    cout << "finished making query object" << endl;

    vector<uint128_t> dataVals(windowSize, (uint128_t)1);
    vector<uint32_t> dcfVals(windowSize, (uint32_t)1);

    if (g_send_table) {
        client->AddValList(string("test_vals"), windowSize, dataVals);
        client->AddDCFTable(string("test_dcf"), windowSize, numBuckets, dcfVals);
        cout << "finished setup" << endl;
    } else {
        client->RegisterDCFTableMeta(string("test_dcf"), (uint32_t)windowSize, (uint32_t)numBuckets);
        cout << "[Setup] Reuse existing DCF tables (skip upload)." << endl;
    }
    uint32_t totalMs = 0.0;
    
    while (totalMs < seconds * 1000) {
        for (int j = 0; j < numSearches && totalMs < seconds * 1000; j++) {
            INIT_TIMER;
            START_TIMER;
            uint128_t agg = client->AggQuery(q.agg_table_id, q);
            uint32_t time = STOP_TIMER_();
            times.push_back(time);
            totalMs += time;
        } for (int j = 0; j < numAppends && totalMs < seconds * 1000; j++) {
            INIT_TIMER;
            START_TIMER;
            client->RunDCFUpdate("test_dcf", 0, 1);
            uint32_t time = STOP_TIMER_();
            times.push_back(time);
            totalMs += time;
        }
    }

    return true;
}



void aggTreeTest(QueryClient *client, int depth, int reps, vector <uint32_t> &times) {
    map<uint64_t, uint128_t> aggTreeData;
    int left_x = 6;
    string table_id = "test_aggtree";
    for (uint64_t i = 1; i < (1 << (depth - 1)); i++) {
        uint128_t one = 1;
        aggTreeData[i+1] = one;
    }

    if (g_send_table) {
        client->AddAggTree(table_id, sum, depth, aggTreeData);
    } else {
        cout << "[Setup] Reuse existing AggTree (skip upload)." << endl;
    }
    for (int i = 0; i < reps; i++) {
        INIT_TIMER;
        START_TIMER;
        uint128_t *ret;
        uint128_t *ret_r;
        client->AggTreeQuery(table_id, left_x, 1, &ret, &ret_r);
        times.push_back(STOP_TIMER_());
    }
}

void aggTreeThroughput(QueryClient *client, int depth, int reps, vector <uint32_t> &times, int numAppends, int numSearches, int seconds) {
    map<uint64_t, uint128_t> aggTreeData;
    int left_x = 6;
    string table_id = "test_aggtree";
    for (uint64_t i = 1; i < (1 << (depth - 1)); i++) {
        uint128_t one = 1;
        aggTreeData[i+1] = one;
    }
    uint32_t totalMs = 0;
    if (g_send_table) {
        client->AddAggTree(table_id, sum, depth, aggTreeData);
    } else {
        cout << "[Setup] Reuse existing AggTree (skip upload)." << endl;
    }

    while (totalMs < seconds * 1000) {
        for (int j = 0; j < numSearches && totalMs < seconds * 1000; j++) {
            INIT_TIMER;
            START_TIMER;
            uint128_t *ret;
            uint128_t *ret_r;
            client->AggTreeQuery(table_id, left_x, 1, &ret, &ret_r);
            uint32_t time = STOP_TIMER_();
            times.push_back(time);
            totalMs += time;
        } for (int j = 0; j < numAppends && totalMs < seconds * 1000; j++) {
            INIT_TIMER;
            START_TIMER;
            client->AggTreeAppend(table_id, -1, 1);
            uint32_t time = STOP_TIMER_();
            times.push_back(time);
            totalMs += time;
        }
    }
}

int main(int argc, char *argv[]) {
    ifstream config_stream(argv[1]);
    json config;
    config_stream >> config;

    vector<shared_ptr<grpc::Channel>> channels;
    for (int i = 0; i < NUM_SERVERS; i++) {
        shared_ptr<grpc::Channel> channel = grpc::CreateChannel(config[ADDRS][i], grpc::InsecureChannelCredentials());
        channels.push_back(channel);
    }

    // QueryClient *client = new QueryClient(channels, config[MALICIOUS]);
    auto client = std::make_unique<QueryClient>(channels, config[MALICIOUS]);

    int logNumBuckets = config[LOG_NUM_BUCKETS];
    int logBlockNum = config.contains(LOG_BLOCK_NUM) ? (int)config[LOG_BLOCK_NUM] : (logNumBuckets / 2);
    int logWindowSize = config[LOG_WINDOW_SZ];
    int numBuckets = 1 << logNumBuckets;
    int windowSize = 1 << logWindowSize;
    int blockNum = 1 << logBlockNum;
    bool vbIsPoint = config.contains(VB_IS_POINT) ? (bool)config[VB_IS_POINT] : true;
    uint32_t vbPointX = config.contains(VB_POINT_X) ? (uint32_t)config[VB_POINT_X] : 1;
    uint32_t vbRangeLeft = config.contains(VB_RANGE_LEFT) ? (uint32_t)config[VB_RANGE_LEFT] : 0;
    uint32_t vbRangeRight = config.contains(VB_RANGE_RIGHT) ? (uint32_t)config[VB_RANGE_RIGHT] : 3;
    bool boIsPoint = config.contains(BO_IS_POINT) ? (bool)config[BO_IS_POINT] : true;
    uint32_t boPointX = config.contains(BO_POINT_X) ? (uint32_t)config[BO_POINT_X] : 1;
    uint32_t boRangeLeft = config.contains(BO_RANGE_LEFT) ? (uint32_t)config[BO_RANGE_LEFT] : 0;
    uint32_t boRangeRight = config.contains(BO_RANGE_RIGHT) ? (uint32_t)config[BO_RANGE_RIGHT] : 3;
    uint32_t dcfRangeLeft = config.contains(DCF_RANGE_LEFT) ? (uint32_t)config[DCF_RANGE_LEFT] : 8;
    uint32_t dcfRangeRight = config.contains(DCF_RANGE_RIGHT) ? (uint32_t)config[DCF_RANGE_RIGHT] : 4;
    if (vbPointX >= (uint32_t)numBuckets) {
        throw std::invalid_argument("vb_point_x out of numBuckets range.");
    }
    if (vbRangeLeft >= (uint32_t)numBuckets || vbRangeRight >= (uint32_t)numBuckets) {
        throw std::invalid_argument("vb_range_left/right out of numBuckets range.");
    }
    if (boPointX >= (uint32_t)numBuckets) {
        throw std::invalid_argument("bo_point_x out of numBuckets range.");
    }
    if (boRangeLeft >= (uint32_t)numBuckets || boRangeRight >= (uint32_t)numBuckets) {
        throw std::invalid_argument("bo_range_left/right out of numBuckets range.");
    }
    if (dcfRangeLeft >= (uint32_t)numBuckets || dcfRangeRight >= (uint32_t)numBuckets) {
        throw std::invalid_argument("dcf_range_left/right out of numBuckets range.");
    }
    cout << "Num buckets: 2^" << logNumBuckets << " = " << numBuckets << endl;
    cout << "Window size: 2^" << logWindowSize << " = " << windowSize << endl;
    cout << "Block num: 2^" << logBlockNum << " = " << blockNum << endl;
    cout << "VB mode: " << (vbIsPoint ? "point" : "range") << endl;
    cout << "VB point x: " << vbPointX << endl;
    cout << "VB range: [" << vbRangeLeft << ", " << vbRangeRight << "]" << endl;
    cout << "BO mode: " << (boIsPoint ? "point" : "range") << endl;
    cout << "BO point x: " << boPointX << endl;
    cout << "BO range: [" << boRangeLeft << ", " << boRangeRight << "]" << endl;
    cout << "DCF range: [" << dcfRangeLeft << ", " << dcfRangeRight << "]" << endl;
    int numSearches = config[NUM_SEARCHES];
    int numAppends = config[NUM_APPENDS];
    int seconds = config[SECONDS];
    int numAnds = config[NUM_ANDS];
    int reps = config[REPS];
    g_send_table = config.contains(SEND_TABLE) ? (bool)config[SEND_TABLE] : true;
    cout << "Send table this run: " << (g_send_table ? "true" : "false") << endl;
    vector<uint32_t> times;
    const string queryType = config[TYPE];
    unordered_map<string, function<void()>> handlers;
    handlers["point"] = [&]() { dpfAggTest(client.get(), numBuckets, windowSize, numAnds, reps, times); };
    handlers["range"] = [&]() { dcfAggTest(client.get(), numBuckets, windowSize, numAnds, reps, dcfRangeLeft, dcfRangeRight, times); };
    handlers["point-throughput"] = [&]() { dpfThroughput(client.get(), numBuckets, windowSize, numAnds, times, numAppends, numSearches, seconds); };
    handlers["range-throughput"] = [&]() { dcfThroughput(client.get(), numBuckets, windowSize, numAnds, dcfRangeLeft, dcfRangeRight, times, numAppends, numSearches, seconds); };
    handlers["tree"] = [&]() { aggTreeTest(client.get(), config[DEPTH], reps, times); };
    handlers["tree-throughput"] = [&]() { aggTreeThroughput(client.get(), config[DEPTH], reps, times, numAppends, numSearches, seconds); };

    handlers["vb-non-fss-point"] = [&]() { VBNonFSSPointAggTest(client.get(), windowSize, numBuckets, numAnds, reps, vbPointX, times); };
    handlers["dpf-vb-non-fss-point"] = handlers["vb-non-fss-point"];
    handlers["vb-non-fss-range"] = [&]() { VBNonFSSRangeAggTest(client.get(), windowSize, numBuckets, numAnds, reps, vbRangeLeft, vbRangeRight, times); };
    handlers["dpf-vb-non-fss-range"] = handlers["vb-non-fss-range"];

    handlers["vb-fss-point"] = [&]() { VBFSSPointAggTest(client.get(), windowSize, numBuckets, logBlockNum, numAnds, reps, vbPointX, times); };
    handlers["dpf-vb-fss-point"] = handlers["vb-fss-point"];
    handlers["vb-fss-range"] = [&]() { VBFSSRangeAggTest(client.get(), windowSize, numBuckets, logBlockNum, numAnds, reps, vbRangeLeft, vbRangeRight, times); };
    handlers["dpf-vb-fss-range"] = handlers["vb-fss-range"];

    handlers["bo-non-fss-point"] = [&]() { boNonFSSPointAggTest(client.get(), windowSize, numBuckets, logBlockNum, numAnds, reps, boPointX, times); };
    handlers["bo-non-fss-range"] = [&]() { boNonFSSRangeAggTest(client.get(), windowSize, numBuckets, logBlockNum, numAnds, reps, boRangeLeft, boRangeRight, times); };
    handlers["bo-fss-point"] = [&]() { boFSSPointAggTest(client.get(), windowSize, numBuckets, logBlockNum, numAnds, reps, boPointX, times); };
    handlers["bo-fss-range"] = [&]() { boFSSRangeAggTest(client.get(), windowSize, numBuckets, logBlockNum, numAnds, reps, boRangeLeft, boRangeRight, times); };

    handlers["vb-non-fss"] = [&]() {
        if (vbIsPoint) {
            VBNonFSSPointAggTest(client.get(), windowSize, numBuckets, numAnds, reps, vbPointX, times);
        } else {
            VBNonFSSRangeAggTest(client.get(), windowSize, numBuckets, numAnds, reps, vbRangeLeft, vbRangeRight, times);
        }
    };
    handlers["dpf-vb-non-fss"] = handlers["vb-non-fss"];

    handlers["vb-fss"] = [&]() {
        if (vbIsPoint) {
            VBFSSPointAggTest(client.get(), windowSize, numBuckets, logBlockNum, numAnds, reps, vbPointX, times);
        } else {
            VBFSSRangeAggTest(client.get(), windowSize, numBuckets, logBlockNum, numAnds, reps, vbRangeLeft, vbRangeRight, times);
        }
    };
    handlers["dpf-vb-fss"] = handlers["vb-fss"];

    handlers["bo-non-fss"] = [&]() {
        if (boIsPoint) {
            boNonFSSPointAggTest(client.get(), windowSize, numBuckets, logBlockNum, numAnds, reps, boPointX, times);
        } else {
            boNonFSSRangeAggTest(client.get(), windowSize, numBuckets, logBlockNum, numAnds, reps, boRangeLeft, boRangeRight, times);
        }
    };
    handlers["bo-fss"] = [&]() {
        if (boIsPoint) {
            boFSSPointAggTest(client.get(), windowSize, numBuckets, logBlockNum, numAnds, reps, boPointX, times);
        } else {
            boFSSRangeAggTest(client.get(), windowSize, numBuckets, logBlockNum, numAnds, reps, boRangeLeft, boRangeRight, times);
        }
    };

    auto it = handlers.find(queryType);
    if (it == handlers.end()) {
        throw invalid_argument("Unknown query_type: " + queryType);
    }
    it->second();

    string expDir = config[EXP_DIR];
    ofstream file(expDir + "/results.dat");
    if (file.is_open()) {
        for (int i = 0; i < times.size(); i++) {
            file << to_string(i) << " " << to_string(times[i]) << endl;
            std::cout << to_string(i) << " " << to_string(times[i]) << std::endl;
        }
    }

    return 0;
}
