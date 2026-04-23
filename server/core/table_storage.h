#ifndef WALDO_SERVER_CORE_TABLE_STORAGE_H_
#define WALDO_SERVER_CORE_TABLE_STORAGE_H_

#include <string>
#include <vector>

#include "../../secure-indices/core/common.h"

using namespace std;
using namespace osuCrypto;

class OneHotTable {
public:
    string table_id;
    uint32_t windowSize;
    uint32_t numBuckets;
    bool hasBlockLayout;
    uint32_t logBlockNum;
    uint32_t blockNum;
    uint32_t blockSize;
    vector<vector<uint128_t>> table;

    OneHotTable(string table_id, uint32_t windowSize, uint32_t numBuckets);
    OneHotTable(string table_id, uint32_t windowSize, uint32_t numBuckets, uint32_t logBlockNum);
    void oneHotTableUpdateRank(int rank, const uint128_t *rank_data);
    void setBlockLayout(uint32_t logBlockNum_);
    const uint128_t *getBlockDataPtr(uint32_t row, uint32_t blockIdx) const;
    uint128_t *getBlockDataPtrMutable(uint32_t row, uint32_t blockIdx);
};

class BOIndexTable {
public:
    string table_id;
    uint32_t windowSize;
    uint32_t blockNum;
    vector<vector<uint128_t>> table;

    BOIndexTable(string table_id, uint32_t windowSize, uint32_t blockNum);
    void updateRank(int rank, const uint128_t *rank_data);
};

class BOOffsetTable {
public:
    string table_id;
    uint32_t windowSize;
    uint32_t blockSize;
    vector<vector<uint128_t>> table;

    BOOffsetTable(string table_id, uint32_t windowSize, uint32_t blockSize);
    void updateRank(int rank, const uint128_t *rank_data);
};

struct BOTableMeta {
    uint32_t windowSize;
    uint32_t numBuckets;
    uint32_t logBlockNum;
    uint32_t blockNum;
    uint32_t blockSize;
};

#endif  // WALDO_SERVER_CORE_TABLE_STORAGE_H_

