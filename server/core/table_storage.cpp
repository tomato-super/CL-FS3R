#include "table_storage.h"

#include <stdexcept>

OneHotTable::OneHotTable(string table_id, uint32_t windowSize, uint32_t numBuckets) :
    table_id(table_id),
    windowSize(windowSize),
    numBuckets(numBuckets),
    hasBlockLayout(false),
    logBlockNum(0),
    blockNum(0),
    blockSize(0) {
    table.assign(windowSize, vector<uint128_t>(numBuckets, 0));
}

OneHotTable::OneHotTable(string table_id, uint32_t windowSize, uint32_t numBuckets, uint32_t logBlockNum) :
    OneHotTable(table_id, windowSize, numBuckets) {
    setBlockLayout(logBlockNum);
}

void OneHotTable::oneHotTableUpdateRank(int rank, const uint128_t *rank_data) {
    if (rank < 0 || rank >= (int)table.size()) {
        throw std::out_of_range("Invalid rank!");
    }
    for (uint32_t i = 0; i < numBuckets; i++) {
        table[rank][i] = rank_data[i];
    }
}

void OneHotTable::setBlockLayout(uint32_t logBlockNum_) {
    if (logBlockNum_ >= 31) {
        throw std::invalid_argument("logBlockNum is too large for OneHotTable.");
    }
    uint32_t localBlockNum = 1u << logBlockNum_;
    if (localBlockNum == 0 || numBuckets == 0 || numBuckets % localBlockNum != 0) {
        throw std::invalid_argument("Invalid OneHotTable block layout.");
    }
    hasBlockLayout = true;
    logBlockNum = logBlockNum_;
    blockNum = localBlockNum;
    blockSize = numBuckets / blockNum;
}

const uint128_t *OneHotTable::getBlockDataPtr(uint32_t row, uint32_t blockIdx) const {
    if (!hasBlockLayout) {
        throw std::runtime_error("OneHotTable block layout is not initialized.");
    }
    if (row >= windowSize || blockIdx >= blockNum) {
        throw std::out_of_range("OneHotTable block access out of range.");
    }
    return table[row].data() + ((size_t)blockIdx * (size_t)blockSize);
}

uint128_t *OneHotTable::getBlockDataPtrMutable(uint32_t row, uint32_t blockIdx) {
    if (!hasBlockLayout) {
        throw std::runtime_error("OneHotTable block layout is not initialized.");
    }
    if (row >= windowSize || blockIdx >= blockNum) {
        throw std::out_of_range("OneHotTable block access out of range.");
    }
    return table[row].data() + ((size_t)blockIdx * (size_t)blockSize);
}

BOIndexTable::BOIndexTable(string table_id, uint32_t windowSize, uint32_t blockNum) :
    table_id(table_id), windowSize(windowSize), blockNum(blockNum) {
    table.assign(windowSize, vector<uint128_t>(blockNum, 0));
}

void BOIndexTable::updateRank(int rank, const uint128_t *rank_data) {
    if (rank < 0 || rank >= (int)table.size()) {
        throw std::out_of_range("Invalid BO index rank!");
    }
    for (uint32_t i = 0; i < blockNum; i++) {
        table[rank][i] = rank_data[i];
    }
}

BOOffsetTable::BOOffsetTable(string table_id, uint32_t windowSize, uint32_t blockSize) :
    table_id(table_id), windowSize(windowSize), blockSize(blockSize) {
    table.assign(windowSize, vector<uint128_t>(blockSize, 0));
}

void BOOffsetTable::updateRank(int rank, const uint128_t *rank_data) {
    if (rank < 0 || rank >= (int)table.size()) {
        throw std::out_of_range("Invalid BO offset rank!");
    }
    for (uint32_t i = 0; i < blockSize; i++) {
        table[rank][i] = rank_data[i];
    }
}

