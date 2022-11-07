#pragma once

#include <string>

#include "leveldb/comparator.h"
#include "leveldb/slice.h"

class Code42Comparator : public leveldb::Comparator {
public:
    Code42Comparator() { }

    virtual const char* Name() const;

    virtual int Compare(const leveldb::Slice& a, const leveldb::Slice& b) const;

    void FindShortestSeparator(std::string*, const leveldb::Slice&) const;
    void FindShortSuccessor(std::string*) const;
};