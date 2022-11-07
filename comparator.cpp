#include "comparator.h"

const char* Code42Comparator::Name() const {
    return "code42.archive.v2.virtual.table";
}

int Code42Comparator::Compare(const leveldb::Slice& a, const leveldb::Slice& b) const {
    return a.compare(b);
}

void Code42Comparator::FindShortestSeparator(std::string*, const leveldb::Slice&) const {
}

void Code42Comparator::FindShortSuccessor(std::string*) const {
}