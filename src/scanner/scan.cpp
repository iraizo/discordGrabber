#include "scan.h"


void scanner::FillShiftTable(const uint8_t* pPattern, size_t patternSize, uint8_t wildcard, size_t* bad_char_skip)
{
    size_t idx = 0;
    size_t last = patternSize - 1;

    // Get last wildcard position
    for (idx = last; idx > 0 && pPattern[idx] != wildcard; --idx);
    size_t diff = last - idx;
    if (diff == 0)
        diff = 1;

    // Prepare shift table
    for (idx = 0; idx <= UCHAR_MAX; ++idx)
        bad_char_skip[idx] = diff;
    for (idx = last - diff; idx < last; ++idx)
        bad_char_skip[pPattern[idx]] = last - idx;
}

/**
 * DarthTon's FindPattern implementation - the fastest (public) one available
 */
const void* scanner::Search(const uint8_t* pScanPos, size_t scanSize, const uint8_t* pPattern, size_t patternSize, uint8_t wildcard)
{
    size_t bad_char_skip[UCHAR_MAX + 1];
    const uint8_t* scanEnd = pScanPos + scanSize - patternSize;
    intptr_t last = static_cast<intptr_t>(patternSize) - 1;

    scanner::FillShiftTable(pPattern, patternSize, wildcard, bad_char_skip);

    // Search
    for (; pScanPos <= scanEnd; pScanPos += bad_char_skip[pScanPos[last]])
    {
        for (intptr_t idx = last; idx >= 0; --idx)
            if (pPattern[idx] != wildcard && pScanPos[idx] != pPattern[idx])
                goto skip;
            else if (idx == 0)
                return pScanPos;
    skip:;
    }

    return nullptr;
}