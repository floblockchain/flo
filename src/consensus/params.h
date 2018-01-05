// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include "uint256.h"
#include <map>
#include <string>

namespace Consensus {

enum DeploymentPos
{
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_CSV, // Deployment of BIP68, BIP112, and BIP113.
    DEPLOYMENT_SEGWIT, // Deployment of BIP141, BIP143, and BIP147.
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in versionbits.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit;
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime;
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    uint256 nMinimumChainWork;
    uint256 defaultAssumeValid;

    // FLO: Difficulty adjustment forks.
    int64_t TargetTimespan(int height) const {
        // V1
        if (height < nHeight_Difficulty_Version2)
            return nTargetTimespan_Version1;
        // V2
        if (height < nHeight_Difficulty_Version3)
            return nInterval_Version2 * nPowTargetSpacing;
        // V3
        return nInterval_Version3 * nPowTargetSpacing;
    }

    int64_t DifficultyAdjustmentInterval(int height) const {
        // V1
        if (height < nHeight_Difficulty_Version2)
            return nInterval_Version1;
        // V2
        if (height < nHeight_Difficulty_Version3)
            return nInterval_Version2;
        // V3
        return nInterval_Version3;
    }

    int64_t MaxActualTimespan(int height) const {
        const int64_t averagingTargetTimespan = AveragingInterval(height) * nPowTargetSpacing;
        // V1
        if (height < nHeight_Difficulty_Version2)
            return averagingTargetTimespan * (100 + nMaxAdjustDown_Version1) / 100;
        // V2
        if (height < nHeight_Difficulty_Version3)
            return averagingTargetTimespan * (100 + nMaxAdjustDown_Version2) / 100;
        // V3
        return averagingTargetTimespan * (100 + nMaxAdjustDown_Version3) / 100;
    }

    int64_t MinActualTimespan(int height) const {
        const int64_t averagingTargetTimespan = AveragingInterval(height) * nPowTargetSpacing;
        // V1
        if (height < nHeight_Difficulty_Version2)
            return averagingTargetTimespan * (100 - nMaxAdjustUp_Version1) / 100;
        // V2
        if (height < nHeight_Difficulty_Version3)
            return averagingTargetTimespan * (100 - nMaxAdjustUp_Version2) / 100;
        // V3
        return averagingTargetTimespan * (100 - nMaxAdjustUp_Version3) / 100;
    }

    int64_t AveragingInterval(int height) const {
        // V1
        if (height < nHeight_Difficulty_Version2)
            return nAveragingInterval_Version1;
        // V2
        if (height < nHeight_Difficulty_Version3)
            return nAveragingInterval_Version2;
        // V3
        return nAveragingInterval_Version3;
    }

    // V1
    int64_t nTargetTimespan_Version1;
    int64_t nInterval_Version1;
    int64_t nMaxAdjustUp_Version1;
    int64_t nMaxAdjustDown_Version1;
    int64_t nAveragingInterval_Version1;

    // V2
    int64_t nHeight_Difficulty_Version2;
    int64_t nInterval_Version2;
    int64_t nMaxAdjustDown_Version2;
    int64_t nMaxAdjustUp_Version2;
    int64_t nAveragingInterval_Version2;

    // V3
    int64_t nHeight_Difficulty_Version3;
    int64_t nInterval_Version3;
    int64_t nMaxAdjustDown_Version3;
    int64_t nMaxAdjustUp_Version3;
    int64_t nAveragingInterval_Version3;

};
} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
