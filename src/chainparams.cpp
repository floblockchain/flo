// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) Flo Developers 2013-2018
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const std::string strFloData, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 2;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;
    txNew.strFloData = strFloData;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Slashdot - 17 June 2013 - Saudi Arabia Set To Ban WhatsApp, Skype";
    const std::string strFloData = "text:Florincoin genesis block";
    const CScript genesisOutputScript = CScript() << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, strFloData, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 800000;
        consensus.BIP34Height = 1679161;
        consensus.BIP34Hash = uint256S("490a10507efe42b89104408787088b7c43310cc230310201b5f57dac6f513b8b");
        consensus.BIP65Height = 1679161; // 490a10507efe42b89104408787088b7c43310cc230310201b5f57dac6f513b8b
        consensus.BIP66Height = 1679161; // 490a10507efe42b89104408787088b7c43310cc230310201b5f57dac6f513b8b
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 6048; // 75% of 8064
        consensus.nMinerConfirmationWindow = 8064;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1522562766; // April 1st, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1554098766; // April 1st, 2019

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1522562766; // April 1st, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1554098766; // April 1st, 2019

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000000050b6f9f1c2494ad8"); // 3,000,000

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x5ad3a302e3b1c681f0177411384ea03ee595a80a530c23a61f22839fae948e7f"); // 3,000,000

        // Difficulty adjustments
        consensus.nPowTargetSpacing = 40; // 40s block time
        // V1
        consensus.nTargetTimespan_Version1 = 60 * 60;
        consensus.nInterval_Version1 = consensus.nTargetTimespan_Version1 / consensus.nPowTargetSpacing;
        consensus.nMaxAdjustUp_Version1 = 75;
        consensus.nMaxAdjustDown_Version1 = 300;
        consensus.nAveragingInterval_Version1 = consensus.nInterval_Version1;
        // V2
        consensus.nHeight_Difficulty_Version2 = 208440;
        consensus.nInterval_Version2 = 15;
        consensus.nMaxAdjustDown_Version2 = 300;
        consensus.nMaxAdjustUp_Version2 = 75;
        consensus.nAveragingInterval_Version2 = consensus.nInterval_Version2;
        // V3
        consensus.nHeight_Difficulty_Version3 = 426000;
        consensus.nInterval_Version3 = 1;
        consensus.nMaxAdjustDown_Version3 = 3;
        consensus.nMaxAdjustUp_Version3 = 2;
        consensus.nAveragingInterval_Version3 = 6;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfd;
        pchMessageStart[1] = 0xc0;
        pchMessageStart[2] = 0xa5;
        pchMessageStart[3] = 0xf1;
        nDefaultPort = 7312;
        nPruneAfterHeight = 100000;
        nNlrLimit = 100; // 100 * ~40s = ~66 minutes

        genesis = CreateGenesisBlock(1371488396, 1000112548, 0x1e0ffff0, 1, 100 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x09c7781c9df90708e278c35d38ea5c9041d7ecfcdd1c56ba67274b7cff3e1cea"));
        assert(genesis.hashMerkleRoot == uint256S("0x730f0c8ddc5a592d5512566890e2a73e45feaa6748b24b849d1c29a7ab2b2300"));

        // Note that of those with the service bits flag, most only support a subset of possible options
        vSeeds.emplace_back("seed1.florincoin.org", false);
        vSeeds.emplace_back("node.oip.fun", false);
        vSeeds.emplace_back("flodns.oip.li", false);
        vSeeds.emplace_back("flodns.oip.fun", false);
        vSeeds.emplace_back("flodns.seednode.net", false);

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,35);  //F
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,8);   //4
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,94); //e or f
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,163); //R
        base58Prefixes[SECRET_KEY2] =    std::vector<unsigned char>(1,176); //T
        base58Prefixes[EXT_PUBLIC_KEY] = {0x01, 0x34, 0x40, 0x6b}; //Fpub, Fprv for mainnet
        base58Prefixes[EXT_SECRET_KEY] = {0x01, 0x34, 0x3c, 0x31};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData) {
            {
                {      0, uint256S("0x09c7781c9df90708e278c35d38ea5c9041d7ecfcdd1c56ba67274b7cff3e1cea")},
                {   8002, uint256S("0x73bc3b16d99bbf797f396c9532f80c3b73bb21304280de2efbc5edcb75739234")},
                {  18001, uint256S("0x5a7a4821aa4fc7ee3dea2f8319e9fa4d991a8c6762e79cb624c64e4cf1031582")},
                {  38002, uint256S("0x4962437c6d0a450f44c1e40cd38ff220f8122af1517e1329f1abd07fb7791e40")},
                { 160002, uint256S("0x478d381c92298614c3a05fb934a4fffc4d3e5b573efbba9b3e8b2ce8d26a0f8f")},
                { 208001, uint256S("0x2bb3f8b2d5081aefa0af9f5d8de42bd73a5d89eebf78aa7421cd63dc40a56d4c")},
                { 270001, uint256S("0x74988a3179ae6bbc5986e63f71bafc855202502b07e4d9331015eee82df80860")},
                { 290036, uint256S("0x145994381e5e4f0e5674adc1ace9a03b670838792f6bd6b650c80466453c2da3")},
                { 344665, uint256S("0x40fe36d8dec357aa529b6b1d99b2989a37ed8c7b065a0e3345cd15a751b9c1ad")},
                { 400236, uint256S("0xf9a4b8e21d410539e45ff3f11c28dee8966de7edffc45fd02dd1a5f4e7d4ef38")},
                { 415000, uint256S("0x16ef8ab98a7300039a5755d5bdc00e31dada9d2f1c440ff7928f43c4ea41c0a8")},
                { 420937, uint256S("0x48a75e4687021ec0dda2031439de50b61933e197a4e1a1185d131cc2b59b8444")},
                { 425606, uint256S("0x62c8d811b1a49f6fdaffded704dc48b1c98d6f8dd736d8afb96c9b097774a85e")},
                { 508694, uint256S("0x65cde197e9118e5164c4dcdcdc6fcfaf8c0de605d569cefd56aa220e7739da6a")},
                { 696454, uint256S("0x8cfb75684405e22f8f69522ec11f1e5206758e37f25db13880548f69fe6f1976")},
                { 955000, uint256S("0xb5517a50aee6af59eb0ab4ee3262bcbaf3f6672b9301cdd3302e4bab491e7526")},
                {1505017, uint256S("0xd38b306850bb26a5c98400df747d4391bb4e359e95e20dc79b50063ed3c5bfa7")},
                {1678879, uint256S("0x1e874e2852e8dfb3553f0e6c02dcf70e9f5697effa31385d25a3c88fe26676fc")},
                {1678909, uint256S("0x4c5a1040e337a542e6717904c8346bd72151fc34c390dff7b5cf23dcedc5058a")},
                {1679162, uint256S("0xb32c64fb80a4196ff3e1be883db10629e1d7cd27c00ef0b5d1fe54af481fc10f")},
                {1796633, uint256S("0xc2da8b936a7f2c0de02aa0c6c45f3d971ebad78655255a945b0e60b62f27d445")},
                {2094558, uint256S("0x946616c88286f32bfac15868456d87a86f8611e1f9b56594b81e46831ce43f81")},
                {2532181, uint256S("0xcacd5149aaed1088ae1db997a741210b0525e941356104120f182f3159931c79")},
                {3000000, uint256S("0x5ad3a302e3b1c681f0177411384ea03ee595a80a530c23a61f22839fae948e7f")},
            }
        };

        chainTxData = ChainTxData{
            // Data as of block 5ad3a302e3b1c681f0177411384ea03ee595a80a530c23a61f22839fae948e7f  (height 3,000,000).
            1538389345, // * UNIX timestamp of last known number of transactions
            4563023,    // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
        	0.03  // * estimated number of transactions per second after that timestamp
        };

    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 800000;
        consensus.BIP34Height = 33600;  //already activated on main so activate here too
        consensus.BIP34Hash = uint256S("4ac31d938531317c065405a9b23478c8c99204ff17fc294cb09821e2c2b42e65");
        consensus.BIP65Height = 33600; // 4ac31d938531317c065405a9b23478c8c99204ff17fc294cb09821e2c2b42e65
        consensus.BIP66Height = 33600; // 4ac31d938531317c065405a9b23478c8c99204ff17fc294cb09821e2c2b42e65
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 600; // 75% of 800
        consensus.nMinerConfirmationWindow = 800;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1483228800; // January 1, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1530446401; // July 1, 2018  FLO future date

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1483228800; // January 1, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1530446401;  // July 1, 2018  FLO future date

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000003dd47d3172"); // 230,000

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0xc2e6451240a580c3bfa5ddbfad1b001f8655e7c51d5c32c123e16f69c2d2b539"); // 230,000

        // Difficulty adjustments
        consensus.nPowTargetSpacing = 40; // 40s block time
        // V1
        consensus.nTargetTimespan_Version1 = 60 * 60;
        consensus.nInterval_Version1 = consensus.nTargetTimespan_Version1 / consensus.nPowTargetSpacing;
        consensus.nMaxAdjustUp_Version1 = 75;
        consensus.nMaxAdjustDown_Version1 = 300;
        consensus.nAveragingInterval_Version1 = consensus.nInterval_Version1;
        // V2
        consensus.nHeight_Difficulty_Version2 = 50000;
        consensus.nInterval_Version2 = 15;
        consensus.nMaxAdjustDown_Version2 = 300;
        consensus.nMaxAdjustUp_Version2 = 75;
        consensus.nAveragingInterval_Version2 = consensus.nInterval_Version2;
        // V3
        consensus.nHeight_Difficulty_Version3 = 60000;
        consensus.nInterval_Version3 = 1;
        consensus.nMaxAdjustDown_Version3 = 3;
        consensus.nMaxAdjustUp_Version3 = 2;
        consensus.nAveragingInterval_Version3 = 6;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfd;
        pchMessageStart[1] = 0xc0;
        pchMessageStart[2] = 0x5a;
        pchMessageStart[3] = 0xf2;
        nDefaultPort = 17312;
        nPruneAfterHeight = 100000;
        nNlrLimit = 50; // 50 * ~40s = ~33 minutes

        genesis = CreateGenesisBlock(1371387277, 1000580675, 0x1e0ffff0, 1, 100 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x9b7bc86236c34b5e3a39367c036b7fe8807a966c22a7a1f0da2a198a27e03731"));
        assert(genesis.hashMerkleRoot == uint256S("0x730f0c8ddc5a592d5512566890e2a73e45feaa6748b24b849d1c29a7ab2b2300"));

        vFixedSeeds.clear();
        vSeeds.clear();

        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("testnet.oip.fun", false);

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,115);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,198);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,58);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[SECRET_KEY2] =    std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x01, 0x34, 0x40, 0xe2};  //Fput, Fprt for testnet
        base58Prefixes[EXT_SECRET_KEY] = {0x01, 0x34, 0x3c, 0x23};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData) {
            {
                {2056, uint256S("0xd3334db071731beaa651f10624c2fea1a5e8c6f9e50f0e602f86262938374148")},
                {230000, uint256S("0xc2e6451240a580c3bfa5ddbfad1b001f8655e7c51d5c32c123e16f69c2d2b539")},
            }
        };

        chainTxData = ChainTxData{
            // flo: Data as of block c2e6451240a580c3bfa5ddbfad1b001f8655e7c51d5c32c123e16f69c2d2b539 (height 230,000)
            1538135261, 			// * UNIX timestamp of last known number of transactions
            265211,					// * total number of transactions between genesis and that timestamp
            0.01                  	// * estimated number of transactions per second after that timestamp
        };

    }
};

/**
 * Regression test
 * https://bitcoin.org/en/developer-examples#regtest-mode
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        // Difficulty adjustments
        consensus.nPowTargetSpacing = 40; // 40s block time
        // V1
        consensus.nTargetTimespan_Version1 = 60 * 60;
        consensus.nInterval_Version1 = consensus.nTargetTimespan_Version1 / consensus.nPowTargetSpacing;
        consensus.nMaxAdjustUp_Version1 = 75;
        consensus.nMaxAdjustDown_Version1 = 300;
        consensus.nAveragingInterval_Version1 = consensus.nInterval_Version1;
        // V2
        consensus.nHeight_Difficulty_Version2 = 208440;
        consensus.nInterval_Version2 = 15;
        consensus.nMaxAdjustDown_Version2 = 300;
        consensus.nMaxAdjustUp_Version2 = 75;
        consensus.nAveragingInterval_Version2 = consensus.nInterval_Version2;
        // V3
        consensus.nHeight_Difficulty_Version3 = 426000;
        consensus.nInterval_Version3 = 1;
        consensus.nMaxAdjustDown_Version3 = 3;
        consensus.nMaxAdjustUp_Version3 = 2;
        consensus.nAveragingInterval_Version3 = 6;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 17412;
        nPruneAfterHeight = 1000;
        nNlrLimit = 10;

        genesis = CreateGenesisBlock(1371387277, 0, 0x207fffff, 1, 100 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0xec42fa26ca6dcb1103b59a1d24b161935ea4566f8d5736db8917d5b9a8dee0d7"));
        assert(genesis.hashMerkleRoot == uint256S("0x730f0c8ddc5a592d5512566890e2a73e45feaa6748b24b849d1c29a7ab2b2300"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,115);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,198);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,58);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[SECRET_KEY2] =    std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true; 

//        checkpointData = (CCheckpointData) {
//            {
//                {0, uint256S("530827f38f93b43ed12af0b3ad25a288dc02ed74d6d7857862df51fc56c416f9")},
//            }
//        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}
