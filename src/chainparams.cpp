// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "key_io.h"
#include "main.h"
#include "crypto/equihash.h"

#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"
#include <inttypes.h>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    // To create a genesis block for a new chain which is Overwintered:
    //   txNew.nVersion = OVERWINTER_TX_VERSION
    //   txNew.fOverwintered = true
    //   txNew.nVersionGroupId = OVERWINTER_VERSION_GROUP_ID
    //   txNew.nExpiryHeight = <default value>
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 520617983 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nSolution = nSolution;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = genesis.BuildMerkleTree();
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database (and is in any case of zero value).
 *
 * >>> from pyblake2 import blake2s
 * >>> 'Zcash' + blake2s(b'The Economist 2016-10-29 Known unknown: Another crypto-currency is born. BTC#436254 0000000000000000044f321997f336d2908cf8c8d6893e88dbf067e2d949487d ETH#2521903 483039a6b6bd8bd05f0584f9a078d075e454925eb71c1f13eaff59b405a721bb DJIA close on 27 Oct 2016: 18,169.68').hexdigest()
 *
 * CBlock(hash=00040fe8, ver=4, hashPrevBlock=00000000000000, hashMerkleRoot=c4eaa5, nTime=1477641360, nBits=1f07ffff, nNonce=4695, vtx=1)
 *   CTransaction(hash=c4eaa5, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff071f0104455a6361736830623963346565663862376363343137656535303031653335303039383462366665613335363833613763616331343161303433633432303634383335643334)
 *     CTxOut(nValue=0.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: c4eaa5
 */
static CBlock CreateGenesisBlock(uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Zcash0b9c4eef8b7cc417ee5001e3500984b6fea35683a7cac141a043c42064835d34";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nSolution, nBits, nVersion, genesisReward);
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
void *chainparams_commandline(void *ptr);
#include "komodo_defs.h"

extern bool PARAMS_LOADED;
extern char ASSETCHAINS_SYMBOL[KOMODO_ASSETCHAIN_MAXLEN];
extern uint16_t ASSETCHAINS_P2PPORT,ASSETCHAINS_RPCPORT;
extern uint32_t ASSETCHAIN_INIT, ASSETCHAINS_MAGIC, ASSETCHAINS_ALGO, ASSETCHAINS_EQUIHASH, ASSETCHAINS_VERUSHASH;
extern int32_t VERUS_BLOCK_POSUNITS, ASSETCHAINS_LWMAPOS, ASSETCHAINS_SAPLING, ASSETCHAINS_OVERWINTER;
extern int64_t ASSETCHAINS_SUPPLY;
extern std::string VERUS_DEFAULT_ZADDR;

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

class CMainParams : public CChainParams {
public:
    CMainParams()
    {
        strNetworkID = "main";
        strCurrencyUnits = "LKYL";
        bip44CoinType = 133; // As registered in https://github.com/satoshilabs/slips/blob/master/slip-0044.md (ZCASH, should be VRSC)
        consensus.fCoinbaseMustBeProtected = false; // true this is only true wuth Verus and enforced after block 12800 (enforcement ending at solution V3)
        consensus.nSubsidySlowStartInterval = 20000;
        consensus.nPreBlossomSubsidyHalvingInterval = Consensus::PRE_BLOSSOM_HALVING_INTERVAL;
        consensus.nPostBlossomSubsidyHalvingInterval = Consensus::POST_BLOSSOM_HALVING_INTERVAL;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 4000;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.powAlternate = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        const size_t N = 200, K = 9;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        consensus.nEquihashN = N;
        consensus.nEquihashK = K;
        consensus.nPowAveragingWindow = 17;

        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPreBlossomPowTargetSpacing = Consensus::PRE_BLOSSOM_POW_TARGET_SPACING;
        consensus.nPostBlossomPowTargetSpacing = Consensus::POST_BLOSSOM_POW_TARGET_SPACING;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = boost::none;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170005;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nProtocolVersion = 170009;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("000000000000000000000000000000000000000000000000017e73a331fae01c");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xf9;
        pchMessageStart[1] = 0xee;
        pchMessageStart[2] = 0xe4;
        pchMessageStart[3] = 0x8d;
        nDefaultPort = 9270;
        nMinerThreads = 0;
        nPruneAfterHeight = 100000;

        // Lucky Lode launch genesis — DRAFT ceremony 2026-10-13, internal/genesis_grind.py
        // (runbook §1). Transcript: nTime=1791865812,
        // message="the coin you mine on whatever you already own.",
        // reward=0 to OP_RETURN "LuckyLode fair launch - no premine" (no premine),
        // nBits=0x1f00ffff, version=4, empty solution, null sapling root.
        // DRAFT: re-run the ceremony for final values; the asserts below are
        // the gate (a mismatched pin fails at startup, loudly).
        genesis = CreateGenesisBlock(
            "the coin you mine on whatever you already own.",
            CScript() << OP_RETURN << ParseHex("4c75636b794c6f64652066616972206c61756e6368202d206e6f207072656d696e65"),
            1791865812,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000007b38"),
            ParseHex(""),
            0x1f00ffff, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash(0);
        assert(consensus.hashGenesisBlock == uint256S("0x000042ebd0408abd6080b215a7fa63758378a1f92612401818aedc5da8e60d36"));
        assert(genesis.hashMerkleRoot == uint256S("0xe826780cb764461be27e590018df8caeeea2dbbeee5d7cd28724e039e4d216a5"));
        vFixedSeeds.clear();
        vSeeds.clear();
        // Lucky Lode: P2PKH addresses start with 'L' (48), P2SH with 'M' (50).
        // (Regtest keeps upstream {0},{5} for test compatibility; identity
        // prefix 102 is tracked separately for the LuckyID rebrand pass.)
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,48);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,50);
        base58Prefixes[IDENTITY_ADDRESS] = std::vector<unsigned char>(1,102);
        base58Prefixes[INDEX_ADDRESS] = std::vector<unsigned char>(1,137);
        base58Prefixes[QUANTUM_ADDRESS] = std::vector<unsigned char>(1,58);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,188);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        // guarantees the first two characters, when base58 encoded, are "zc"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {22,154};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVK"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAB,0xD3};
        // guarantees the first two characters, when base58 encoded, are "SK"
        base58Prefixes[ZCSPENDING_KEY] = {171,54};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zs";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviews";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivks";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-main";
        bech32HRPs[SAPLING_EXTENDED_FVK]         = "zxviews";

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        if ( pthread_create((pthread_t *)malloc(sizeof(pthread_t)),NULL,chainparams_commandline,(void *)&consensus) != 0 )
        {

        }
    }
};
static CMainParams mainParams;

void CChainParams::SetCheckpointData(CChainParams::CCheckpointData checkpointData)
{
    CChainParams::checkpointData = checkpointData;
}

void *chainparams_commandline(void *ptr)
{
    CChainParams::CCheckpointData checkpointData;
    while ( !PARAMS_LOADED || !ASSETCHAINS_P2PPORT )
    {
        #ifdef _WIN32
        boost::this_thread::sleep(boost::posix_time::milliseconds(1000));
        #else
        sleep(1);
        #endif
    }
    //fprintf(stderr,">>>>>>>> port.%u\n",ASSETCHAINS_P2PPORT);
    if ( ASSETCHAINS_SYMBOL[0] != 0 )
    {
        // Lucky Lode network identity lock (testnet runbook §2): fixed
        // owned p2p magic + staged ports, NEVER derived from the chain
        // name at runtime. A name-derived magic can collide with Verus or
        // another komodo-family chain; cross-connecting to foreign
        // traffic is a consensus-safety issue, not cosmetics. Frozen
        // before any public peer connects AND before the genesis
        // ceremony (the values feed tx/block hashing paths); changing
        // them later invalidates the whole network. Staged values —
        // founder sign-off before launch.
        if ( strcmp(ASSETCHAINS_SYMBOL, "LUCKYLODE") == 0 )
        {
            ASSETCHAINS_MAGIC = 0x4C4B594C; // "LKYL" on the wire
            ASSETCHAINS_P2PPORT = 9270;
            if ( ASSETCHAINS_RPCPORT == 0 )
                ASSETCHAINS_RPCPORT = 9271;
        }
        else if ( strcmp(ASSETCHAINS_SYMBOL, "LUCKYLODETEST") == 0 )
        {
            // Same pinned consensus magic as mainnet (it feeds PoS/tx
            // hashing); the testnet p2p wire magic is "LucT" from
            // CTestNetParams, so the two networks cannot cross-connect.
            ASSETCHAINS_MAGIC = 0x4C4B594C;
            ASSETCHAINS_P2PPORT = 19270;
            if ( ASSETCHAINS_RPCPORT == 0 )
                ASSETCHAINS_RPCPORT = 19271;
        }
        mainParams.SetDefaultPort(ASSETCHAINS_P2PPORT);
        if ( ASSETCHAINS_RPCPORT == 0 )
            ASSETCHAINS_RPCPORT = ASSETCHAINS_P2PPORT + 1;
        mainParams.pchMessageStart[0] = ASSETCHAINS_MAGIC & 0xff;
        mainParams.pchMessageStart[1] = (ASSETCHAINS_MAGIC >> 8) & 0xff;
        mainParams.pchMessageStart[2] = (ASSETCHAINS_MAGIC >> 16) & 0xff;
        mainParams.pchMessageStart[3] = (ASSETCHAINS_MAGIC >> 24) & 0xff;
        fprintf(stderr, ">>>>>>>>>> %s: p2p.%u rpc.%u magic.%08x %u %" PRId64 " coins\n", ASSETCHAINS_SYMBOL, ASSETCHAINS_P2PPORT, ASSETCHAINS_RPCPORT, ASSETCHAINS_MAGIC, ASSETCHAINS_MAGIC, ASSETCHAINS_SUPPLY / COIN);


        bool isVerusActive = _IsVerusActive();

        int64_t nBlockTime = isVerusActive ? CCurrencyDefinition::DEFAULT_BLOCKTIME_TARGET : GetArg("-blocktime", CCurrencyDefinition::DEFAULT_BLOCKTIME_TARGET);
        mainParams.SetBlockTime(nBlockTime);

        if (ASSETCHAINS_ALGO != ASSETCHAINS_EQUIHASH)
        {
            // this is only good for 60 second blocks with an averaging window of 45. for other parameters, use:
            // nLwmaAjustedWeight = (N+1)/2 * (0.9989^(500/nPowAveragingWindow)) * nPowTargetSpacing
            int64_t PowAveragingWindow = isVerusActive ? CCurrencyDefinition::DEFAULT_AVERAGING_WINDOW : GetArg("-powaveragingwindow", CCurrencyDefinition::DEFAULT_AVERAGING_WINDOW);
            mainParams.consensus.nPowAveragingWindow = PowAveragingWindow;
            mainParams.consensus.powAlternate = uint256S("00000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");

            if (!isVerusActive && mainParams.consensus.nBlockTime != CCurrencyDefinition::DEFAULT_BLOCKTIME_TARGET)
            {
                cpp_dec_float_50 averagingFactor(std::to_string((mainParams.consensus.nPowAveragingWindow+1)/2));
                cpp_dec_float_50 factorBase("0.9989");
                cpp_dec_float_50 factorExponent = cpp_dec_float_50("500") / cpp_dec_float_50(std::to_string(mainParams.consensus.nPowAveragingWindow));
                cpp_dec_float_50 blockTime(std::to_string(mainParams.consensus.nBlockTime));

                cpp_dec_float_50 weight = averagingFactor * pow(factorBase, factorExponent) * blockTime;
                std::stringstream ss(weight.str(0, std::ios_base::fixed));
                try
                {
                    ss >> mainParams.consensus.nLwmaAjustedWeight;
                }
                catch(const std::exception& e)
                {
                    fprintf(stderr,"%s: error calculating adjusted blocktime weight\n", __func__);
                    assert(false);
                }
                LogPrint("blocktime", "nLwmaAjustedWeight = %ld\n", mainParams.consensus.nLwmaAjustedWeight);
            } else {
                mainParams.consensus.nLwmaAjustedWeight = 1350;
            }
        }

        if (ASSETCHAINS_LWMAPOS != 0)
        {
            mainParams.consensus.posLimit = uint256S("000000000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
            mainParams.consensus.nPOSAveragingWindow = 45;
            // spacing is 1000 units per block to get better resolution, POS is 50% hard coded for now, we can vary it later
            // when we get reliable integer math on nLwmaPOSAjustedWeight
            mainParams.consensus.nPOSTargetSpacing = VERUS_BLOCK_POSUNITS * 2;
            // nLwmaPOSAjustedWeight = (N+1)/2 * (0.9989^(500/nPOSAveragingWindow)) * nPOSTargetSpacing
            // this needs to be recalculated if VERUS_BLOCK_POSUNITS is changed
            mainParams.consensus.nLwmaPOSAjustedWeight = 46531;
        }

        // this includes VRSCTEST, unlike the checkpoints and changes below
        if (isVerusActive)
        {
            // Lucky Lode: transparent-first payouts (owner decision
            // 2026-10-17). Upstream Verus set this true; inherited here it
            // makes EVERY transparent coinbase spend consensus-invalid
            // (pool payouts, PoS rewards, luckynode draws, wallet sends) —
            // "Coinbase funds earned while shielding protection is active
            // can only be sent to a zaddr". Our chains pay R/L addresses by
            // design; protection stays off on mainnet like test/regtest.
            mainParams.consensus.fCoinbaseMustBeProtected = false;
        }

        if (_IsVerusMainnetActive())
        {
            // Lucky Lode: fresh chain — no upstream seeds. Bootstrap nodes
            // are added as they come online (doc 12 hosting plan).
            mainParams.vFixedSeeds.clear();
            mainParams.vSeeds.clear();

            mainParams.consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = 227520;
            mainParams.consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = 227520;
            checkpointData = (CChainParams::CCheckpointData) {
                boost::assign::map_list_of
                (0, mainParams.consensus.hashGenesisBlock),
                0,  // * UNIX timestamp of last checkpoint block
                0,  // * total number of transactions between genesis and last checkpoint
                0   // * estimated number of transactions per day after checkpoint
            };

            mainParams.consensus.nMinimumChainWork = uint256S("0x00"); // fresh chain
        }
        else
        {
            mainParams.vSeeds.clear();
            mainParams.vFixedSeeds.clear();
            if (_IsVerusActive())
            {
                mainParams.vFixedSeeds.clear(); // fresh chain: no upstream seeds
            }
            mainParams.consensus.nMinimumChainWork = uint256S("0x00"); // fresh chain
            mainParams.consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = ASSETCHAINS_SAPLING;
            mainParams.consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = ASSETCHAINS_OVERWINTER;
            checkpointData = (CChainParams::CCheckpointData) {
                boost::assign::map_list_of
                (0, mainParams.consensus.hashGenesisBlock),
                0,  // * UNIX timestamp of last checkpoint block
                0,  // * total number of transactions between genesis and last checkpoint
                0   // * estimated number of transactions per day after checkpoint
            };
        }
    }
    else
    {
            checkpointData = (CChainParams::CCheckpointData) {
                boost::assign::map_list_of
                (0, mainParams.consensus.hashGenesisBlock),
                0,  // * UNIX timestamp of last checkpoint block
                0,  // * total number of transactions between genesis and last checkpoint
                0   // * estimated number of transactions per day after checkpoint
            };
    }

    mainParams.SetCheckpointData(checkpointData);

    ASSETCHAIN_INIT = 1;
    return(0);
}

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        strCurrencyUnits = "tLKYL";
        bip44CoinType = 1;
        // Lucky Lode: transparent-first mining payouts (doc 11, runbook).
        // Upstream Zcash set this true on testnet; inherited here, it made
        // every pool/luckynode payout consensus-invalid ("Coinbase funds
        // earned while shielding protection is active can only be sent to
        // a zaddr"). Regtest and the base params are false too.
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nSubsidySlowStartInterval = 20000;
        consensus.nPreBlossomSubsidyHalvingInterval = Consensus::PRE_BLOSSOM_HALVING_INTERVAL;
        consensus.nPostBlossomSubsidyHalvingInterval = Consensus::POST_BLOSSOM_HALVING_INTERVAL;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 400;
        const size_t N = 200, K = 9;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        consensus.nEquihashN = N;
        consensus.nEquihashK = K;
        // Lucky Lode: LuckyHash POW_LIMIT (doc 05 §5.3, compact 0x1f00ffff)
        consensus.powLimit = uint256S("0000ffff00000000000000000000000000000000000000000000000000000000");
        consensus.powAlternate = uint256S("0000ffff00000000000000000000000000000000000000000000000000000000");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        // Lucky Lode: PoS parameters mirror mainnet — without them the PoS
        // default target is zero and no PoS block can ever win on this
        // network. (Upstream only sets these on mainParams; regtest/testnet
        // were left at zero. Found live 2026-10-13: the staker ran with a
        // 646-coin stake but the target was 0x00..00, unwinnable.)
        consensus.posLimit = uint256S("000000000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.nPOSAveragingWindow = 45;
        consensus.nPOSTargetSpacing = VERUS_BLOCK_POSUNITS * 2;
        consensus.nLwmaPOSAjustedWeight = 46531;
        consensus.nMaxFutureBlockTime = 7 * 60;

        nDefaultPort = 19270;
        nMinerThreads = 0;
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPreBlossomPowTargetSpacing = Consensus::PRE_BLOSSOM_POW_TARGET_SPACING;
        consensus.nPostBlossomPowTargetSpacing = Consensus::POST_BLOSSOM_POW_TARGET_SPACING;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 299187;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170003;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = 207500;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = 280000;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nProtocolVersion = 170008;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight = 584000;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00"); // fresh chain

        // Lucky Lode testnet magic ("LucT")
        pchMessageStart[0] = 0x4C;
        pchMessageStart[1] = 0x75;
        pchMessageStart[2] = 0x63;
        pchMessageStart[3] = 0x54;
        nMaxTipAge = 24 * 60 * 60;

        nPruneAfterHeight = 1000;

        // Lucky Lode TESTNET genesis — FINAL ceremony 2026-10-13, internal/genesis_grind.py
        // Same identity message + no-premine burn as mainnet, but its own nTime
        // and nonce so testnet has a distinct genesis (founder decision 2026-10-13;
        // nTime finalized 2026-10-13: kept the ground value so the tested hash
        // stands). Transcript: nTime=1791869035, nBits=0x1f00ffff, version=4,
        // empty solution, null sapling root.
        genesis = CreateGenesisBlock(
            "the coin you mine on whatever you already own.",
            CScript() << OP_RETURN << ParseHex("4c75636b794c6f64652066616972206c61756e6368202d206e6f207072656d696e65"),
            1791869035,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000016b67"),
            ParseHex(""),
            0x1f00ffff, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash(0);
        assert(consensus.hashGenesisBlock == uint256S("0x000024a132b37b93939504f73f8b3d6477f256c072254bc9379dde44321f3cfa"));
        assert(genesis.hashMerkleRoot == uint256S("0xe826780cb764461be27e590018df8caeeea2dbbeee5d7cd28724e039e4d216a5"));

        vFixedSeeds.clear();
        vSeeds.clear();
        //vSeeds.push_back(CDNSSeedData("z.cash", "dns.testnet.z.cash")); // Komodo

        // Lucky Lode TESTNET: distinct from both upstream Verus testnet
        // ({0},{5}) and Lucky Lode mainnet ({48},{50}). Bitcoin-testnet
        // convention so test coins are unmistakable (m/n... and 2...).
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[IDENTITY_ADDRESS] = std::vector<unsigned char>(1,102);
        base58Prefixes[INDEX_ADDRESS] = std::vector<unsigned char>(1,137);
        base58Prefixes[QUANTUM_ADDRESS] = std::vector<unsigned char>(1,58);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {20,81};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVt"
        base58Prefixes[ZCVIEWING_KEY]  = {0xA8,0xAC,0x0C};
        base58Prefixes[ZCSPENDING_KEY] = {177,235};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "ztestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivktestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-test";
        bech32HRPs[SAPLING_EXTENDED_FVK]         = "zxviewtestsapling";

        vFixedSeeds.clear(); // Lucky Lode testnet: fresh chain, no upstream seeds

        // Lucky Lode testnet bootstrap seed (2026-10-14): the staging VPS
        // (40.160.149.124:9270) as a hardcoded fixed seed, so a fresh
        // testnet node finds the network without -addnode. Fixed seeds are
        // loaded into addrman at startup (net.cpp) and only bootstrap the
        // address book — replace with seed.luckylode.cc DNS records
        // (vSeeds) once the dedicated seed boxes and DNS are final.
        {
            SeedSpec6 seed;
            memset(seed.addr, 0, sizeof(seed.addr));
            seed.addr[10] = 0xff; // IPv4-mapped IPv6: ::ffff:40.160.149.124
            seed.addr[11] = 0xff;
            seed.addr[12] = 40;
            seed.addr[13] = 160;
            seed.addr[14] = 149;
            seed.addr[15] = 124;
            seed.port = 9270;
            vFixedSeeds.push_back(seed);
        }

        //fRequireRPCPassword = true;
        fMiningRequiresPeers = false;//true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;


        // Lucky Lode testnet: genesis-only checkpoint (fresh chain, no
        // upstream checkpoints — those belong to the Zcash/Verus testnet).
        checkpointData = (CChainParams::CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock),
            0,  // * UNIX timestamp of last checkpoint block
            0,  // * total number of transactions between genesis and last checkpoint
            0   // * estimated number of transactions per day after checkpoint
        };

        /*
        // Hardcoded fallback value for the Sprout shielded value pool balance
        // for nodes that have not reindexed since the introduction of monitoring
        // in #2795.
        nSproutValuePoolCheckpointHeight = 440329;
        nSproutValuePoolCheckpointBalance = 40000029096803;
        fZIP209Enabled = true;
        hashSproutValuePoolCheckpointBlock = uint256S("000a95d08ba5dcbabe881fc6471d11807bcca7df5f1795c99f3ec4580db4279b");

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = {
            "t2UNzUUx8mWBCRYPRezvA363EYXyEpHokyi", "t2N9PH9Wk9xjqYg9iin1Ua3aekJqfAtE543", "t2NGQjYMQhFndDHguvUw4wZdNdsssA6K7x2", "t2ENg7hHVqqs9JwU5cgjvSbxnT2a9USNfhy",
            "t2BkYdVCHzvTJJUTx4yZB8qeegD8QsPx8bo", "t2J8q1xH1EuigJ52MfExyyjYtN3VgvshKDf", "t2Crq9mydTm37kZokC68HzT6yez3t2FBnFj", "t2EaMPUiQ1kthqcP5UEkF42CAFKJqXCkXC9",
            "t2F9dtQc63JDDyrhnfpzvVYTJcr57MkqA12", "t2LPirmnfYSZc481GgZBa6xUGcoovfytBnC", "t26xfxoSw2UV9Pe5o3C8V4YybQD4SESfxtp", "t2D3k4fNdErd66YxtvXEdft9xuLoKD7CcVo",
            "t2DWYBkxKNivdmsMiivNJzutaQGqmoRjRnL", "t2C3kFF9iQRxfc4B9zgbWo4dQLLqzqjpuGQ", "t2MnT5tzu9HSKcppRyUNwoTp8MUueuSGNaB", "t2AREsWdoW1F8EQYsScsjkgqobmgrkKeUkK",
            "t2Vf4wKcJ3ZFtLj4jezUUKkwYR92BLHn5UT", "t2K3fdViH6R5tRuXLphKyoYXyZhyWGghDNY", "t2VEn3KiKyHSGyzd3nDw6ESWtaCQHwuv9WC", "t2F8XouqdNMq6zzEvxQXHV1TjwZRHwRg8gC",
            "t2BS7Mrbaef3fA4xrmkvDisFVXVrRBnZ6Qj", "t2FuSwoLCdBVPwdZuYoHrEzxAb9qy4qjbnL", "t2SX3U8NtrT6gz5Db1AtQCSGjrpptr8JC6h", "t2V51gZNSoJ5kRL74bf9YTtbZuv8Fcqx2FH",
            "t2FyTsLjjdm4jeVwir4xzj7FAkUidbr1b4R", "t2EYbGLekmpqHyn8UBF6kqpahrYm7D6N1Le", "t2NQTrStZHtJECNFT3dUBLYA9AErxPCmkka", "t2GSWZZJzoesYxfPTWXkFn5UaxjiYxGBU2a",
            "t2RpffkzyLRevGM3w9aWdqMX6bd8uuAK3vn", "t2JzjoQqnuXtTGSN7k7yk5keURBGvYofh1d", "t2AEefc72ieTnsXKmgK2bZNckiwvZe3oPNL", "t2NNs3ZGZFsNj2wvmVd8BSwSfvETgiLrD8J",
            "t2ECCQPVcxUCSSQopdNquguEPE14HsVfcUn", "t2JabDUkG8TaqVKYfqDJ3rqkVdHKp6hwXvG", "t2FGzW5Zdc8Cy98ZKmRygsVGi6oKcmYir9n", "t2DUD8a21FtEFn42oVLp5NGbogY13uyjy9t",
            "t2UjVSd3zheHPgAkuX8WQW2CiC9xHQ8EvWp", "t2TBUAhELyHUn8i6SXYsXz5Lmy7kDzA1uT5", "t2Tz3uCyhP6eizUWDc3bGH7XUC9GQsEyQNc", "t2NysJSZtLwMLWEJ6MH3BsxRh6h27mNcsSy",
            "t2KXJVVyyrjVxxSeazbY9ksGyft4qsXUNm9", "t2J9YYtH31cveiLZzjaE4AcuwVho6qjTNzp", "t2QgvW4sP9zaGpPMH1GRzy7cpydmuRfB4AZ", "t2NDTJP9MosKpyFPHJmfjc5pGCvAU58XGa4",
            "t29pHDBWq7qN4EjwSEHg8wEqYe9pkmVrtRP", "t2Ez9KM8VJLuArcxuEkNRAkhNvidKkzXcjJ", "t2D5y7J5fpXajLbGrMBQkFg2mFN8fo3n8cX", "t2UV2wr1PTaUiybpkV3FdSdGxUJeZdZztyt",
            };
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight(0));
        */
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        strCurrencyUnits = "rLKYL";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nPreBlossomSubsidyHalvingInterval = Consensus::PRE_BLOSSOM_REGTEST_HALVING_INTERVAL;
        consensus.nPostBlossomSubsidyHalvingInterval = Consensus::POST_BLOSSOM_REGTEST_HALVING_INTERVAL;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        const size_t N = 48, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        consensus.nEquihashN = N;
        consensus.nEquihashK = K;
        // Lucky Lode: LuckyHash POW_LIMIT (doc 05 §5.3, compact 0x1f00ffff)
        consensus.powLimit = uint256S("0000ffff00000000000000000000000000000000000000000000000000000000");
        consensus.powAlternate = uint256S("0000ffff00000000000000000000000000000000000000000000000000000000");
        // Lucky Lode: PoS parameters mirror mainnet — without them the PoS
        // default target is zero and no PoS block can ever win on this
        // network. (Upstream only sets these on mainParams; regtest/testnet
        // were left at zero. Found live 2026-10-13: the staker ran with a
        // 646-coin stake but the target was 0x00..00, unwinnable.)
        consensus.posLimit = uint256S("000000000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.nPOSAveragingWindow = 45;
        consensus.nPOSTargetSpacing = VERUS_BLOCK_POSUNITS * 2;
        consensus.nLwmaPOSAjustedWeight = 46531;
        consensus.nMaxFutureBlockTime = 7 * 60; // 7 mins
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nPowMaxAdjustUp = 0; // Turn off adjustment up
        consensus.nPreBlossomPowTargetSpacing = Consensus::PRE_BLOSSOM_POW_TARGET_SPACING;
        consensus.nPostBlossomPowTargetSpacing = Consensus::POST_BLOSSOM_POW_TARGET_SPACING;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 0;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170003;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170006;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nProtocolVersion = 170008;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // Lucky Lode regtest magic ("LucR")
        pchMessageStart[0] = 0x4C;
        pchMessageStart[1] = 0x75;
        pchMessageStart[2] = 0x63;
        pchMessageStart[3] = 0x52;
        nMinerThreads = 1;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(
            1296688602,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000000009"),
            ParseHex("01936b7db1eb4ac39f151b8704642d0a8bda13ec547d54cd5e43ba142fc6d8877cab07b3"),


            KOMODO_MINDIFF_NBITS, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash(0);
        assert(consensus.hashGenesisBlock == uint256S("0x029f11d80ef9765602235e1bc9727e3eb6ba20839319f761fee920d63401e327"));
        assert(genesis.hashMerkleRoot == uint256S("0xc4eaa58879081de3c24a7b117ed2b28300e7ec4c4c1dff1d3f1268b7857a4ddb"));

        nDefaultPort = 29270;
        nPruneAfterHeight = 1000;

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CChainParams::CCheckpointData) {
            boost::assign::map_list_of
            (0, mainParams.consensus.hashGenesisBlock),
            0,  // * UNIX timestamp of last checkpoint block
            0,  // * total number of transactions between genesis and last checkpoint
            0   // * estimated number of transactions per day after checkpoint
        };
        // These prefixes are the same as the testnet prefixes
        // Lucky Lode: P2PKH addresses start with 'L' (48), P2SH with 'M' (50).
        // (Regtest keeps upstream {0},{5} for test compatibility; identity
        // prefix 102 is tracked separately for the LuckyID rebrand pass.)
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,48);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,50);
        base58Prefixes[IDENTITY_ADDRESS] = std::vector<unsigned char>(1,102);
        base58Prefixes[INDEX_ADDRESS] = std::vector<unsigned char>(1,137);
        base58Prefixes[QUANTUM_ADDRESS] = std::vector<unsigned char>(1,58);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,188);
        //base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0x25};
        //base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBA};
        //base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zregtestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewregtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivkregtestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-regtest";
        bech32HRPs[SAPLING_EXTENDED_FVK]         = "zxviewregtestsapling";

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = { "t2FwcEhFdNXuFMv1tcYwaBJtYVtMj8b1uTg" };
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight(0));
    }

    void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
    {
        assert(idx > Consensus::BASE_SPROUT && idx < Consensus::MAX_NETWORK_UPGRADES);
        consensus.vUpgrades[idx].nActivationHeight = nActivationHeight;
    }

    void UpdateRegtestPow(int64_t nPowMaxAdjustDown, int64_t nPowMaxAdjustUp, uint256 powLimit)
    {
        consensus.nPowMaxAdjustDown = nPowMaxAdjustDown;
        consensus.nPowMaxAdjustUp = nPowMaxAdjustUp;
        consensus.powLimit = powLimit;
    }

    void SetRegTestZIP209Enabled() {
        fZIP209Enabled = true;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    // the only reason this should occur is before initialization to convert addresses
    // we don't use others besides main, and the only risk in returning it would be something else not initialized
    if (!pCurrentParams)
    {
        return mainParams;
    }
    return *pCurrentParams;
}

void DisableCoinbaseMustBeProtected()
{
    CChainParams &curParams = pCurrentParams ? *pCurrentParams : mainParams;
    curParams.DisableCoinbaseMustBeProtected();
}

void EnableCoinbaseMustBeProtected()
{
    CChainParams &curParams = pCurrentParams ? *pCurrentParams : mainParams;
    curParams.EnableCoinbaseMustBeProtected();
}

bool AreParamsInitialized()
{
    return (pCurrentParams != NULL);
}

void CChainParams::SetBlockTime(uint64_t blockTime)
{
    consensus.nBlockTime = blockTime;
    consensus.nMaxFutureBlockTime = 7 * consensus.nBlockTime;
    consensus.nPowTargetSpacing = consensus.nBlockTime;
    nMaxTipAge = 24 * 60 * consensus.nBlockTime;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);

    // Some python qa rpc tests need to enforce the coinbase consensus rule
    if (network == CBaseChainParams::REGTEST && IsArgSet("-regtestprotectcoinbase")) {
        regTestParams.SetRegTestCoinbaseMustBeProtected();
    }

    // When a developer is debugging turnstile violations in regtest mode, enable ZIP209
    if (network == CBaseChainParams::REGTEST && IsArgSet("-developersetpoolsizezero")) {
        regTestParams.SetRegTestZIP209Enabled();
    }
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);

    return true;
}


// Block height must be >0 and <=last founders reward block height
// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)
std::string CChainParams::GetFoundersRewardAddressAtHeight(int nHeight) const {
    int preBlossomMaxHeight = consensus.GetLastFoundersRewardBlockHeight(0);
    // zip208
    // FounderAddressAdjustedHeight(height) :=
    // height, if not IsBlossomActivated(height)
    // BlossomActivationHeight + floor((height - BlossomActivationHeight) / BlossomPoWTargetSpacingRatio), otherwise
    bool blossomActive = consensus.NetworkUpgradeActive(nHeight, Consensus::UPGRADE_BLOSSOM);
    if (blossomActive) {
        int blossomActivationHeight = consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight;
        nHeight = blossomActivationHeight + ((nHeight - blossomActivationHeight) / Consensus::BLOSSOM_POW_TARGET_SPACING_RATIO);
    }
    assert(nHeight > 0 && nHeight <= preBlossomMaxHeight);
    size_t addressChangeInterval = (preBlossomMaxHeight + vFoundersRewardAddress.size()) / vFoundersRewardAddress.size();
    size_t i = nHeight / addressChangeInterval;
    return vFoundersRewardAddress[i];
}

// Block height must be >0 and <=last founders reward block height
// The founders reward address is expected to be a multisig (P2SH) address
CScript CChainParams::GetFoundersRewardScriptAtHeight(int nHeight) const {
    assert(nHeight > 0 && nHeight <= consensus.GetLastFoundersRewardBlockHeight(nHeight));

    CTxDestination address = DecodeDestination(GetFoundersRewardAddressAtHeight(nHeight).c_str());
    assert(IsValidDestination(address));
    assert(boost::get<CScriptID>(&address) != nullptr);
    CScriptID scriptID = boost::get<CScriptID>(address); // address is a boost variant
    CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    return script;
}

std::string CChainParams::GetFoundersRewardAddressAtIndex(int i) const {
    assert(i >= 0 && i < vFoundersRewardAddress.size());
    return vFoundersRewardAddress[i];
}

void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
{
    regTestParams.UpdateNetworkUpgradeParameters(idx, nActivationHeight);
}

void UpdateRegtestPow(int64_t nPowMaxAdjustDown, int64_t nPowMaxAdjustUp, uint256 powLimit) {
    regTestParams.UpdateRegtestPow(nPowMaxAdjustDown, nPowMaxAdjustUp, powLimit);
}
