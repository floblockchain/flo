// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "key.h"

#include "base58.h"
#include "script/script.h"
#include "uint256.h"
#include "util.h"
#include "utilstrencodings.h"
#include "test/test_bitcoin.h"

#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

//#define GENERATE_FLO_DATA

#ifdef GENERATE_FLO_DATA
#include <iostream>
#endif

static const std::string strSecret1     ("6UYrXhVrgjhHP9bjyc1HPVbKbkdLtrSLYTLZ9eJRpKUQeMTzuXt");  //hex: 5bfd923b4950181c2466a7b44fc759774b4bbbe99a8922dce9326c497e2c963f
static const std::string strSecret2     ("6UbQ5c5u9ZSVSS7DdecXaHKSbU88NbBenepqn5Gd36cNTNAAZnx");  //hex: 61c453b04d3a8572359ac43bb0233084a590f36d736a4ce740398ffa29ae5184
static const std::string strSecret1C    ("RAbbcVkNJPSoJkxLgqWFLHCV6PZQosCqFqFJu9dvXrXyMmjB9Dr6"); //hex: 5bfd923b4950181c2466a7b44fc759774b4bbbe99a8922dce9326c497e2c963f01
static const std::string strSecret2C    ("RAnpsKrdAnBWXFpSkm1owu2Py8iTYHt1nVxAHwqx4Fm7h2SkaSQd"); //hex: 61c453b04d3a8572359ac43bb0233084a590f36d736a4ce740398ffa29ae518401
static const CBitcoinAddress addr1 ("FGnu49xmR6MDgZ5biBASB73A9jzn5G2Chz");
static const CBitcoinAddress addr2 ("FSwZQFY39grFLSfS57L2FQhX2XgJMhpuRQ");
static const CBitcoinAddress addr1C("FTJAqaCyPdx9z3uSNNZz2r1D98gEJ4QpzU");
static const CBitcoinAddress addr2C("FAS6sPR2dLvXKZBrDk7rmafKvW6YnoD9Vc");

static const std::string strAddressBad("LWegHWHB5rmaF5rgWYt1YN3StapRdnGabc");

BOOST_FIXTURE_TEST_SUITE(key_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(key_test1)
{
    CBitcoinSecret bsecret1, bsecret2, bsecret1C, bsecret2C, baddress1;
    BOOST_CHECK( bsecret1.SetString (strSecret1));
    BOOST_CHECK( bsecret2.SetString (strSecret2));
    BOOST_CHECK( bsecret1C.SetString(strSecret1C));
    BOOST_CHECK( bsecret2C.SetString(strSecret2C));
    BOOST_CHECK(!baddress1.SetString(strAddressBad));

    CKey key1  = bsecret1.GetKey();
    BOOST_CHECK(key1.IsCompressed() == false);
    CKey key2  = bsecret2.GetKey();
    BOOST_CHECK(key2.IsCompressed() == false);
    CKey key1C = bsecret1C.GetKey();
    BOOST_CHECK(key1C.IsCompressed() == true);
    CKey key2C = bsecret2C.GetKey();
    BOOST_CHECK(key2C.IsCompressed() == true);

    CPubKey pubkey1  = key1. GetPubKey();
    CPubKey pubkey2  = key2. GetPubKey();
    CPubKey pubkey1C = key1C.GetPubKey();
    CPubKey pubkey2C = key2C.GetPubKey();


    CBitcoinAddress addr1BA,addr2BA,addr1CBA,addr2CBA;
    addr1BA.Set(pubkey1.GetID());
    addr2BA.Set(pubkey2.GetID());
    addr1CBA.Set(pubkey1C.GetID());
    addr2CBA.Set(pubkey2C.GetID());

#ifdef GENERATE_FLO_DATA
    std::cout << "static const CBitcoinAddress addr1 (\"" << addr1BA.ToString() << "\");\n";
    std::cout << "static const CBitcoinAddress addr2 (\"" << addr2BA.ToString() << "\");\n";
    std::cout << "static const CBitcoinAddress addr1C(\"" << addr1CBA.ToString() << "\");\n";
    std::cout << "static const CBitcoinAddress addr2C(\"" << addr2CBA.ToString() << "\");\n";
#endif

    BOOST_CHECK(key1.VerifyPubKey(pubkey1));
    BOOST_CHECK(!key1.VerifyPubKey(pubkey1C));
    BOOST_CHECK(!key1.VerifyPubKey(pubkey2));
    BOOST_CHECK(!key1.VerifyPubKey(pubkey2C));

    BOOST_CHECK(!key1C.VerifyPubKey(pubkey1));
    BOOST_CHECK(key1C.VerifyPubKey(pubkey1C));
    BOOST_CHECK(!key1C.VerifyPubKey(pubkey2));
    BOOST_CHECK(!key1C.VerifyPubKey(pubkey2C));

    BOOST_CHECK(!key2.VerifyPubKey(pubkey1));
    BOOST_CHECK(!key2.VerifyPubKey(pubkey1C));
    BOOST_CHECK(key2.VerifyPubKey(pubkey2));
    BOOST_CHECK(!key2.VerifyPubKey(pubkey2C));

    BOOST_CHECK(!key2C.VerifyPubKey(pubkey1));
    BOOST_CHECK(!key2C.VerifyPubKey(pubkey1C));
    BOOST_CHECK(!key2C.VerifyPubKey(pubkey2));
    BOOST_CHECK(key2C.VerifyPubKey(pubkey2C));

    BOOST_CHECK(addr1.Get()  == CTxDestination(pubkey1.GetID()));
    BOOST_CHECK(addr2.Get()  == CTxDestination(pubkey2.GetID()));
    BOOST_CHECK(addr1C.Get() == CTxDestination(pubkey1C.GetID()));
    BOOST_CHECK(addr2C.Get() == CTxDestination(pubkey2C.GetID()));

    for (int n=0; n<16; n++)
    {
        std::string strMsg = strprintf("Very secret message %i: 11", n);
        uint256 hashMsg = Hash(strMsg.begin(), strMsg.end());

        // normal signatures

        std::vector<unsigned char> sign1, sign2, sign1C, sign2C;

        BOOST_CHECK(key1.Sign (hashMsg, sign1));
        BOOST_CHECK(key2.Sign (hashMsg, sign2));
        BOOST_CHECK(key1C.Sign(hashMsg, sign1C));
        BOOST_CHECK(key2C.Sign(hashMsg, sign2C));

        BOOST_CHECK( pubkey1.Verify(hashMsg, sign1));
        BOOST_CHECK(!pubkey1.Verify(hashMsg, sign2));
        BOOST_CHECK( pubkey1.Verify(hashMsg, sign1C)); //failed
        BOOST_CHECK(!pubkey1.Verify(hashMsg, sign2C));

        BOOST_CHECK(!pubkey2.Verify(hashMsg, sign1));
        BOOST_CHECK( pubkey2.Verify(hashMsg, sign2));
        BOOST_CHECK(!pubkey2.Verify(hashMsg, sign1C));
        BOOST_CHECK( pubkey2.Verify(hashMsg, sign2C)); //failed

        BOOST_CHECK( pubkey1C.Verify(hashMsg, sign1)); //failed
        BOOST_CHECK(!pubkey1C.Verify(hashMsg, sign2));
        BOOST_CHECK( pubkey1C.Verify(hashMsg, sign1C));
        BOOST_CHECK(!pubkey1C.Verify(hashMsg, sign2C));

        BOOST_CHECK(!pubkey2C.Verify(hashMsg, sign1));
        BOOST_CHECK( pubkey2C.Verify(hashMsg, sign2)); //failed
        BOOST_CHECK(!pubkey2C.Verify(hashMsg, sign1C));
        BOOST_CHECK( pubkey2C.Verify(hashMsg, sign2C));

        // compact signatures (with key recovery)

        std::vector<unsigned char> csign1, csign2, csign1C, csign2C;

        BOOST_CHECK(key1.SignCompact (hashMsg, csign1));
        BOOST_CHECK(key2.SignCompact (hashMsg, csign2));
        BOOST_CHECK(key1C.SignCompact(hashMsg, csign1C));
        BOOST_CHECK(key2C.SignCompact(hashMsg, csign2C));

        CPubKey rkey1, rkey2, rkey1C, rkey2C;

        BOOST_CHECK(rkey1.RecoverCompact (hashMsg, csign1));
        BOOST_CHECK(rkey2.RecoverCompact (hashMsg, csign2));
        BOOST_CHECK(rkey1C.RecoverCompact(hashMsg, csign1C));
        BOOST_CHECK(rkey2C.RecoverCompact(hashMsg, csign2C));

        BOOST_CHECK(rkey1  == pubkey1);
        BOOST_CHECK(rkey2  == pubkey2);
        BOOST_CHECK(rkey1C == pubkey1C);
        BOOST_CHECK(rkey2C == pubkey2C);
    }

    // test deterministic signing

    std::vector<unsigned char> detsig, detsigc;
    std::string strMsg = "Very deterministic message";
    uint256 hashMsg = Hash(strMsg.begin(), strMsg.end());
    BOOST_CHECK(key1.Sign(hashMsg, detsig));
    BOOST_CHECK(key1C.Sign(hashMsg, detsigc));
    BOOST_CHECK(detsig == detsigc);
    BOOST_CHECK(detsig == ParseHex("30450221008eb06cff5d3e674ec8cd6ff8178a5537af23339bcf646407fb3f4d59ff9b51560220267cca388c801f470890eb636f24eed2b432776789944435eb0b32bdf26dcf9a"));
#ifdef GENERATE_FLO_DATA
    std::cout << "detsig == ParseHex(\"";
    for (std::vector<unsigned char>::const_iterator i = detsig.begin(); i != detsig.end(); ++i)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(*i);
    std::cout << ")\n";
#endif
    BOOST_CHECK(key2.Sign(hashMsg, detsig));
    BOOST_CHECK(key2C.Sign(hashMsg, detsigc));
    BOOST_CHECK(detsig == detsigc);
    BOOST_CHECK(detsig == ParseHex("3045022100b0208c440f805a57c654491518f6a7c699abd1767bfa738fc676fc5cb430395302206bb4ad99d6a0f952814f33816d4211ce36d7a5c116255927cf9b6b8d4779c276"));
#ifdef GENERATE_FLO_DATA
    std::cout << "detsig == ParseHex(\"";
    for (std::vector<unsigned char>::const_iterator i = detsig.begin(); i != detsig.end(); ++i)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(*i);
    std::cout << ")\n";
#endif
    BOOST_CHECK(key1.SignCompact(hashMsg, detsig));
    BOOST_CHECK(key1C.SignCompact(hashMsg, detsigc));
    BOOST_CHECK(detsig == ParseHex("1b8eb06cff5d3e674ec8cd6ff8178a5537af23339bcf646407fb3f4d59ff9b5156267cca388c801f470890eb636f24eed2b432776789944435eb0b32bdf26dcf9a"));
#ifdef GENERATE_FLO_DATA
    std::cout << "detsig == ParseHex(\"";
    for (std::vector<unsigned char>::const_iterator i = detsig.begin(); i != detsig.end(); ++i)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(*i);
    std::cout << ")\n";
#endif
    BOOST_CHECK(detsigc == ParseHex("1f8eb06cff5d3e674ec8cd6ff8178a5537af23339bcf646407fb3f4d59ff9b5156267cca388c801f470890eb636f24eed2b432776789944435eb0b32bdf26dcf9a"));
#ifdef GENERATE_FLO_DATA
    std::cout << "detsigc == ParseHex(\"";
    for (std::vector<unsigned char>::const_iterator i = detsigc.begin(); i != detsigc.end(); ++i)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(*i);
    std::cout << ")\n";
#endif
    BOOST_CHECK(key2.SignCompact(hashMsg, detsig));
    BOOST_CHECK(key2C.SignCompact(hashMsg, detsigc));
    BOOST_CHECK(detsig == ParseHex("1cb0208c440f805a57c654491518f6a7c699abd1767bfa738fc676fc5cb43039536bb4ad99d6a0f952814f33816d4211ce36d7a5c116255927cf9b6b8d4779c276"));
#ifdef GENERATE_FLO_DATA
    std::cout << "detsig == ParseHex(\"";
    for (std::vector<unsigned char>::const_iterator i = detsig.begin(); i != detsig.end(); ++i)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(*i);
    std::cout << ")\n";
#endif
    BOOST_CHECK(detsigc == ParseHex("20b0208c440f805a57c654491518f6a7c699abd1767bfa738fc676fc5cb43039536bb4ad99d6a0f952814f33816d4211ce36d7a5c116255927cf9b6b8d4779c276"));
#ifdef GENERATE_FLO_DATA
    std::cout << "detsigc == ParseHex(\"";
    for (std::vector<unsigned char>::const_iterator i = detsigc.begin(); i != detsigc.end(); ++i)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(*i);
    std::cout << ")\n";
#endif
}

BOOST_AUTO_TEST_SUITE_END()
