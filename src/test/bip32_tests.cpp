// Copyright (c) 2013-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include "base58.h"
#include "key.h"
#include "uint256.h"
#include "util.h"
#include "utilstrencodings.h"
#include "test/test_bitcoin.h"

#include <string>
#include <vector>

//create new data define CREATE_NEW_TEST_DATA
//#define CREATE_NEW_TEST_DATA
#ifdef CREATE_NEW_TEST_DATA
#include <iostream>
#endif

struct TestDerivation {
    std::string pub;
    std::string prv;
    unsigned int nChild;
};

struct TestVector {
    std::string strHexMaster;
    std::vector<TestDerivation> vDerive;

    TestVector(std::string strHexMasterIn) : strHexMaster(strHexMasterIn) {}

    TestVector& operator()(std::string pub, std::string prv, unsigned int nChild) {
        vDerive.push_back(TestDerivation());
        TestDerivation &der = vDerive.back();
        der.pub = pub;
        der.prv = prv;
        der.nChild = nChild;
        return *this;
    }
};

TestVector test1 =
  TestVector("000102030405060708090a0b0c0d0e0f")
	("Fpub15bEDvvx1UUJ5idB31kXnq1boZreVC1g4Ujmym73jtvhcUVEK9SvXeNQ2RmL2AW122PytQNzGGrFrrecSjjkUneQd9sVX3cqNDmZaxyS1uX",
	 "Fprv4rbspRQ4B6uzsEYhvzDXRh4sFY2A5jHphFpBBNhSBZPijgA5mc8fyr3vBA82WH5w6VW3PTMqcyVx4LTU9Vu6rkeKqT9GMX7Ec7ApYdFxs4e",
	  0x80000000)
	("Fpub17reDeER6jbHEKktEmdAfs7i8PQzsGVgk6AfwrVAi67yyknQjNz1enioohL2mUQY2EgYkdvQzuvLqFckPmU8Yg78pnfkSMX3t9u7taBzcAK",
	 "Fprv4tsHp8hXGN2z1qgR8k6AJjAyaMaWTomqNsF59U5Z9kb16xTGBqfm6zQKxRUMuzTtoYPjkkgi1LLpn6VBo6BHepiquKpQbUp8K7ofyq9vodP",
	  0x1)
	("Fpub1A2mRRnJVSUM4moKy2X3Gc1NBmQ6sJDygQqWY8FyeivCDJHYTBQKcMd3DmncBR7syxJbY4NX7WQpRZMZs6e2EKw57zWbuzXKWtRuBVeADEd",
	 "Fprv4w3R1vFQf4v3rHirrzz2uU4ddjZcTqW8KBuujjrN6PPDLVxPue654ZJZNUfRWvEwFd9RZaH963JEv31QvRyGRzDHR6n8fEayyv83Wij9dyj",
	  0x80000002)
	("Fpub1Ce3TxcACKKkvwbRDcvQdc3WQvGd8qoy1x5BnTZ8pbHdd9UfFwEkWoAxmnySdHZCLUQL9SM8VSynstVraCBZHn5uhtUjzwb1EaM3Gmtr4ZK",
	 "Fprv4yeh4T5GMwmTiTWx7bPQGU6mrtS8jP67ej9az59XGFkekM9WiPvVxzrUvWt3V9kRm6ApA3E4WT899EkAWStTZ5ewmiLgpApvbBsG9HQsNDn",
	  0x2)
	("Fpub1EsSJPj7Nnzk1R58ut8VX7CpVjZMmS8ATRxV3R5c92rEzF72Khw7iNdtT7xq35hvonXWHSq5YBsuSJqrfVcm1NZAcg2vq8UqFGFtRS93Feo",
	 "Fprv51t5ttCDYRSSnvzforbV9yG5whisMyQK6D2tF2fzahKG7SmsnAcsAaKQbqHVwp9rptJWmxTdRGaJcRechsRokUEzAxRnNFedkALReoCWMvd",
	  0x3b9aca00)
	("Fpub1GbCn5LMVvNwXkrb2RhDppCpHy8favwCFgM3HhTkM7EjhNWQr8BmyUnx5wsmtLneHUp3nnkt5PaW2jEsmM7brdiHVDT1dc4U4DsofWnZFzi",
	 "Fprv53brNZoTfYpeKGn7vQADTgG5jwJBBUDLtTRSVK48nmhkpaBGJasXRgUUEh4hrjGwSHhmZKSaGK7RcbezEwSXsRtXWTC1VAQM2VtnPzNwcEC",
	  0x0);

TestVector test2 =
  TestVector("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")
	("Fpub15bEDvvx1UUJ5L8W9AppF2jN3m15ApGVk4XWGhqsiH3ZuTWRVJDrxYXzNXrJjQrxvadmo539fMMWaeNqZveucheMV64xMY7VgbSfrrxY1rp",
	 "Fprv4rbspRQ4B6uzrr4339HostndVjAamMYeNqbuUKSG9wWb2fBGwkucQkDWXDu5gne2LYFU8jpHu5Y99sBaBvHoU7y6HsDWVs1yBMo3uaPVLDN",
	  0x0)
	("Fpub18ryVecuVVJNbbioGxChJq8tQikKsnknJEGsSWsKnguXbRxQ4ZZw7P7EwzpCXVsQ8u7wfJ2u4SCUjooXT5MKxJJdm8odFtFsp5ZLJ9iPye3",
	 "Fprv4usd6961f7k5P7eLAvfgwhC9rguqUL2vw1MGe8TiEMNYiddFX2FgZanm6jAtKrUrkCVJ2kE2LExGWNpPkCnrQM8VJ3dZtMBiJmhcGuGzwd5",
	  0xffffffff)
	("Fpub1A22kFeRsPUUmTvyhQCLnApSoTyERGvUPPMQMun6SRfv3jBrgSzFKStqZP4KHEUVvR3VK8tWMed5QUfsDyqSgSmGJDRgccWtgTpw8s7ntYn",
	 "Fprv4w2gLk7Y31vBYyrWbNfLR2siFS8k1pCd2ARoZXNUt68wAvri8ufzmeaMi5es47DLeRpBomRfPFTNwcZAUaPyyea3imrueruy6Z393MVb1ru",
	  0x1)
	("Fpub1Cq1AGdN32mfs5c7m4Luk7kg8zqjXTqjhprGCySRkK2MiZ41yxWxDMHDQBFT57AnWbW39myjzmvuVGvt8tGPwnEAtVdXq9x6cEVtPMzJofX",
	 "Fprv4yqekm6UCfDNebXef2ouNyoway1F817tLbvfQb2pByVNqkisSRChfYxjYsrV5pR2xPAtZ4W3no8bGKLKXTvMz8PLrYPiVxtMaMTsWvTygH4",
	  0xfffffffe)
	("Fpub1E135EZieRjPA2qiVYAT7dSs3jK6aSUEjXa9jh8qb5HcAuNx5dSxjseK2qNxGUhEU39fxH3T3PFm8v6GpmNuf8vdAPx2PT3WUTaTvLFF4h1",
	 "Fprv511gfj2pp4B5wYmFPWdSkVW8VhUcAykPNJeYwJjE2jkdJ73oY68iC5KqBaasiEoKVxTartH3BAiB5SRh3Qprfy4WgUw2eAuyuwUPanePVaK",
	  0x2)
	("Fpub1FN52fnEAc3cuJ2cDcJ96NpqSnrCpmPKPhC39UVLDs9CF6iXFGNivSbK7ETEQ43vz6MuECYrw6GkdM9mes4oyPnCoZn7KpLF9kmeauXfZTw",
	 "Fprv52NidAFLLEVKgox97am8jEt6tm1iRJfU2UGSM65ifXcDNJPNhj4UNeGqFzFssFtPYGKK9durdGYs7zKCmjC5iwoEVLSXhb3hcJowfLFVLYp",
	  0x0);

TestVector test3 =
  TestVector("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be")
	("Fpub15bEDvvx1UUJ4PaffZKcT1zPvQLAvgRmTQJ4fzsRyy8Mshjh9STpuomWrXPHZ1Sc6fPdd4vA42BN1x1kQdhM33JVcKyB66ZLUJxNPNNsWRr",
	 "Fprv4rbspRQ4B6uzquWCZXnc5t3fNNVgXDhv6BNTscTpRdbNzuQYbu9aN1T31DdFdosMREvDhfWPoWGrWWntRMSEFbULp9n9hJMwU5TQZVuhhdq",
	  0x80000000)
	("Fpub17xRxtm5gqqeFvg4thf7WGk4ckwZ5XqfrtY1VEZGvH3j8is9iwEgzGZEAFDoHN3MJ2tUQ2fttyNreQx6LsdXcHaSHRv4dx48xVKH3mNqqc1",
	 "Fprv4ty5ZPEBrUHM3Sbbng8798oL4j74g57pVfcQgr9fMwWkFvY1BPvSSUEkJyybymCGsPZdicJGTEuKA4S2za1z1MfyFHhCSTdkb6R4Wsht5fW",
	  0x0);

void RunTest(const TestVector &test) {
    std::vector<unsigned char> seed = ParseHex(test.strHexMaster);
#ifdef CREATE_NEW_TEST_DATA
    std::cout << "  TestVector(\"" << test.strHexMaster << "\")\n";
#endif
    //used to store master key
    CExtKey key;

    //used to store public key
    CExtPubKey pubkey;

    //set master key from strHexMaster (nDepth=0,nChild=0)
    key.SetMaster(&seed[0], seed.size());

    //set public key from master key
    pubkey = key.Neuter();


    for (const TestDerivation &derive : test.vDerive) {
        unsigned char data[74];
        key.Encode(data);
        pubkey.Encode(data);

        // Test private key
        CBitcoinExtKey b58key; b58key.SetKey(key);
#ifndef CREATE_NEW_TEST_DATA
        BOOST_CHECK(b58key.ToString() == derive.prv);
#endif

        CBitcoinExtKey b58keyDecodeCheck(derive.prv);
        CExtKey checkKey = b58keyDecodeCheck.GetKey();
        assert(checkKey == key); //ensure a base58 decoded key also matches

        // Test public key
        CBitcoinExtPubKey b58pubkey; b58pubkey.SetKey(pubkey);
#ifndef CREATE_NEW_TEST_DATA
        BOOST_CHECK(b58pubkey.ToString() == derive.pub);
#endif

        CBitcoinExtPubKey b58PubkeyDecodeCheck(derive.pub);
        CExtPubKey checkPubKey = b58PubkeyDecodeCheck.GetKey();
        assert(checkPubKey == pubkey); //ensure a base58 decoded pubkey also matches

#ifdef CREATE_NEW_TEST_DATA
        //create new data
        std::cout << "    (\"" << b58pubkey.ToString() << "\",\n";
        std::cout << "     \"" << b58key.ToString() << "\",\n";
        std::cout << "      0x" << std::hex << derive.nChild << ")\n";
#endif

        // Derive new keys
        CExtKey keyNew;
        BOOST_CHECK(key.Derive(keyNew, derive.nChild));
        CExtPubKey pubkeyNew = keyNew.Neuter();
        if (!(derive.nChild & 0x80000000)) {
            // Compare with public derivation
            CExtPubKey pubkeyNew2;
            BOOST_CHECK(pubkey.Derive(pubkeyNew2, derive.nChild));
            BOOST_CHECK(pubkeyNew == pubkeyNew2);
        }
        key = keyNew;
        pubkey = pubkeyNew;

        CDataStream ssPub(SER_DISK, CLIENT_VERSION);
        ssPub << pubkeyNew;
        BOOST_CHECK(ssPub.size() == 75);

        CDataStream ssPriv(SER_DISK, CLIENT_VERSION);
        ssPriv << keyNew;
        BOOST_CHECK(ssPriv.size() == 75);

        CExtPubKey pubCheck;
        CExtKey privCheck;
        ssPub >> pubCheck;
        ssPriv >> privCheck;

        BOOST_CHECK(pubCheck == pubkeyNew);
        BOOST_CHECK(privCheck == keyNew);
    }
}

BOOST_FIXTURE_TEST_SUITE(bip32_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bip32_test1) {
    RunTest(test1);
}

BOOST_AUTO_TEST_CASE(bip32_test2) {
    RunTest(test2);
}

BOOST_AUTO_TEST_CASE(bip32_test3) {
    RunTest(test3);
}

BOOST_AUTO_TEST_SUITE_END()
