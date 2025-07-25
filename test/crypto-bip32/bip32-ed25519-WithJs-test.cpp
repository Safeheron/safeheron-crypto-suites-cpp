#include <google/protobuf/stubs/common.h>
#include "gtest/gtest.h"
#include "crypto-suites/crypto-bip32/bip32.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-encode/hex.h"

using safeheron::bip32::HDKey;
using safeheron::curve::CurveType;
using safeheron::curve::CurvePoint;
using namespace safeheron::encode;
void test_CKD(const std::string &seed, const std::string& root_xprv, const std::string& root_xpub, const std::vector<std::vector<std::string >> &child, const std::vector<std::vector<std::string >> &child_pub) {
    HDKey hd_root;
    std::string seed_bytes = hex::DecodeFromHex(seed);
    hd_root.FromSeed(CurveType::ED25519, reinterpret_cast<const uint8_t *>(seed_bytes.c_str()), seed_bytes.length());

    std::string root_xprv1;
    bool extended = hd_root.ToExtendedPrivateKey(root_xprv1);
    EXPECT_TRUE(extended);
    EXPECT_TRUE(root_xprv == root_xprv1);

    std::string root_xpub1;
    extended = hd_root.ToExtendedPublicKey(root_xpub1);
    EXPECT_TRUE(extended);
    EXPECT_TRUE(root_xpub == root_xpub1);

    for(size_t i = 0; i < child.size(); ++i) {
        HDKey hd_child = hd_root.PrivateCKDPath(child[i][0]);
        std::string child_xprv;
        extended = hd_child.ToExtendedPrivateKey(child_xprv);
        EXPECT_TRUE(extended);
        EXPECT_TRUE(child[i][1] == child_xprv);

        std::string child_xpub;
        extended = hd_child.ToExtendedPublicKey(child_xpub);
        EXPECT_TRUE(extended);
        EXPECT_TRUE(child[i][2] == child_xpub);
        std::cout << child[i][0] << ": " << child_xprv << ", " << child_xpub << std::endl << std::endl;
    }

    for(size_t i = 0; i < child_pub.size(); ++i) {
        HDKey hd_child = hd_root.PublicCKDPath(child_pub[i][0]);
        std::string child_xpub;
        extended = hd_child.ToExtendedPublicKey(child_xpub);
        EXPECT_TRUE(extended);
        EXPECT_TRUE(child_pub[i][1] == child_xpub);
        std::cout << child_pub[i][0] << "child_xpub: "  << child_xpub << std::endl << std::endl;
    }

}
TEST(bip32, testConsistent) {
    std::string seed = "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678";

    std::string root_xprv = "eprv423G5rKnJnGfkoU9nt7BeNyjvskhLsT5BpNkmJ66ANqu7R2WY62wEypvrGBApFqFnhVWF7hQbewmPzmPbz1Wu3BsqyfEZZwKWQ6w9JbU99q";
    std::string root_xpub = "epub8YjJEGN2T9xLeGVwgXmn3ndrVuGdWCdym7yY3p8PaeeHwuHHAUrXRUSo2KfWcN9TvKtKbXLwiHbtzb3it7bEokffaGXzhTPMuE11LXvWroE";
    std::vector<std::vector<std::string >> child = {
            {
                "m/0'",
                "eprv44kuwxXPmvsQrKLFQYVjZJZPteRp9RUZwbk3aY2EXbuBZtiDaLy3RjMqPpa4fNSyggWTjA7Hf28xKBqn37Nd8X4ZL4JUVTu1RRtTcSGPDA9",
                "epub8bSx6NZdvJZ5jnN3JCAKxiDWTfwkJkfUWuLps44XwshaQNxzCjndcDyhZs7qFjuBiTcnrptG2XCh2qEguiCaWebsSDi9XyfVtfUBX2YxaHm"
            },
            {
                "m/1",
                "eprv44kuwxXFSGLSguV4rFJ6ZukuEh5PKEX56MQxegsA4V7WgxcKjfzdc5ocDChYLG9iVhaEpnQwZueGuESV8vBsQwbLSpJAxwQKLntNCMxx6Dk",
                "epub8bSx6NZVae27aNWrjtxgyKR1oibKUZhyff1jwCuTUkuuXSs6N4pDnaRUPH3XnQ6SWcBU3fT4xPGogKbinXKWXGkenk8Q6K4mfVEY7pjaaiR"
            },
            {
                "m/2'",
                "eprv44kuwxXPmvsQwfoZ2NMJYaENZgD3dFSyBvUfJCuMBjmDsHbw6FpNwYVsoBpohYUsJRRHdd7diHXZ9t8b6Ytz9X1KZh7vuCD79BV9tZ11Ree",
                "epub8bSx6NZdvJZ5q8qLv21twytV8hiynadsmE5Saiwec1Zchmrhiedy837jyDGLS2gtDJVfUnxL2f8J1qGF11yR4RMqy1ThBhooDhtGgRqpBTY"
            },
            {
                "m/3",
                "eprv44kuwxXFSGLSoYziPbSX7Mdw96p6sB7TuKpNhAgEDbEK5qVrg2TDZT2MS1TroHemyyPAsmTNnZaAWo6F1NjgRYyrXZzLxJ7D16HBRoZQKuZ",
                "epub8bSx6NZVae27h22WHF77WmJ3i8L32WJNUdR9ygiXds2hvKkdJRGojweDc44DdYLtCHj5yMA5tAna7kZx7zLcWfindqWj1MUKX85pgopShdZ"
            },
            {
                "m/4'",
                "eprv44kuwxXPmvsQzj1GvQdzYY3sr6a2QxicoNJHJgrgEkCVkHL2dKQLASEt66G8kXSgzi3K2myzvLhM1qKtTRkRC7Ads9y4Agm8qTsusXKSLdT",
                "epub8bSx6NZdvJZ5tC34p4JawwhzR85xaHuXNfu4bCtyf1ztamaoFiDvLvrkG9Nkv4F9chy6Nq3JKG4ibQeGoBE5jxQTSujJ4ViqVTTi8tP3p2z"
            },
            {
                "m/5",
                "eprv44kuwxXFSGLSuFaubLu3jzgWghFCr6pZnw2nMW6CYD4FFXZXEK7rVa5T2RKTmr2omYhiadNmMD2EFur6rfkoFsFHWTDSEtRRLTu8DPxZo8W",
                "epub8bSx6NZVae27nichUzZe9QLdFim91S1UNEdZe28VxUre61pHrhwSg4hKCUWThVSDcFePsWVvxKQuaX6W9EMXfJ5CER96CnES4UqwoGoMGb8"
            },
            {
                "m/6'",
                "eprv44kuwxXPmvsR6mRZA2uxDV7ScdDBq3vr2wg4SgsEAa9gyHT3zts64dKewXzBgP28gwi29Mj9NotQisne6SrG2FYT85aVUrfKNPGWgQD5KoQ",
                "epub8bSx6NZdvJZ5zETM3gaYctmZBej7zP7kcFGqjCuXaqx5omhpdHggF7wX7azDMmm9okTstqginwioAof5EvPTPpSY6mc4XJPPywWTrUHzTbi"
            },
            {
                "m/7",
                "eprv44kuwxXFSGLSyBh7cg3HYvPT8uG9rdDLhhoWUqF1iEpUnSkLdpQdzEfWCtmakhd47N3Qysg2uiJPkegJvmCBhxEou8NWjxg7nTzxmQzCpG7",
                "epub8bSx6NZVae27reiuWKhsxL3Zhvn61xQFH1QHmMHK8Wcscw17GDEEAjHNNxnc92VRLH6KmgTujCZnzjtEydkLFKbycS7ucrYbeNoaJSV2nQy"
            },
            {
                "m/8'",
                "eprv44kuwxXPmvsRC3cdZeqT9SPmqokRAzUhSAV611pE7uriNws4LKbst3g7Xq1VKSBkHMv8ySWwjgVoCjTxjgNftu4frjEMWdi96nxViovS8i5",
                "epub8bSx6NZdvJZ65WeRTJW3Yr3tQqGMLKfc1U5sHXrXYBf7DS7pxiRU4YHyhsrs1sVDFpL22bw5axmsjaYZFAokvGf2A2fHEqcM3xxyMh8tTqB"
            },
            {
                "m/9",
                "eprv44kuwxXFSGLT57MonvQ2KfPumivzaC4jFAtydQ8XomzFdnCbGC9swB5kAQGid8woVAbDc1tBaFM5PTYunKAXND13DBCKTcjCVYShbX7bE6c",
                "epub8bSx6NZVae27xaPbga4cj542LkSvjXFdpUVkuvAqE3neUGTMtayU7fhcLUAwndAzn5iQG9xntPHZJN9nmE5btwoJyW7VGCUS8ZXfruvgGxX"
            },
            {
                "m/0'/0",
                "eprv47GJvG7WY14JMN1Cc6nXgz48j9aXaNLgHSt7LSGQouN7Sw7buftNZi5d5nUxkUCGLaiwCTifnWcKWVPwJ5GGypLj5dzFWVENtRctEmJzDna",
                "epub8dxM4g9kgNjyEq2zVkT86PiFJB6TjhXarkUtcxJiEBAWHRNNY4hxkChVFrEVGLLGDSfEQQkQAyjJkgMewUS7RrAN5aoShZiq6pHDoccSLxR"
            },
            {
                "m/0'/1",
                "eprv47GJvG7WY14JR9yBypTKAypFR9XCUoouc5zynk4xKChXX3KH53zJpnY6no7cq3AnM6YAGT1drbLDZ9QGDnYXGjyryWLYsWdG4QTTqPvM7rj",
                "epub8dxM4g9kgNjyJczysU7uaPUMzB38e8zpBPbm5G7FjUVvMXa3hSou1H9xxrmxaecWYBRYh7tZyreym64zozTqQ7KfNxDyL33HTBM3c6nDmaL"
            },
            {
                "m/1/0",
                "eprv46kPwd6F4K4FAeMwjAhWUxN9fUZcHCRfqN9WmUUVv6YSuB9uQKHNB1epy9Kbe1p2xLFqx9tUZ5npCDBss8VkFQzt2y1hSmhx7YVi2EQFsDi",
                "epub8dSS638VCgjv47PjcpN6tN2GEW5YSXcaQfkJ3zWoLNLqjfQg2i6xMWGh9CprCr2yNvYjC7EDUeMHoJ9oFzqikqH9Fru7otqeq1twKBVddx8"
            },
            {
                "m/1/1",
                "eprv46kPwd6F4K4FEqjP8p3Uy47edAwtyR7iCsYw44zfbsWe6DERXTE272erS8T7Yuio85R9H3tJRaJKbBH4oLQsM6do98fBzwq8gW6NzibJsdq",
                "epub8dSS638VCgjv8JmB2Ti5NTmmCCTq8kJcnB9iLb2y29K2vhVC9r3cHXGicCtjAhoUgsNLtjX9h1Vd8hAJHT8AWGmyFKAUqmwRtbTt43c9Rsu"
            },
            {
                "m/2'/0",
                "eprv47VJ9RMxUwevThjXEDjoRGSMdgy58zymK7eWV2Kt5AQo2KipYv5qM8EL1vPQtV3MJYzDBC4hWovQVygYj2ahDbthmFRm96jBepzcGFodfcm",
                "epub8eBLHqQCdKLbMAmK7sQPpg6UCiV1JLAftRFHmYNBVSDBroybBJuRXcrCBx1VHYpHKMqx4cemGP4Zn1zQaBpAG4YNhtzdTZt8jD6RMtW9oaf"
            },
            {
                "m/2'/1",
                "eprv47VJ9RMxUwevW2NXyxLJkr9Fuunq1JiRDMi55btYEjyfRefwvqjKhRmcSRu6MJiAevF25AmwB1QbEkoGe5Hot5aDdkNVHv2UcoodKNwknu7",
                "epub8eBLHqQCdKLbPVQKsbzuAFoNUwJmAduKnfJrN7vqf1n4G8viZEYusvPUcWNZdwmRc3n1zPmhQc3w7Rs51M2cwLeGbAVbePZjLZ6CK3bAAJm"
            },
            {
                "m/3/0",
                "eprv46BTMRR9fx7fZoSpPPDwr1dFUeZkyC3t2jULHqPdDQ5i8WqcenLxMASZeEGpsdjGJ3Ft2jkW7fuCjURyP9DdtWrEnPDVUc8FnFRtxqF8GQG",
                "epub8csVVqTPpKoLTGUcH2tYFRHN3g5h8XEnc357aMRvdft6y16PHBAYXf4RpJ4ddq11xZ3AxHY7gWq1NKtsbWpr4VkMrJT3kKGRzejzWtmTKsi"
            },
            {
                "m/3/1",
                "eprv46BTMRR9fx7fdu6ag6KAnLZtUJxEBWH7UsQKZW6YiS2yRDXjhHRtZXhyqV19HuSMen9gBBBvotADujdeYnVuKwx3LRtNTb86qcTgC9uRvMK",
                "epub8csVVqTPpKoLXN8NZjymBkE13LUALqU24B16r28r8hqNFhnWKgFUk2Kr1XiEYY3Cnc1tbz64YWg1eFG7QL2MLm58P1xGE9wVh8c53Pvs3XX"
            },
            {
                "m/4'/0",
                "eprv46X5yWiXubk6S8qjirXeYg346ZeDQC8mvNTpm4FWHp33E4QqwiJTgayzBhfLKYA4YHyiFsiWbubMideRyL873mGpNxuM5A33Dc7y7uPcKet",
                "epub8dD87vkn3yRmKbsXcWCEx5hAfbA9ZXKgVg4c3aHoi5qS4Yfca783s5brMkLaRfyybP8ehZDNFs9hgeVQrfod9fc6c5gEut2YvmEp1tCWDeq"
            },
            {
                "m/4'/1",
                "eprv46X5yWiXubk6TSnamnLujLWKLtsaJfofB8vp5ThoSoQt8deAyFH6ro3MQoh5XJasvLiR5cZ6ao35UknzMWEKPf16xF5MwkTTGoPSbbxG7DW",
                "epub8dD87vkn3yRmLupNfS1W8kARuvPWTzzZkSXbMyk6s5DGy7twbe6h3HfDarkSH1cqKvE8c7nf7zRn7cQpdUX8mTMxJ8jqgLJ2tEGHDjfQMcN"
            },
            {
                "m/5/0",
                "eprv47X3vFHHL9kxGd3nubSo8bKwVWTtuafHUKYDBfpLMSBDmCsrukx62YnbmZ1kdb5qfWM6LFSw56naM2EmKFaUzQ37bjUSDqL2BMC1kkCqu45",
                "epub8eD64fKXUXSdA65aoF7PXzz44Xyq4urC3d8zUBrdmhycbh8dY9mgD3QTwbRDM9tZKjJu268Y1Qxv7eCAq9BDNskaKTNBHG1HA7sXKtGfvW3"
            },
            {
                "m/5/1",
                "eprv47X3vFHHL9kxKWmRmQzqtdYH5cugSNdtYZad3jEZL56vPWd2rpKp8HCiNN2FVvPP6MSFVCCoMiKaW6TwAyUWxXUMF2ujSZ6wkm6Ss5x5yXT",
                "epub8eD64fKXUXSdCyoDf4fSJ3CPeeRcbhpo7sBQLFGrkLuKDzsoVD9QJmpaYQj1cdiVKkS984Rnbwep7aLMEbvwFkDUTi4bPepeBq5tB7KDcDS"
            },
            {
                "m/6'/0",
                "eprv47TEmCQ8i7Y2dGFEVfVS3xTStYrufBM7pHjbUaHLmsvTUWciZbmKQ3ErKWNBeEPECWkKNNwHFCkn1AjGnJ7CkpZ1sZDs5yos5Ns1gmwkbjf",
                "epub8e9GucSNrVDhWjH2PKA2TN7ZTaNqpWY2PbLNm6KeC9irJzsVBzauaXriVZ59Pa1NCT71fEMdXXitGWqQ982dksmVaKcHwYLsnxZygSTJSeN"
            },
            {
                "m/6'/1",
                "eprv47TEmCQ8i7Y2f1iocFKeJQyQ12fWFxGxqdtw91CqZzkU74Wyn1cUACEdGFrrCLaiCpkVF2nGnW1CByr85VSRF8b8M75asdbWd9fTZDavNtT",
                "epub8e9GucSNrVDhYUkbVtzEhpdWa4BSRHTsQwViRXF8zGYrwYmkQQS4LgrVSJHfijnbzZuYAwGmv4ZRtenRB7NcSttAEryPy861HrPAG7fCA9N"
            },
            {
                "m/7/0",
                "eprv45yrwSDXA7QiaHtfWzE2VGAL248V9MBRpR3UWPgNxQmH4gw5XRtJVrMcmLVvCvgFFQn3p2H4kRzt4eKMJxg7hRdorBiFpQXQR7TQs9EoJvi",
                "epub8cfu5rFmJV6PTkvTQdtctfpSb5eRJgNLPieFnuigNgZfuBBr9phtgLyUwPsWznV3rSSCL5QUWFazMHY9HzEHgrjm1BeQh6UQFmy5xAEoB43"
            },
            {
                "m/7/1",
                "eprv45yrwSDXA7QibkndpdY9a2naPVwLkSvVXXetD7kC8G5Cz2gA5wo9Uqg4af9LCKrUaivQDRY3qiQgPMuUyu6gg3AKS36uQWcSREZwYxkZZdc",
                "epub8cfu5rFmJV6PVDpRiHCjySSgxXTGun7Q6qFfVdnVYXsbpWvviLcjfLHvkifWC6EzbkqSEcZjvhfuHMhBmwbu55SuNA4f5PkjZgfW7Hw3wNW"
            },
            {
                "m/8'/0",
                "eprv45qYV9m9m9ShDioburCc7zgEM4oB3UGfXXHsooNYGNouPkeeMKv4LPPNUPDpcz7kvNB6yXd8Ji5MvC9egD34kbifaqQCmFtwZJdfdfd4AxN",
                "epub8cXadZoPuX8N7BqPoVsCXQLLv6K7CoTa6ptf6KQqgecJEEuQyijeWt1EeSUnJfNeRWuuWY2SmYRC8Z3rAf9iBEWeueMHS48ScohZPoToBE8"
            },
            {
                "m/8'/1",
                "eprv45qYV9m9m9ShFHstSRbgUjFby1ide3MXLhEkpu7WdQHrnEV3h2umMurDqqjyVUvHR2mozjM1MEwmHdijY8GEDNiofN1p7sb8oaRoi4C3pcz",
                "epub8cXadZoPuX8N8kugL5GGt8uiY3EZoNYRuzqY7R9p3g6FcijpKRjMYQU61tzn1pRa4MXZdbX4xca5J5vGqCcp2kGP2uoYi8aE2n2Qp5L5rSD"
            },
            {
                "m/9/0",
                "eprv47HCLb74k47wNtSqY3EeVZZByzRMytPQ9gJJv2ai1BiDYS63ahSfhfHZZC1HfLdTYCSywZxrbqVGDaHN4K7M3Zmk8vqquYESMDJHuYk8aUa",
                "epub8dyEV19JtRocGMUdRguEtyDJZ1wJ9DaJiyu6CYd1RTWcNvLpD6GFt9uRjG1uoVFbzgmMzu1ypcqFNKWyZs3f9zybNJFQfVB11BEWXJyiGKm"
            },
            {
                "m/9/1",
                "eprv47HCLb74k47wQk9vn2aAzn5yvJA6kJTZedTkSjCVDDSkFePTL3PTEd1qVHyGtTBLX9f9hnza1w25j3QCT1tCB9knCzmNFF12a1KBk9mQgp1",
                "epub8dyEV19JtRocJDBifgEmQBk6VKg2udeUDw4XjFEndVF968eDxSD3R7dhfM78skkqAur3zscF9NPsFbNL21fu6DepAdAUV421Uepy2CeoX5u"
            },
            {
                "m/0'/0/795690107",
                "eprv48ys86Nyw4hYv3DC499JHC8hwpNHJDZd7LbKHo5sNvUsZWGTPQnzSaSQ4nM5cXQKjCi7qJCwi2Mybv2EhgQJWqGHirq3tPmFnypS1vPSypL",
                "epub8ffuGWRE5SPDoWEywnotgbnpWqtDTYkXgeC6aK8AoCHGPzXE1ocad54GEpLLdhwdyQBu7viwtNqSyH3JvCYLH9QXtPVXFWgQg2N8scZVnWz"
            },
            {
                "m/0'/1/795690107",
                "eprv4899KJAhLja9qpwzZqA2BBfDNubD7xwt88KzGKtuinAGeWVbqB629CU9BmLcGqbmMDSR6ELG2QNtv6AFEmzszAMWCYCpDQYTiP4wxmHMLfE",
                "epub8eqBTiCwV7FpjHynTUpcabKKww79HJ8nhRvmYqwD93xfUzkNTZucKh61MoJjJU3hX4dhxMoESGq5K5UsU4HBxdoZgbam9cCu8mJjVD1LVfN"
            },
            {
                "m/2'/0/732676328",
                "eprv49Jvo9pSGSgVsYseXRBURMeYqccHKoXBJsfgTCNbUgMNAd9TQrW4X5WnFY3N1mMkhHZUmzuWbXnCjbRqiZ6ypdgueuxzcntvHYXERoDjc47",
                "epub8fzxwZrgQpNAm1uSR4r4pmJfQe8DV8i5tBGTjiQttx9m17QE3FKeha8eRany5R2A7jNhuke596GqYpcFXovs3FBDwj7NQy7YpGcWnxxFtTx"
            },
            {
                "m/2'/1/732676328",
                "eprv49NiqaAyFZTpGMs1wjTXmqjKAaf3pDXFCoDJNMxcHWdF88khCswq5bVYSRiPfPr4LQVsqJpG8uzJArETta2td5zHFF7C9HExzq2HpMFKAWG",
                "epub8g4kyzDDPw9V9ptoqP88BFPRjcAyyYi9n6p5eszuhnRdxd1TqGmRG67QcUQFvuPgQKfpFJKcpLfbTp16R4kkVtvTs4rp6CbwrfhZ2RQsq2m"
            },
            {
                "m/4'/0/577320614",
                "eprv496hD9LbhUEUvQgyFKnLLurrmC2BA9ygacVBEtDS3MUD7Pu57E7FtQkrwV2cfNBgCNAKYy6Q4fJvvJ6Nar4MQTvAjfXB1UL8Qdm71v6Pfpj",
                "epub8fnjMZNqqqv9osim8ySvkKWyLDY7KVAb9v5xXQFjTdGbwt9qjcvr4uNj7YtiuSwwUPKKTK6A4G5QBSU5VmeHALTfZkMVzqtqDdNqsnMPQ7Y"
            },
            {
                "m/4'/1/577320614",
                "eprv48WFt6jJAATgiLAxmhV1bXoNbSxBcFusPS8iGM4g8T12rer1oaSxjEAy4E1T2ZfGHXTSU9FgZxgBjLsJvaR9keEmWbosSQUot83SvQr9YKt",
                "epub8fCJ2WmYJY9MboCkfM9bzwTVAUU7mb6mxjjVYs6yYioRh96nRyGYuinqEJLE47M49WYSgxHGamd5n7c2MUwjfnXeHtanoS5NfAeKho2gcrQ"
            },
            {
                "m/6'/0/1690896966",
                "eprv48HE7QYatbpqga7tNXCqdUAEwXqnp53BXJrYhzMWBfgpWrEhWycTYQZXiTjmR7y7bq9pMdofzwb2e2T7XLgoYhsGKsBNBMhYiYPvCHC1NdH",
                "epub8eyGFpaq2yWWa39gGAsS2spMWZMiyQE66cTKzWPobwVDMLVU9NS3iuBPtXUtwapoZ7fKxvSE6jrmWyPEto4WmW4BqLxLC7HpEAUfaHH2qv4"
            },
            {
                "m/6'/1/1690896966",
                "eprv48WHj7FNJA45KjySr6Ejt6XxBMNA4JKgcJ3GGoJV6966UiAv7B5P9TzJ7fdrte56sadt9ku1E2pgmK4kXuQ5uxxMFa7sDhRueHbxCGK9SnP",
                "epub8fCKsXHcSXjkDD1EjjuLHWC4kNt6DdWbBbe3ZKLnWQtVKCRgjZtyKxcAHjAqi2bkvZUptvGSvkgt6mhPSiozgheKyQGdUXWqQPmZjWAMtb3"
            },
            {
                "m/8'/0/10428238",
                "eprv48JWS9SENvZ3ospvwgyqavSyHsobQu5TAJexZt2Ug9bxZkj4bSfxZE2zoWdgdY6aXN2Gxsfjkv6FRsVh7qhQvPTGeYRPbPJ7xTwuhrtm8XL",
                "epub8ezYaZUUXJEihLriqLeRzL75ruKXaEGMjcFjrQ4n6RQMQEyqDqVYjieryZ99u4Mvf9e28J8FM5Xkc7255xSdsGRrW3WNtdhXgaXtQ11gXfD"
            },
            {
                "m/8'/1/10428238",
                "eprv48ne33d9481ewE9ujKaCxhZJrBnReK19NGbS5VoiqEijqc8nSDTRGYH4U73DhUtPF75kD4vemhTepMtKdrPmJ6kuWv7GQ8tByT9bLbbySfA",
                "epub8fUgBTfPCVhKphBhcyEoN7DRRDJMoeC3waCDN1r2FWX8g6PZ4cH1T2tveBVH2vmn4EaGhRsqbNgtxPfmtEbJUPe3NNwU4hHbmCJYd7eRzSh"
            }
    };
    std::vector<std::vector<std::string >> child_pub = {
            {
                "m/1/0/119009092",
                "epub8eXtCyspq1ErY5QjX5r4S4BEbv3BXAgCcuNmr4Ga4ipRD9H1Vg8tbKhujXRBsequWDxCkFRDruyRnk2QxUUNHawyYXxFBUv6QwqJr5eZeHY"
            },
            {
                "m/1/1/119009092",
                "epub8fZrLZTMhvqgFxdPShM4WGr4cWMbGGofo3U6dVzTBb3xaAMjimNiP7cvNYkG2wwnzzzSkVPXC6oiB6ewxMxAnpNdmPUNRTntVb699oYntJa"
            },
            {
                "m/3/0/508355423",
                "epub8fbc2i1mvfXFVrP89Zut1n2Ac9LNE2ysSb2AxPD1JYxyfaet7weUB41nkGwnDe9izT2ak3edPgqcTGdr9LML7yNtWGR1DsfbXCRSp5VWLCC"
            },
            {
                "m/3/1/508355423",
                "epub8g6uXFniCkafYc2Rg1aiRaWcvEBPAKYARq6Rxq8ukhbDpYZHJW56LRTtKvvooBewYiRCjDCPJRNiziuqgxdEUzzVpyNqhHFeBR8Pjz8bcPz"
            },
            {
                "m/5/0/747301337",
                "epub8evyK3VsTLQ6wNWjFsCTUoPH3hLW5SPPoDstfx5xni7s3awUrV9AwfpRYpoFq6cPtpvX3xf7aEUyaUxkA8naEBi6HHmgDbXZD2L3sPF9r9X"
            },
            {
                "m/5/1/747301337",
                "epub8eYtwCpvYJxZpHuckxiKF5dAW1w7BvcC19L9f8sptG2G2b2rrXQvw9nr7uAEkxVr7GshVfpxyUhdntT2cGc2jb161mvK8QXazFhiUPbAj5D"
            },
            {
                "m/7/0/173432525",
                "epub8fH5FNKYqJKwWSfuriDg9QBVbHw7m1NfaQpYJhiug5DNrwtxAEoTv73DaLfftKaEj2tFpUSPTYhfXvrQQq2pJugkNo4CQvmBsRu2kaSRU22"
            },
            {
                "m/7/1/173432525",
                "epub8feKCAyRCVZTqES1FgM4tMenTCGTCoidNa5pejbdwgSFyx9LtiWf6n9WeQbp4uvyAiGu27LzHQH4p9dMhK32bhWB6Qw59BwPtR8xEgCLnwa"
            },
            {
                "m/9/0/1281305338",
                "epub8g4pnW3rk2y99DMjE3tmz8TbrsJrCMGvUerWRDnWxy1B77kRL87sJ5SVqgzCpFKDnFZqwTc5XHCt5Wzye2So9SLaGVYwMPQqJ7WHPKzbPQM"
            },
            {
                "m/9/1/1281305338",
                "epub8gDR1Q9t8efVMXzjG1qbxNU9GuNMDCTp5oP8sysfvCDss9oFsxNxxHqrey2aiscysMoUUzxTrC35Qn5iSoe5prst9aUGDv7gKXnsxTzQ2Xg"
            }
    };

    test_CKD(seed, root_xprv, root_xpub, child, child_pub);
}


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}

