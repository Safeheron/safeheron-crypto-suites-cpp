#include "gtest/gtest.h"
#include "crypto-suites/crypto-hash/sha256.h"
#include <vector>
#include <string>
#include "util-test.h"
//go native test
static std::vector<std::vector<std::string>> digest_message_arr = {
        {"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ""},
        {"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", "a"},
        {"fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603", "ab"},
        {"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "abc"},
        {"88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589", "abcd"},
        {"36bbe50ed96841d10443bcb670d6554f0a34b761be67ec9c4a8ad2c0c44ca42c", "abcde"},
        {"bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721", "abcdef"},
        {"7d1a54127b222502f5b79b5fb0803061152a44f92b37e23c6527baf665d4da9a", "abcdefg"},
        {"9c56cc51b374c3ba189210d5b6d4bf57790d351c96c47c02190ecf1e430635ab", "abcdefgh"},
        {"19cc02f26df43cc571bc9ed7b0c4d29224a3ec229529221725ef76d021c8326f", "abcdefghi"},
        {"72399361da6a7754fec986dca5b7cbaf1c810a28ded4abaf56b2106d06cb78b0", "abcdefghij"},
        {"a144061c271f152da4d151034508fed1c138b8c976339de229c3bb6d4bbb4fce", "Discard medicine more than two years old."},
        {"6dae5caa713a10ad04b46028bf6dad68837c581616a1589a265a11288d4bb5c4", "He who has a shady past knows that nice guys finish last."},
        {"ae7a702a9509039ddbf29f0765e70d0001177914b86459284dab8b348c2dce3f", "I wouldn't marry him with a ten foot pole."},
        {"6748450b01c568586715291dfa3ee018da07d36bb7ea6f180c1af6270215c64f", "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave"},
        {"14b82014ad2b11f661b5ae6a99b75105c2ffac278cd071cd6c05832793635774", "The days of the digital watch are numbered.  -Tom Stoppard"},
        {"7102cfd76e2e324889eece5d6c41921b1e142a4ac5a2692be78803097f6a48d8", "Nepal premier won't resign."},
        {"23b1018cd81db1d67983c5f7417c44da9deb582459e378d7a068552ea649dc9f", "For every action there is an equal and opposite government program."},
        {"8001f190dfb527261c4cfcab70c98e8097a7a1922129bc4096950e57c7999a5a", "His money is twice tainted: 'taint yours and 'taint mine."},
        {"8c87deb65505c3993eb24b7a150c4155e82eee6960cf0c3a8114ff736d69cad5", "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977"},
        {"bfb0a67a19cdec3646498b2e0f751bddc41bba4b7f30081b0b932aad214d16d7", "It's a tiny change to the code and not completely disgusting. - Bob Manchek"},
        {"7f9a0b9bf56332e19f5a0ec1ad9c1425a153da1c624868fda44561d6b74daf36", "size:  a.out:  bad magic"},
        {"b13f81b8aad9e3666879af19886140904f7f429ef083286195982a7588858cfc", "The major problem is with sendmail.  -Mark Horton"},
        {"b26c38d61519e894480c70c8374ea35aa0ad05b2ae3d6674eec5f52a69305ed4", "Give me a rock, paper and scissors and I will move the world.  CCFestoon"},
        {"049d5e26d4f10222cd841a119e38bd8d2e0d1129728688449575d4ff42b842c1", "If the enemy is within range, then so are you."},
        {"0e116838e3cc1c1a14cd045397e29b4d087aa11b0853fc69ec82e90330d60949", "It's well we cannot hear the screams/That we create in others' dreams."},
        {"4f7d8eb5bcf11de2a56b971021a444aa4eafd6ecd0f307b5109e4e776cd0fe46", "You remind me of a TV show, but that's all right: I watch it anyway."},
        {"61c0cc4c4bd8406d5120b3fb4ebc31ce87667c162f29468b3c779675a85aebce", "C is as portable as Stonehedge!!"},
        {"1fb2eb3688093c4a3f80cd87a5547e2ce940a4f923243a79a2a1e242220693ac", "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley"},
        {"395585ce30617b62c80b93e8208ce866d4edc811a177fdb4b82d3911d8696423", "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule"},
        {"4f9b189a13d030838269dce846b16a1ce9ce81fe63e65de2f636863336a98fe6", "How can you write a big system without C++?  -Paul Glick"}
};

TEST(hash, sha256) {
    for (size_t i = 0; i < digest_message_arr.size(); ++i) {
        safeheron::hash::CSHA256 sha256;
        uint8_t digest[safeheron::hash::CSHA256::OUTPUT_SIZE];
        sha256.Write((uint8_t *)digest_message_arr[i][1].c_str(), digest_message_arr[i][1].length());
        sha256.Finalize(digest);
        EXPECT_TRUE(bytes2hex(digest, safeheron::hash::CSHA256::OUTPUT_SIZE) == digest_message_arr[i][0]);
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    return ret;
}