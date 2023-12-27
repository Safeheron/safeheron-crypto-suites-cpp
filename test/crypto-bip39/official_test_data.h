#include <vector>
#include <string>
/**
 * Test data references:
 * https://github.com/trezor/python-mnemonic/blob/master/vectors.json
 * https://github.com/bip32JP/bip32JP.github.io/blob/master/test_EN_BIP39.json
 */
static std::vector<std::vector<std::string>> english_mnemonic_vec = {
        {
                "00000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        },
        {
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank yellow",
        },
        {
                "80808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        },
        {
                "ffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        },
        {
                "000000000000000000000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        },
        {
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
        },
        {
                "808080808080808080808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
        },
        {
                "ffffffffffffffffffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
        },
        {
                "0000000000000000000000000000000000000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        },
        {
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        },
        {
                "8080808080808080808080808080808080808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        },
        {
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        },
        {
                "77c2b00716cec7213839159e404db50d",
                "jelly better achieve collect unaware mountain thought cargo oxygen act hood bridge",
        },
        {
                "b63a9c59a6e641f288ebc103017f1da9f8290b3da6bdef7b",
                "renew stay biology evidence goat welcome casual join adapt armor shuffle fault little machine walk stumble urge swap",
        },
        {
                "3e141609b97933b66a060dcddc71fad1d91677db872031e85f4c015c5e7e8982",
                "dignity pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk host tomato cradle drill spread actor shine dismiss champion exotic",
        },
        {
                "0460ef47585604c5660618db2e6a7e7f",
                "afford alter spike radar gate glance object seek swamp infant panel yellow",
        },
        {
                "72f60ebac5dd8add8d2a25a797102c3ce21bc029c200076f",
                "indicate race push merry suffer human cruise dwarf pole review arch keep canvas theme poem divorce alter left",
        },
        {
                "2c85efc7f24ee4573d2b81a6ec66cee209b2dcbd09d8eddc51e0215b0b68e416",
                "clutch control vehicle tonight unusual clog visa ice plunge glimpse recipe series open hour vintage deposit universe tip job dress radar refuse motion taste",
        },
        {
                "eaebabb2383351fd31d703840b32e9e2",
                "turtle front uncle idea crush write shrug there lottery flower risk shell",
        },
        {
                "9e885d952ad362caeb4efe34a8e91bd2",
                "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
        },
        {
                "7ac45cfe7722ee6c7ba84fbc2d5bd61b45cb2fe5eb65aa78",
                "kiss carry display unusual confirm curtain upgrade antique rotate hello void custom frequent obey nut hole price segment",
        },
        {
                "4fa1a8bc3e6d80ee1316050e862c1812031493212b7ec3f3bb1b08f168cabeef",
                "exile ask congress lamp submit jacket era scheme attend cousin alcohol catch course end lucky hurt sentence oven short ball bird grab wing top",
        },
        {
                "18ab19a9f54a9274f03e5209a2ac8a91",
                "board flee heavy tunnel powder denial science ski answer betray cargo cat",
        },
        {
                "18a2e1d81b8ecfb2a333adcb0c17a5b9eb76cc5d05db91a4",
                "board blade invite damage undo sun mimic interest slam gaze truly inherit resist great inject rocket museum chief",
        },
        {
                "15da872c95a13dd738fbf50e427583ad61f18fd99f628c417a61cf8343c90419",
                "beyond stage sleep clip because twist token leaf atom beauty genius food business side grid unable middle armed observe pair crouch tonight away coconut",
        },
        {
                "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
                "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
        },
        {
                "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
                "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
        },
        {
                "c0ba5a8e914111210f2bd131f3d5e08d",
                "scheme spot photo card baby mountain device kick cradle pact join borrow",
        },
        {
                "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
                "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
        },
        {
                "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
                "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
        },
        {
                "23db8160a31d3e0dca3688ed941adbf3",
                "cat swing flag economy stadium alone churn speed unique patch report train",
        },
        {
                "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
                "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
        },
        {
                "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
                "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
        },
        {
                "f30f8c1da665478f49b001d94c5fc452",
                "vessel ladder alter error federal sibling chat ability sun glass valve picture",
        },
        {
                "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
                "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
        },
        {
                "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
                "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
        },
};

static std::vector<std::vector<std::string>> simplified_chinese_mnemonic_vec = {
        {
                "00000000000000000000000000000000",
                "的 的 的 的 的 的 的 的 的 的 的 在",
        },
        {
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "枪 疫 霉 尝 俩 闹 饿 贤 枪 疫 霉 卿",
        },
        {
                "80808080808080808080808080808080",
                "壤 对 据 人 三 谈 我 表 壤 对 据 不",
        },
        {
                "ffffffffffffffffffffffffffffffff",
                "歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 逻",
        },
        {
                "000000000000000000000000000000000000000000000000",
                "的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 动",
        },
        {
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "枪 疫 霉 尝 俩 闹 饿 贤 枪 疫 霉 尝 俩 闹 饿 贤 枪 殿",
        },
        {
                "808080808080808080808080808080808080808080808080",
                "壤 对 据 人 三 谈 我 表 壤 对 据 人 三 谈 我 表 壤 民",
        },
        {
                "ffffffffffffffffffffffffffffffffffffffffffffffff",
                "歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 裕",
        },
        {
                "0000000000000000000000000000000000000000000000000000000000000000",
                "的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 性",
        },
        {
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "枪 疫 霉 尝 俩 闹 饿 贤 枪 疫 霉 尝 俩 闹 饿 贤 枪 疫 霉 尝 俩 闹 饿 搭",
        },
        {
                "8080808080808080808080808080808080808080808080808080808080808080",
                "壤 对 据 人 三 谈 我 表 壤 对 据 人 三 谈 我 表 壤 对 据 人 三 谈 我 五",
        },
        {
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 佳",
        },
        {
                "9e885d952ad362caeb4efe34a8e91bd2",
                "蒙 台 脱 纪 构 硫 浆 霉 感 仅 鱼 汤",
        },
        {
                "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
                "父 泥 炼 胁 鞋 控 载 政 惨 逐 整 碗 环 惯 案 棒 订 移",
        },
        {
                "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
                "宁 照 违 材 交 养 违 野 悉 偷 梅 设 贵 帝 鲜 仰 圈 首 荷 钩 隙 抓 养 熟",
        },
        {
                "c0ba5a8e914111210f2bd131f3d5e08d",
                "伐 旱 泡 口 线 揭 县 杨 断 芳 额 件",
        },
        {
                "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
                "福 惜 怀 叔 筋 酵 货 科 牙 冒 辈 罩 悬 耕 浇 呵 连 级",
        },
        {
                "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
                "仪 未 九 茶 队 梯 妇 孤 托 病 泉 贺 产 绘 吹 测 局 碳 征 墨 晶 帮 息 延",
        },
        {
                "23db8160a31d3e0dca3688ed941adbf3",
                "济 扶 块 言 穗 定 万 绘 姻 逃 颗 焰",
        },
        {
                "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
                "虑 铺 目 祸 英 钩 尤 添 醇 嘛 触 独 起 赋 连 剪 邦 中",
        },
        {
                "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
                "而 怕 夏 客 盖 古 松 面 解 谓 鲜 唯 障 烯 共 吴 永 丁 赤 副 醒 分 猛 埔",
        },
        {
                "f30f8c1da665478f49b001d94c5fc452",
                "昏 途 所 够 请 乃 风 一 雕 缺 垫 阀",
        },
        {
                "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
                "瓶 顾 床 圈 倡 励 炭 柄 且 招 价 紧 折 将 乎 硬 且 空",
        },
        {
                "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
                "柄 需 固 姆 色 斥 霍 握 宾 琴 况 团 抵 经 摸 郭 沙 鸣 拖 妙 阳 辈 掉 迁",
        }
};


static std::vector<std::vector<std::string>> traditional_chinese_mnemonic_vec = {
        {
                "00000000000000000000000000000000",
                "的 的 的 的 的 的 的 的 的 的 的 在",
        },
        {
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "槍 疫 黴 嘗 倆 鬧 餓 賢 槍 疫 黴 卿",
        },
        {
                "80808080808080808080808080808080",
                "壤 對 據 人 三 談 我 表 壤 對 據 不",
        },
        {
                "ffffffffffffffffffffffffffffffff",
                "歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 邏",
        },
        {
                "000000000000000000000000000000000000000000000000",
                "的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 動",
        },
        {
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "槍 疫 黴 嘗 倆 鬧 餓 賢 槍 疫 黴 嘗 倆 鬧 餓 賢 槍 殿",
        },
        {
                "808080808080808080808080808080808080808080808080",
                "壤 對 據 人 三 談 我 表 壤 對 據 人 三 談 我 表 壤 民",
        },
        {
                "ffffffffffffffffffffffffffffffffffffffffffffffff",
                "歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 裕",
        },
        {
                "0000000000000000000000000000000000000000000000000000000000000000",
                "的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 性",
        },
        {
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "槍 疫 黴 嘗 倆 鬧 餓 賢 槍 疫 黴 嘗 倆 鬧 餓 賢 槍 疫 黴 嘗 倆 鬧 餓 搭",
        },
        {
                "8080808080808080808080808080808080808080808080808080808080808080",
                "壤 對 據 人 三 談 我 表 壤 對 據 人 三 談 我 表 壤 對 據 人 三 談 我 五",
        },
        {
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 佳",
        },
        {
                "9e885d952ad362caeb4efe34a8e91bd2",
                "蒙 台 脫 紀 構 硫 漿 黴 感 僅 魚 湯",
        },
        {
                "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
                "父 泥 煉 脅 鞋 控 載 政 慘 逐 整 碗 環 慣 案 棒 訂 移",
        },
        {
                "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
                "寧 照 違 材 交 養 違 野 悉 偷 梅 設 貴 帝 鮮 仰 圈 首 荷 鉤 隙 抓 養 熟",
        },
        {
                "c0ba5a8e914111210f2bd131f3d5e08d",
                "伐 旱 泡 口 線 揭 縣 楊 斷 芳 額 件",
        },
        {
                "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
                "福 惜 懷 叔 筋 酵 貨 科 牙 冒 輩 罩 懸 耕 澆 呵 連 級",
        },
        {
                "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
                "儀 未 九 茶 隊 梯 婦 孤 托 病 泉 賀 產 繪 吹 測 局 碳 徵 墨 晶 幫 息 延",
        },
        {
                "23db8160a31d3e0dca3688ed941adbf3",
                "濟 扶 塊 言 穗 定 萬 繪 姻 逃 顆 焰",
        },
        {
                "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
                "慮 鋪 目 禍 英 鉤 尤 添 醇 嘛 觸 獨 起 賦 連 剪 邦 中",
        },
        {
                "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
                "而 怕 夏 客 蓋 古 松 面 解 謂 鮮 唯 障 烯 共 吳 永 丁 赤 副 醒 分 猛 埔",
        },
        {
                "f30f8c1da665478f49b001d94c5fc452",
                "昏 途 所 夠 請 乃 風 一 雕 缺 墊 閥",
        },
        {
                "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
                "瓶 顧 床 圈 倡 勵 炭 柄 且 招 價 緊 折 將 乎 硬 且 空",
        },
        {
                "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
                "柄 需 固 姆 色 斥 霍 握 賓 琴 況 團 抵 經 摸 郭 沙 鳴 拖 妙 陽 輩 掉 遷",
        }
};
