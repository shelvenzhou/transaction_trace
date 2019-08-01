import logging
from collections import defaultdict
from datetime import timedelta, timezone

from ...basic_utils import DatetimeUtils
from ..trace_analysis import TraceAnalysis
from ..results import ResultType, AttackCandidate

l = logging.getLogger("transaction-trace.analysis.Honeypot")


parity_wallet_addrs = [
    "0xc8330a4c8c1ec7304ef887c48f1d715f6838ac34",
    "0xa382dffc9b6a0f13cc74a881c6b5fe0e67493fca",
    "0xfe1069d03e640f79f519862cf2beb6d642c6c2c5",
    "0x248743463983b3b0c667717bb8c30e5ac79199bb",
    "0x47a8f1938cc353cf7ac55e58c01041d73397866e",
    "0x5ff91865a451a09fe706ce5eae8591176709ab3e",
    "0xc4724c8546c9c4e26d08182f803e0b51a061357e",
    "0x6cb2bc8af04dc5da25dfa001be49d65872e32e79",
    "0x70567688019c11e414d9aadc133df158ed62ea06",
    "0x8d2ee01dd9e947067fda69e3b62064556a92d1c8",
    "0x1a4a470c2f8ba954b8bd220f5cf67e47da02afab",
    "0x3786f1baa3343a74e1f5325b7a99e769b0bbab0e",
    "0x5ef23c65d747e38a26175d6042337e6cc04ffa52",
    "0xd31a34d621122bebe0dee360e33bbe61193d5b90",
    "0xfbbe877a949e8eb1db740ebb3ef020b20b9fbbfa",
    "0x5a86492154ccf6f51c7e30f7caac96c6d970149d",
    "0x7c56961d3c90313561758e7b4163e4c2f8da0a79",
    "0xf3f5d63fd032c16cdef380caa96e4ce46b673115",
    "0x260a28a165081f5cfe94454543514e76ae746410",
    "0x1e71c36fa78096ad934acc5caece41a1102fa944",
    "0x60332cffff9c09427be46159570552f6f240c0be",
    "0xfbee8fd47bd88ec4c045b3e0d10832a410dd9823",
    "0x8e4b3eadf078a80a3308da16fce741c2c20305a1",
    "0x376c3e5547c68bc26240d8dcc6729fff665a4448",
    "0x5b523bd1a0346f52acf33dedd4ba697974cd86bc",
    "0x10abe2494e4525f8cd2bac772671f0e1a44c6975",
    "0x12c413b8113e1e3c7026b36453690c95279208ec",
    "0xdb2c56839381731015c6b077a48b37931472f3b9",
    "0xbd6ed4969d9e52032ee3573e643f6a1bdc0a7e1e",
    "0x8f4b3c36196a4c94c69debded3060424e339c2ea",
    "0xded679f2fd307e1c8bf8a5b20e3d4178369bb996",
    "0x2026bb1dcc41abdae6864a8b76b5134dd8330195",
    "0x6344d1d10befac3f4b646c4bc7166ff08d46b40a",
    "0x9b6fd6fef6e5be6191b69f2e69c3018393233fca",
    "0x22dc62c96de482743b231f29326a3d18b2d73eb2",
    "0x58246c2f07a89ae49faf6fa629b1c034e8efba04",
    "0xc92cbb01fb1fcaa2c97bc4fa02a355c9bb1d2a81",
    "0x2993753c24323d9152e69f6589109f67b2921dac",
    "0x3d5ef5bc2455f374a255bf59adb2b32b89852b5a",
    "0x47d4d2b35d1f1ab19092978e77f59addffe65aec",
    "0xdb0e7d784d6a7ca2cbda6ce26ac3b1bd348c06f8",
    "0xd716558a8decc07958ae1135fde3ab52c810e4ee",
    "0xd7dfc49e5d13f77830029134fb06f5fa6d5e8ec4",
    "0xba3dfb3e317e5e73b6ef7f6093fea825cc632c6a",
    "0x73f879679b0fd8b25196834fe3e7a9615ea1b608",
    "0x39a5c0807a6ca01b639ee617ce5a616910c35539",
    "0x4022cc301cdfc1df7e1db82c7a0b4448ec1c4df8",
    "0x7bfc9294c9ae9d17a5abd6839b1301622a523640",
    "0xb057e153bc1d616dfa756c48037870d817b563b6",
    "0xa4633ce0cde310ce813ae9b3bdccad7b6db83390",
    "0xc6c554d741c0eac1f70deaec54943f62ac25946a",
    "0x130a542a258401625aebd190457f25d35cca8301",
    "0xbf8d6bc02bdf4828a1adb7951ec1409fb8ec582c",
    "0xcb196f14ca2dfd8a0bbe9334297d531f4c4b7ba4",
    "0xec4604d5db119b12b0940c01e71738c132a53354",
    "0x9ed5cf624a0fd02b2beb911691d2a8db0b63937a",
    "0x4b190b856007286aeecf6a726f9b0ef0eab5447e",
    "0x764a1c7bfd2a8dba90f41226c54e9bf88c706258",
    "0xbc0b668a81c4410d2c345eb3e6cd168a207e1b97",
    "0x01e5be25eb25a0b4ffb73d34a0b5b72b49dafa7a",
    "0x7f455c9c0181b8e671724aa71178925a1a487bf4",
    "0x361ece54a07f979b231aa77b01f10f5e2d60312b",
    "0x57d6729f695137efc32c9592c9f879162ba81c8f",
    "0x7ef1839b5b704a6a16d8eb0df8c566f8ed335308",
    "0x74864c79bc0a9da30b481a4d83b399df6cc15fea",
    "0xb4e63046001074b223872137174eec63a7e12cf5",
    "0x0a7b3acda33aac1eeebcde16e2987b01dd577904",
    "0xb760caf6272fead30bea2143c71d36ea85a64298",
    "0x0a14ff4ab24373fa0cbdd81b05326969b25c9ea5",
    "0xd1f4b2bb61b2dec72d5222a6beb062a9575d6804",
    "0xcd48b208de2cb871be5143d3cf29ff879d02dd1b",
    "0x64ac37c60a0d16aed4e48f27fc8a7c78b839e9ca",
    "0xb19bf165dd18009e74cd45c9b42fbd81ff985de9",
    "0x927a1af0a4f6584ef3255761290e7f657f120588",
    "0x397f22f6c4bc789898a6cda954881908348c7f00",
    "0x3c91bc1dcc872bede647dac18ac5ee4c861f2c15",
    "0x7cda7e8f32f2c37e4aae627a98ed130eb4a678f8",
    "0x7f4513ca0825ddb484763f8e96cf6d61207f125c",
    "0xfe7e3ee7d3fcd8f3957aafb8348a38d229e4409a",
    "0x3fcf5019220095982ebfc1873f48f65ac6c4a4c1",
    "0x2b3b7578d4af42bba2ecfa749ce8b4b570bfa1a3",
    "0xb76250b38d57055c96fcd75abccb27ee8b931e77",
    "0xf82edcd70fbec5ad9a80afeb4c54c581af929bc7",
    "0xc1711a9f824c8e54cad7ba0842afa9e4a209a711",
    "0xa90eab04e963e3cc086a2d3d1ad5e74fd9f88b8b",
    "0xc0968d7e104a06357c69e04e260a483b30c29a05",
    "0xa7950e88d0c41c1396fcb84c2d50286194538b8f",
    "0xcf113c0b3dc0b8159174ea2e950a9792e925bca8",
    "0x5fe4d1375c34933cec23ce6ec903b591dd5331db",
    "0x83d20d869a9dcbe6c49c553735beecdbd6c802fb",
    "0x039704a4ecf78b0e1eef8f181a7838a0c68876ca",
    "0x43c0d31adb89df0e6b02bf2bd9acb0696fe41e46",
    "0xbe17d91c518f1743aa0556425421d59de0372766",
    "0x28c4b59e6da29e9e3a0b68837f9e0bf16763e868",
    "0x0da3a765ee9ed638d4cd059e5981ad1fe46a6949",
    "0x52c643150e71207153931afe91eaa42a6e18d409",
    "0x325d5e031c3c0f6e1cbbc52a9cb46d296139b4ea",
    "0xdc0ca849bbe85c6e43b1e7e7f9aafd65e59154e7",
    "0x6bbb55bde42bb38f0fe70f3579c762bd6904813c",
    "0x8fd3c6fb67a0a65e1353945da3a7cac1c1d14cc9",
    "0xd8d00f087432ee962d297c7619471f6f82c3b915",
    "0x8d0edc2c55ba4337335e686b88bf40faaafb9797",
    "0x6c944ade51842cc3f557853619cce328c3d138ad",
    "0xae50462e7ed5b22f31b1ed3a5ef3fb9220277ef7",
    "0x8b7af85a82c081ba4ba556e925547325fae43b98",
    "0x26bab9b0f5b13b0de1bb21497c356a88a4173dbf",
    "0xbfcda554d44cfe6b953b98c4729ddab09b2989cd",
    "0xf34fc048d524e3c52d4db26d52095bf67ab5cea1",
    "0x18ad3d43ed8db2b991389c703b6c945f96ffc116",
    "0x0d74d7843f9ef6782a28181d85239ba735e6a13e",
    "0x8e2495bf4ca2eea20635e15d0b2837ccdff70453",
    "0x0399f871448b0aee36180be78951ceea033c40c1",
    "0x49be90abb08f304dc3ce4d9cda7e5abed79e01cc",
    "0xa113f56092cefb9255c56813de43c6ca2d80681c",
    "0x1a7e8e64560cc3ba240ce98e11ebb959196c6e83",
    "0x2c0be2d4aae83a8d5d92cee3f966da3043a1242e",
    "0xab88b9bc99476dd4d7d8a1d8381066519359f243",
    "0xf1d99c208a1d8c7d3332df459a2068c18735d60d",
    "0xf6c329e9754eb9bbc20627d448a15c4de99ef557",
    "0xf0374a28f7cd967a153e5e837279ba4ebf60412f",
    "0xb52284ffe2560aae7b4b61a4fd079d9ca8a8aeac",
    "0x1f6b7e00acffe252163f66b77d1e2032c09c407b",
    "0xc5307f3b7f3078b09fe263feb6be98d0c68ee489",
    "0x9d8fe087ccbdee7ad4429319421b347b26eb29bc",
    "0x5a2b63b15a8bf61e4f322c39c18b48a67a9cdd60",
    "0x8a2e61965dab7cbdada24aaeb54612dc882395d5",
    "0x37bcaf9ac3c28493a8f4210b112ffe196e27b6dc",
    "0x810e5f7f6e986f27a8e7bbfc5f69fa0d38a96777",
    "0x69ad38baa72a277cb83d1eccc6279552e0f25dc0",
    "0x2f56c5f0b2548ce52fac5512b76eadbb2c511a7f",
    "0x570f77473c329a5149fe5d5786d8759e38ed15be",
    "0xedb480c85c77e3ac3fcc11e8460fa46a77024fb4",
    "0x32a5b17b23d70124c9910b177b131ce3281a930b",
    "0xb87c0ed78caf43ce2843ae1ac3edb7d499673a33",
    "0xac2cf4362b4d701a14db72598827c8840f88aeb1",
    "0x570a68c562af83112d8d0b680661472ba1a9279f",
    "0x67b52b4b693dba3d8c1534b0c1dac27cddf97b2f",
    "0xbbfdf18cf2413fed31293840aa1a1ee7bdfbb170",
    "0x2faea22bbd8a0a5b73bd306a06e2b42dce879a7b",
    "0x20b014a0b669906781250cdcf9966d5c4ce1527a",
    "0x9fc9e6fe3567cfe89cf8de12ac051955b8865308",
    "0x7bf67bdbf58a3c7a6eab82788273960702fb4dc9",
    "0xa34ffdfc968a80ba1c77248520cf60142eb63ca0",
    "0x674ea6ce0e381c3b96107c9962b1880b09392c41",
    "0x19d8acac27553ef390d287b532bbc1f9fdcc261c",
    "0x6a53b3fb6d25c07072ec03009750fef5c44f357d",
    "0xe37f73f567c142d84393b5e34d13300f2ec64b1f",
    "0xae824ca7fbe8e9eba1ea3ee046148c49851157b2",
    "0x7cb40f0df5a940b6785baba223620ed2e5a65975",
    "0xf39fc9bc6b3d39333c3663e89f887a7c6eeb84eb",
    "0x6c5d4a057b94136d0e2df7a76fb0af7e80ac4923",
    "0x5821a5527eb2e84c2566d0c7dae988447d20b984",
    "0x7b6bce3cf38ee602030662fa24ac2ed5a32d0a02",
    "0x01dbb419d66be0d389fab88064493f1d698dc27a",
    "0xffa9477927cf6a7cd2ccd4cb23ca2349520ef872",
    "0xc23f09446ea7cb24bf916801e38492e5318b2b71",
    "0x1929beaa12130bbac95f62ebbe6c0d3d2dfba719",
    "0xeba90b310b464c20d409de6de7a75735bff63dad",
    "0x637cc72b210546e0af1590fd2c9153501f3d1bfd",
    "0x34419291f875a4107e44a3def489f1dfe17b067c",
    "0x0cc12572d4028e492a919fe82feeda53fe43782f",
    "0x5f3ce3907e7e4c5b5b8d04dd3211ca8b81a64733",
    "0x083e6d4450407e5a0ecad6abdd4c5b4f55218a76",
    "0x63c88f2d1d8f4f9f669fe2064c7fee4a7a26d949",
    "0x2249263274f2f4caf409dd45141a8f6185a36369",
    "0xd5d89ee27c3417bb59138eb14c5883b704cc3e67",
    "0x6a45c0ac25b9e6e4b07d9a37fca6de56766872aa",
    "0x9cf8c9cf58cf5b3d41f142ceff9488d5d189d6fd",
    "0xaa693f51d92179c282c700b7e2a6e7052823c291",
    "0x8bbaf6956e8e2aef3eb8f192f5eaf48b4bbbb126",
    "0xfae8014dc8bd8806421dfa4c538a770b3d3541dd",
    "0x042d7b0069b6170c70e6a6aa02dec93d78785eb4",
    "0xa7bcd18b8785db796d309de9283ae86bf007ac0d",
    "0xb0c79c5e6cf2dc806884a076cb47c577fba22eb9",
    "0xe326e3d9a272a56ad12068fb097ae2f0e6665013",
    "0xdf58f348ed7e6656d06a8b8d27ac9d99e5d64f87",
    "0xc78fab6904ced168b894d205d209e95708fa4809",
    "0x700f39cdb7a27bc63adcff51415939a2e6836e3e",
    "0xc02b2a14f767badb6c88e5a62187494b79df5fc5",
    "0xa9773163b1d0d317fadf3a48f2e348d671d5cd8b",
    "0xc6628bc3d0d5f474a40afcd407c193fd671b1cfb",
    "0xc6c19cea659142f046289e97a5351808541ad904",
    "0x4ef53d1d6d484cf7a0ec809aa1a061119d9fd0e0",
    "0x06054d65be538e354e3b6d8ebe38ef3ee8764662",
    "0x03a62c4b61e7118025b8c253b2e09cf74ca0f31a",
    "0xd42fb59059369cc6af6052a4bfd55884c975533b",
    "0x569ebba9f5eebe8ed3e70053dfe78af72714c1aa",
    "0x16ca1cc14eddb7979191eb231302ae972fa435e2",
    "0xd73982a5760f9e54b66506fb5b004cb7e93886a7",
    "0x049671341b35f43c703829ce1cc6c91e68816a05",
    "0x117812f50df15c724948add219d2ad519ad73aa8",
    "0xcf6fd94d077a08f4e800ad01ba4faa01d9c27779",
    "0x3d52571f1ce8f035da1c1ed716f3055790274549",
    "0x065e19a1228ff454229afbd19b20467129e42a7f",
    "0x6d95a950998dfb327d87298509b2f0a7364a164a",
    "0xf3f1d3a7a681349e859b6559270541f6ee2b465c",
    "0xa4c3558924442efc6a7a33d827622532897a894d",
    "0x770c49391fb6d18513c006cdb1ea383ada714d9f",
    "0x196f109ab5d47389b9dae0c176387ca9f90869af",
    "0xe036d56232a2646970aa70410fe23d649967f0b9",
    "0xa8871d303c501c39deb2abe118691eeeea813e30",
    "0x1185181ab325fe0887f2cdd42a16cafc8e721861",
    "0x588536a48b9d47d3117016448926a5e4ffd3b512",
    "0x173b713cca8e97a21cbd0060d7971da23aa8d4dd",
    "0x93202dcdbe77c43b3d6035afa0b5fa42fc4662d9",
    "0xc1897d8dddf036491aefbdd4c3edf6b8595e75a4",
    "0x2cd5a2e0623791eaac6f95fbce81348958520d07",
    "0x9bf10b45de13f8e1144152c89e550e291b457dbe",
    "0xab87948fd3972781506ed52b83c500a4c743daf2",
    "0x375203d21e61b477b4577840ec538c008c12e2ec",
    "0x8e994e25be46c822889e666f4334608580de20b7",
    "0xf6a4384aa41f74714a71e01b3f3faf75a6e879bc",
    "0x8ffc7827beef0893941a22df4a0c4f7c23e01621",
    "0x1f6cbb740f7eeb4806276376e7378dd1fa36fc11",
    "0x5a8a0138114dcdf7bb4a27a2a03fb64cf66ad2e3",
    "0xb68dd3322631244b553fea98040399a4258cf04d",
    "0xdc597b6fe4ba767e5af5cad650953aa7bff211ff",
    "0xf756d77e78a21e1aa0e5394a2c49374210c384ee",
    "0x91efffb9c6cd3a66474688d0a48aa6ecfe515aa5",
    "0x7b36434cec98d70cc64ea93f3d9873d4edca10cb",
    "0x30b3c64d43e7a1e8965d934fa96a3bfb33eee0d2",
    "0xd707e69e6644c2d9709a21acd7b8fbfe5a6de1f6",
    "0x54f0fa75f13d2dd521e954adb3ba208611250f65",
    "0xcc98745f40c668ccf6bd97a6fd954551bcc1e650",
    "0x22b723ca01bf41fd4ea69016f020af206c1de8d6",
    "0xc630a71b2dfbcc621affd33257132b50adbe1cd0",
    "0xdf86984226814e2970ea94fedd9676276fedfacb",
    "0xc7cd9d874f93f2409f39a95987b3e3c738313925",
    "0x475f51c7e51e383f70156cf1fa6c21ba0de0ce69",
    "0x8da4fdb54691fa76a44f7a03f8bdcd3da5216243",
    "0xec3de59c77da42b652d83c6c038396e94de9f189",
    "0x8d5e5f250a1529ef52adcd8a8912f85d339dae6e",
    "0xe0b93a625693a33221cf9bd534ae790ea59a9ba7",
    "0x046ad5aebde812a3c04ec48d50c980edf87edb5f",
    "0x71331c46fba44d85e293d63d1d5a8cdadf264451",
    "0xeecaa19b38c635de7a45e2e264b02853bb9a6d10",
    "0x0614143a9639d3731f343805f098cfe107e756e6",
    "0x248c9bae4fee646906821155ef1a538e7ca978ec",
    "0x568742c9170df9eb358453ba43ba535d24a9967f",
    "0x32b0663b7853ba76b19de69c46fc40fced09bf00",
    "0x49eafa4c392819c009eccdc8d851b4e3c2dda7d0",
    "0xc965c6ef32ccc278181cbc68573fa0a5f1997b17",
    "0x37764fe50340f0158b9facefb3dbaf5222e34a3d",
    "0xd0f706bf4738732145344dc407d36b88859c3349",
    "0x59bff5a17995fa99686de6200ff3032128aabca8",
    "0x51ac2051db10b0d05462ef1d7c3f7afd43ed8be7",
    "0x3cb0d9caf35feadfe090cd55202f45076b7e3e14",
    "0x4c7e21914b6a1c7183455134e24023e88ee90cd1",
    "0x08894447d2d58d6bd47def5e0e4cdf9f4127e582",
    "0xe9bc058c9764f5e9ff39db8b54e7a8a3957d729d",
    "0x68952c720dde3a0827bfd70a60d48c8d9588fb45",
    "0x3cafc5070e24d4fd7ea55a6daedffc51a0dbd80e",
    "0x8a65df1c21800cb3860d7ffab517bcceea685fb0",
    "0xabe6ea1e6dc0add78742bcc07306cb79323d083c",
    "0x75520dafacbe7669820f82709ca2feae9ec4f57d",
    "0x7f379a0d99d224d487ae4751cbf261ae6037153e",
    "0x5ed38634c678a8d5a95234b4b7b2ca07e5bb80a0",
    "0xc319eb3e7e54c22c2d0d62f1512527469931607b",
    "0x5acb62c7657fd814f3cadfe07bf009728d3a7d18",
    "0x770b2a36a396f47ed0b6ec41d9d6e77fc1c48985",
    "0x7ebcdaab21a47bc4a7bd29898ec42a2fe166f740",
    "0x3085335d03541c007fb7b15e9112ca1f364ad8bb",
    "0x14236995526230feafc1d6ea94f8e0c59ec09f1f",
    "0xb52736b178bf12f133b0bbd108650b3b4121ef5c",
    "0xa9b1d13399687fcfab76c9a52ad59cd225134ec6",
    "0xf59fe4c9cfa9fb23a79e74a5396fad24b95c492b",
    "0xd93719574b0bc5f691f5da8cae9599cec1f202c7",
    "0x10e301560860db30dc1bc519a99aa860bc71f076",
    "0x15ce1c7f4f27fccafc863054013a19022e527419",
    "0xb3820ad39d0e422ac1fe5001dea63ab37a041b30",
    "0xff8bf534e3a188051743dc0da04ded57973f815f",
    "0xe17dda15b701364b1fb1146b9f063ea37316e80a",
    "0xb9c85a96be9f7e575f8bcf49506d3d5577b5d49e",
    "0xefc0290283c59572fc03a6cc433831935477ada3",
    "0xb94f3a5ca67be4b33c73c16e84d7cd82277d772c",
    "0xd912a9d8bd2390648f29e8f6734d860771efcd19",
    "0x48122a114156c314cd49438b08d59ac64138a8f3",
    "0x25a13f69c3eb7fd8e7ae4df6d2ebfc1706b35c5d",
    "0x8aed4f7475f0ac5f7973f55cf685ee026c2a1eaf",
    "0xa0c8ee19a69ad6d021959b69476416aac1d4ea10",
    "0x3b38a42018b658da3655492634ee30fb8196e697",
    "0xa71a61e0bd73f919f9a55a6bc0d39ca279c7ce2f",
    "0x02665a0d6f28260e0395863135276ebe793e246c",
    "0xc0ffee60fc383278fc94885d7f7584977bfa00aa",
    "0x4e2d0c204554c7f9cb1e3b3ac1e83dd3b4fc9622",
    "0x93ebfb624be70e131c78bf3e75cc269a92727b8d",
    "0x1f4fe4426bb6936b1007bb0a30f2f46e7c1b64dd",
    "0x20ced4af3f0924640efd751fcd6b1e467e5b6457",
    "0x50073fbd5814cad94e60e85407dca3695d8d0439",
    "0xc1f67ff7482bd4ba2aeadcd523b9ba57bf08ea07",
    "0x6b996ea4b3f311a3c3864549ec8df10133d94b35",
    "0xdedf4048d36d340abdec6249b863ab86021d91bd",
    "0xd95a6aa3e20397211e487b231211e16790a21ac9",
    "0x6b1c036cd31e4a3d09599451a8172eae2e7b0254",
    "0xb55b05e604b42d29a2e429552bc964986db9244c",
    "0xed1475eee0c969d4877bd05ffdd6bfdc84b821da",
    "0xb14613bb377a5b9ca206131642b7c2cc723cc918",
    "0x5913937255279654c16c655cc2ef40c7050311a2",
    "0x74b8ebae3c02f248eca5b1ef7b50d4d9c49f70c2",
    "0x78bb49e80972bf8e5cca4b5092e07ccd272169d6",
    "0xc3836aee8938c790b5bbfc7e8bb82815e6bafcdc",
    "0x607f7d9029ab9e46d8b4f0a4e9373dd1b6711e18",
    "0xcf37d3d08d006426ac01e6c4cd1f679bf3983be9",
    "0x9ada4303a1953faf0762b3e25db2c1f765d1adcf",
    "0x0b23618ad378a6ca9caa4ec2c395f40023012dc6",
    "0x60b615df286f732e9b148a6a1de42afc005dc2c3",
    "0x851286854a2c56eb74a082fdad9d3cf87a218df9",
    "0xb4ff3fae88e93587321aa409b96467c4f11cd539",
    "0xda277dc94f0008216f5af59d7ce0990218927ebc",
    "0x4d6eb94205ed1ff9d0a20bfaaec2e8c196cf0908",
    "0x1b4080a17e3f7e29c40c1be4fc34cb6d3c6a61bb",
    "0x60e2f9eb6fa7cd3984101c4b07d84cc5381f47c3",
    "0xb3740cefcc201d5cf1fa59143976332563314d82",
    "0x0766f0f54ded283e3d682864a126cb7f85d4ae86",
    "0xf968080a985152828441f6c9b916514e75b98651",
    "0xbf764eb314daad130dbad1f75aec54990f21c29b",
    "0x3d578574e5f8e5db7936b95220e335dca7e8bbce",
    "0x7f8e70a2851942346eb08ac9b506f83ffbff1138",
    "0x43d3d1a57c30a27d78c6864048cb3b7e08957fd8",
    "0x80260b19fa28b51aaf61dcc5d3846f206eaa2ca1",
    "0x1dd289285f47fd46afa32397b845a5dccf1767f1",
    "0x788b28b5cb82a6d73001ed2b2f045e0b5186fd64",
    "0xc05e74750f05e8719e56366f62328ce12052da49",
    "0x496d9b487b78090d9ba0b15950da35bc213dd4bc",
    "0x36ea441a8a3a0984fdb201d26fcbb2483523653d",
    "0x3b860c53319a80b7cceaf31a230090aa91204d0a",
    "0xd4d2a4b571109ad1397e953ab87d6e5feed031b2",
    "0x925b853fb8c0f417325839113550a82a4530e09a",
    "0x1dfd75c71a3658a95dc8c677c7689a140f0afb2d",
    "0x90f737392c48618242b28eaa8d4fdc4793af2676",
    "0x2dfec8a8ca774691d952e985fbd82a793a827dae",
    "0xedbfe215a3c7f8fb95cc993c31a8dd445de27e96",
    "0xc2424f85a3cca6e9419d70f23a6146f505bd0143",
    "0xde027cf0de25ab09a1b7612cab455f29a8478dc9",
    "0x62bfcfab786cd93c6c3e9224ab451b99bb26a64e",
    "0xfd2b11f7e1b58c7f9ccf5479aab8ed4bf7a7ee8b",
    "0xdaf9347ca0ffbc04512fd8257d56b3a125d21a77",
    "0x2aab51f6c6dac9c4484e22220bf97dfe1431950a",
    "0x9581ba163b67786d21d539def28e27019fa7a66d",
    "0x4cc324763e797435c22478597102f6dd98382ad4",
    "0x94c333b2c8c1a7b061cc4f9100cab5cc5f13eb2a",
    "0xa3839f00c8afa8926ee10e8d88e15bc9eb52a590",
    "0x774bc8b339a01b08eed0fcac92cd6f17ba1bfe7b",
    "0xec7d7849ca11aab697a289425ffbe8b0b6de9eb3",
    "0x49045e8fd9ea68cdd0c768e8884488cad87dd919",
    "0x55f206ccea40fb17134258f11e732f358a10822a",
    "0x8f877a49f41f2f59febf3fb2f239fbe65d09a6bc",
    "0xb6a86c3ccb3f062e3208071cda361f7f47a6ed8e",
    "0xbcb2797f9a74d9099d6077c743feb3bc812eb2a4",
    "0xe9c0c06bf99ce31d58f72aea69008e5aedecc29f",
    "0x7433904dc974b9ca83740640749e40d4243e9620",
    "0xc7d3ac5ccaa44f3f0652613ab79adca97090e780",
    "0xe847fb549244df7d1370fff369ed82e2b894d23f",
    "0xde7119dc74161341e2f8b4ed1b73c0ccea1a481f",
    "0x8ee1dfed72c8c401da3525033d471420a1da466b",
    "0x21d32aa7d6f763a21276189046f45423dc37b14e",
    "0x0642b4be08848b4f8a33e8bb5f4f27535c5d3a86",
    "0x42038b07881bc137a21e4f339df3b22f42fd3d4f",
    "0x2c6647d4c95b9e064ceb48727cb4f4918c16d824",
    "0x48010246685c3abe30f0055590d871c49a59a33b",
    "0x651a3731f717a17777c9d8d6f152aa9284978ea3",
    "0x37b57f5047d22109d48fb71a88513cab50c92c07",
    "0x0ca95b38cd1551a3db33f2b7ebeb40db84eba8f9",
    "0xd74401db32ddd23127e7823887c5ca4d81631793",
    "0x822c3fa5cfa69561048a91c707fcf26d21a4fb9a",
    "0xe8ebb13902a7ab342163d2a241c1e4891798b56f",
    "0xa2a5811713b6019e99401132ce13ebb77bb76d15",
    "0xc329224cea39e92509e3bb9c62b2fd2556c41f87",
    "0x9ce7318fc46cddfaf3089327b4d58d54784e541c",
    "0x51b037dafbd9f1e70993f51c9798b86905eb6f71",
    "0x76b51d3d4337b09757a412db0c57182329481a48",
    "0xfae4f8b0972dcee4430097a16cfea1b2d87fbaf0",
    "0xa2c76fa7587985b45a912e3e43041fb579a81ce8",
    "0xd8c1cd276d783e51e92291cca028d198d2e70f2a",
    "0x94bd4150e41c717b7e7564484693073239715376",
    "0x5e341eec52820ec1c1841f20d9ea67973e8c4ee4",
    "0x223cc19bf2fcc7219e0518c89a735b99091a57e9",
    "0x111b3d565f5da36b1decdf19dfbb26dc6cd970c6",
    "0xa1eda623641e4d9539fd2799720f6f970a863d2a",
    "0x01b0ba9b15a075f2bbb2a06296dcf230d7033006",
    "0x8728c6f8d81a2b70025fb54d296d5724801cdebf",
    "0xc4623b433a77b870ef7a995c1443fe2e0657992b",
    "0xd9abba66f18a5f67e799c9230ff586a53adb78e1",
    "0x68e75dd2d38f0302a07895223bdeb866e49e02fd",
    "0x6a7b087f4514e0bdbed6d41c9d71a8a2848c178e",
    "0x6dbb825564e85925b0414fdbd41f764ec475c59b",
    "0xbec591de75b8699a3ba52f073428822d0bfc0d7e",
    "0x8ca62efdc496a0a1f5a76df4833519005c0da16b",
    "0x8b7371c7e8b4bc78b4f9dd1009e1a2ec862a59ee",
    "0xf44362d3a3b828c9b3e25e5b453446a1a95e89a7",
    "0xf199af8b17d81c41abe6220a1d7c9fe04d0d9d2c",
    "0x52f377bd91eef4f281cd3ff7e69771aca9c7df38",
    "0x3b70b40bc8f80f20192325fa56a831761230f8fb",
    "0x5e7f646d01526213ad31b599db04d5f31ff7a6c2",
    "0x58155038e9da2f8cf5486d2a457a7530a83d1a2f",
    "0x9d6782566939500d1444c1ee684c205920377114",
    "0x757ace477985fa469a008499184dbe449a045ab7",
    "0x734722831fcf451fbf2ec4a094aeca0a5007be00",
    "0x9a0df4d6158549151bdc3944fc1f8c3f16600cf2",
    "0x0604c64e13948c7381902fe085889faaac40a0a4",
    "0xc3be97b341b84c00aa1b7fbed64c37da6314e20b",
    "0x4938c291ab7e5e51198dfc210824da5d1bd759bf",
    "0x539077c6e8a7dbf9fd13c16925a9504e3c6e24b8",
    "0xeffef3e06f0f9c327c73081106ca8add36b1aa15",
    "0xccfa829f12bd1b7618702ace114a0e464f311f6e",
    "0xe50634f6cabc048e069ead7ddda94dcf51173841",
    "0x80be1f02d789db2704be5a9f6b97ec8713ebc529",
    "0x41211714f4525fad24d773384424488df5bbef2d",
    "0xd12b693156f6bc4c33d73e60424a544bcbe17556",
    "0x889ce51343cd4e4ac3864c2472ed9bf62713b012",
    "0x77cc39282a160a4a565f10e83c36fd0544965b6e",
    "0xb1acfe19d3277c9b6e29472dbbfa0fa96f81597d",
    "0x49047b146f733206ebb2ee66f382cea80de12836",
    "0x4f790a0b278027a0de7326944391e3c40d6bb949",
    "0x00e97dc9df137a4065418fe6475f9465b63d9f59",
    "0x375bef583df0de326053025e68f19b3fccaed3ec",
    "0x7d8d62adaa4e4a3bcb50464b7d414f5ed07ce940",
    "0x6263c353994c14654f2b8d343dc8de2f0eecbea0",
    "0x91c444fede3cf8aff05bf6f9bea268dbb6142829",
    "0x09c5ba25baa0881ea35fd58e800a6df30c61ecd1",
    "0xd52d57ff144a1b4a5ba49f017a04a9290a73812b",
    "0x4e2c8e58aefaf56b8eaa5d3a5c23cbfcf96c9aed",
    "0xa780f030c766808068cc75e83248f53b1af1a3ab",
    "0x4d12c9633ea68d3731c2603081ff435873114a52",
    "0x85c9397f39b87cb18c04f5c11170cdcf2485d8ec",
    "0xedc116c3519b804b3ccae619728fba95556023a6",
    "0xb5813c9a3f1a226ed7b4390f0873d1e53ad24ed7",
    "0x956ff844abd8f58add1160c62810ad34befc8bbd",
    "0x0505c8e3543034fe3dfed013d2e997102de13d37",
    "0xca940e00c64fa7c273b529608c83bd5aaf1cfeff",
    "0x50126e8fcb9be29f83c6bbd913cc85b40eaf86fc",
    "0x212d7ebc169da490b9e92e83a4366e0c2a783b27",
    "0x8655d6bf4abd2aa47a7a4ac19807b26b7609b61d",
    "0x3b3a9c76ba9a4801ace8e2a8ff8b0e99f66bc5bf",
    "0x9129010ae8e0489751a1995293b65a78b8bbd58b",
    "0xdeb5af89cd95eb814be5c1690144d1f2d7143747",
    "0x37c4362e7c11eac6d90775746bb9bc9810116a6e",
    "0x87ec963c1ffd815432ab8800a374328538b1211a",
    "0x10df28c3ccf3300dd8ff924d9f15440f46d918f7",
    "0x8dc9dd62048d2c2a9013590cb4fe1a5acd73b440",
    "0x990ef5561b73dcce62c40a05cafdf44a16386951",
    "0x26afa29ce626d9dcc331ad5e0fbd454ad6362c7c",
    "0xd6f832f3c093beb4b45c1a7fe38eaec1de012927",
    "0xac558414d058f42665d4eeb66a1934d3f82f5cfd",
    "0xa4f988bd98b70c2a58efbb8d6fe0583acfd9e298",
    "0x22b1ec8f8fc78861db3221950ed0c312b51c66e5",
    "0x80c1b7dedbc495be0de1304c2eda7f55e385453a",
    "0x146241d323fd06fed880ccf314580a292c687ad5",
    "0x82e8e737e1080b70e6ed3d8f96cef519b5e29129",
    "0xb12100ad65600ece950a8485e6304211c0a38493",
    "0xbee7f444eb06a1703499bce3eb6db0427cb6070d",
    "0x9f6443e9181a1569126ef1b1f5c45af6ca8e843d",
    "0x5149e60db1df662b639bcd4832fe60e03d681211",
    "0x25e4af0dd6f4f7127a82a5a82a53e1e6aace4835",
    "0xb4e5a62012f729e9f167ce6a0446edce7f441de4",
    "0xda9b77bd3a426a8d5485b955d7eb4f68540d1363",
    "0x4013f4f6ec28f84ea9071336466bf8916f179852",
    "0xf7128c2022de23ed18de88372a3576924335d6f9",
    "0xd202018c812b3aab4f76b8581ddb8c5d9f75b2e0",
    "0xb3dd79289c61cdc38edb9d637936fc22c8a126fb",
    "0xc64d95986dbf4da6ca69ca2e1c1c573942449f3a",
    "0x576d62f07edc33be16736c742409ffdf2178a821",
    "0xaac6ba6cb7d29722bedd1ee06bfccd30fa3c7581",
    "0x0ed8a14bd199474878d2c3f4ff970b754afb62bd",
    "0x9f82984f02f42b31f24d37799c9d63604f9a6f15",
    "0x8cee09a85474533d894808b2b1cb3df81d7314ba",
    "0xd7e7de032e4682cb150e8fe8c8dcbdc99b4c1fff",
    "0xddf90e79af4e0ece889c330fca6e1f8d6c6cf0d8",
    "0x56f395519ac9ae524ad3a700496140e43fa72dbd",
    "0x90ab10474633d3496f661a987025366620682b23",
    "0x5064196a0319e133579b94d3aee453c2c0862a30",
    "0x02f5243fe979a79bb55dc8dcdb93d8ce85e44b65",
    "0xc4673da886f7e3e9ca24487f6b085e118d9dff02",
    "0xa9eebb32a1d459eb1eb5078c543427c34da44313",
    "0xfb6bfa339346ed9f02020234507d1ebbf9f1acda",
    "0x88aa042c4aae423e0f1bb48542b473d1dd20a807",
    "0x83194029697f575530d62ea047ed9651586660bd",
    "0xe18b0c48a7d1e9dfa333157fa222c783f35044a7",
    "0x06c1edc5d0fb879ab8b129dcff1f7b704782508b",
    "0xd2a8e16af2bb255de1b9d0c3cd3ef798b6e94a5c",
    "0x1bfd493c5945ef1dfb45586e4cb9065b3956b6a2",
    "0x697bedbd0ab6079c90d23510fd6473c7b1e9e202",
    "0x87d3f07ae86953b1ae559f8870696168c4e20ab1",
    "0x027b365d2707e551ad9f968649e49f31a8f59336",
    "0xa73c7171cda453bb44000c80f6a9221718b16211",
    "0x0086859d11090d6421386d4392a03811c45aa858",
    "0x352153034dcbaa835b3c7bd4c4a6ddd9058448b9",
    "0x5aff03be8357d53f4758db5894744f51d515e41f",
    "0xd4a32c1c1578474f1040bddf652dc2d2219e911d",
    "0xa8259e82e086c6d78ae38bcd873026f1f540ce3b",
    "0x16a1dc5b15838ec665a029984b0566e6c1fa4702",
    "0xeb6fb7608d26d9c63ef18914d324b83eaf7a904d",
    "0x60035164864fea8c2d0b124701ee3b24f5f1473a",
    "0x82a0c951c4cf920e45a7bd6a1ac2b1d8d4e3d5c5",
    "0x6cbb6dfe3c91b559b7a8ed22badb37244107a423",
    "0xd3a15d933bc568ce20e93c617822e2ffb77411ea",
    "0x720a73e8b8682674eee2d815f8d69e79091f76cd",
    "0xe4454eb3caf272cd721760d71bf54a39ed389eb9",
    "0x8ae1a1a78c326abc8c7de3e70a8a6bdf9328e0ba",
    "0xc60a27a3c981c0cbd1a8f620c1a1720b41cbbc03",
    "0x9a89bcf8960cfa516de8521e62621fc39b3d3a04",
    "0xb629f1b3f37ec06abfbd89b1a3403dddbf2bf863",
    "0x164c2b90f83b67d897ff00899695430841e38536",
    "0x68a01cf2c40ecd7f37b85ff4b9eece128c6eb75d",
    "0x8a1709188d3626155f33483d4e69085b4c17ab80",
    "0x8c6b5e818165601a3e7faedcb0453bd1285eb0cc",
    "0x1423c4cb6f4a9d656fc5d32682056327f459fd40",
    "0x04ac3e0ab9f65098b16ccb9f0ba844cdba3eeac1",
    "0x1ae1eefa471b3221654221360d25f4e2fae43daa",
    "0x7693f7100a671d0cbfca63bd766fd698c17d6f04",
    "0xcd98d845e445feffdb5e2940af3062e37bcb2ad2",
    "0xdb7e3b8291cf956f16c95ffbb725a0ba8544a217",
    "0xb3c88128cea967c39ca1714957679d086cbff92c",
    "0xf6e51ae30705cd7248d4d9ac602cb58cc4b61a52",
    "0x48c46777aaf7a045b4ce8a71961db19f260fdc68",
    "0xe64ff72d09515593bf11f43aa4ec6765ce4270c4",
    "0x37796f835caa5ff3fa4fcc8327853bcde0b3d5f4",
    "0x3d64536ad74b7ccb55c9db23def676a484eb57e0",
    "0xe4bf5dd03746870ba7c3c8e6e2028d0027612ebb",
    "0x8306f9bdec388231265e77225c4e28eb716f6b55",
    "0x53679877643af65d252cd7f918cbde217cc98e7f",
    "0xcb5243f251c3757b0d403e9855457c872d148b4a",
    "0xafe166952fbdd3d9ade67ca73cb8045339ca5183",
    "0x111115111fd0953445d624ceaac28d0ad0c9e74f",
    "0xf9ee19fa632d737af5614f646c0ce10ec7694031",
    "0x537ed6dbbc23f2ad9675a0443990014e9f76f1c0",
    "0x327bb6e6fff2c05e542c63b0fcfdd270734738ef",
    "0x5974199ba063187cc8d49ac9369bb053b4c1ff25",
    "0x50532e594bc045b75df5e57187e2e24d4655c21e",
    "0xe20ec1721fd0a897592d7630786a4a4c848e96a6",
    "0x2f21fc5166642b8addec2832f350ed5b86d897c0",
    "0x779cdcb772d2afd7a74418637382d40b4a4330fb",
    "0xe605c7d8810043ba3dfa7b08e892e2f9eec056ca",
    "0xae307e3871e5a321c0559fbf0233a38c937b826a",
    "0x3806cf18054a118d071f19bbf7f2fe3afbb680f4",
    "0x4a79f4683e08e932d6fb842b48fa62d6c411b4ea",
    "0x14b96bc52d111073c382d54fe17f29b29a346e6c",
    "0x6affbd9a31644e88d56b5b265c6ebe9dbe619503",
    "0x3ca7d3b7ba818b806d7a1975e8b92e6f55fd0e7e",
    "0x062d1816ea36366a714c34b9b283f4d377dc0191",
    "0x2ddf00ef072b0375fd4c6f0acfd4cbe0065f9a69",
    "0x5eef2747f49ce446f10036ddf48af6b27c3d61b7",
    "0xc511c9934e9e314da30dffa170d6eb33947ec4bc",
    "0x103678815ce4ae9926d938e64cadba406b2f86f6",
    "0x7c6cb1f881bd55fc08e091b82f3f8e902a7329ca",
    "0x97d2e85559b74e148111aa1fbdf5ba49688a96e7",
    "0x086a84f2e7e3e4a0fceeab66b1ad36bea5ded70a",
    "0xc8b09b60c5457cdb373a79be3201917985a7b8ae",
    "0xb302c55f7e4a8320640d212537d5d81256bc4a44",
    "0x3a83e0b68bbc064c56a9cadd7d456b1a05d6ba08",
    "0xf6e5e2344a12e036d3a4fed39c931e3351cb8cee",
    "0x496ccebbb3550b40cc5fb46b111e7b72f5489358",
    "0xa96b0d4cacc9714f69e42bfa49cd20858eb2fe24",
    "0x89ec959fd68895dca52bd02865ad3c30d6196684",
    "0x3f0ad8c31a365df9b2b7c8c62c4b8d1e8768982d",
    "0x6f25bd1075dcf8309a907cc04c0deb1d15fa3fc3",
    "0x2270be634ed8130a0402cd106de1f04ea35fa0a9",
    "0xa3645ec50b6c9c1a3467aaddb0483f7325c0409d",
    "0xf2919796ac2b7d4c884bec05cebe92a4b6f1e701",
    "0x59a37485648c21566e6795b69c4039b1c02d6655",
    "0x16f3beced09ed31a0b34fde290989021c13c4645",
    "0xc8987f22eadef2b68c59938d9a6dfb1fc0c4e0b6",
    "0x9121130195036dcaa494a9983e9431c700dae7b5",
    "0xd7c33aaff9e1fe4e970aee0bcf999a0f9c528b75",
    "0x733c806ad2449581ebf4a85d70d6f38b76f85713",
    "0x4c630c0882b58c1ac59ea3edbabcdb803e34291c",
    "0xc3bcd786b53ccbf2bfc3a350d09e2dd4a6e6959f",
    "0x3bfc20f0b9afcace800d73d2191166ff16540258",
    "0x051b21b946a39c092b806be32ce76d09ccbe058c",
    "0x91355a38d8eedad0bfc0a2f18c590e26e7f7df9d",
    "0xec0dc7522ff8d3da35924bfaebeb5b8d79121d61",
    "0x99a535ab572a2cee6809f17cee35fb36a4b29915",
    "0x74b16e67582e66f791ba45c65f70b84c54541e3b",
    "0xa6ae6a5d2853262a3f591043ea63d4b06940ef0f",
    "0x3cb96f3d6b66c55c2942ebe70826f7a15b044a8a",
    "0xc06a8a5c712e9fc2bacc67ffc066efa0172c17a5",
    "0x2cb6bbecd274fa439e1de92a8e70e4d4ce3b47b3",
    "0x006c94d8e2197732c247086fceecc65c9bedfebd",
    "0x37a9d6ae9229f54e6fe6355678948ae0f8433e3e",
    "0xc7a13c9ceba109499c2c00af977591b55a03e6af",
    "0xc2b6679c79c474cce92699262defeb4d996b4246",
    "0x1a49cb4e860c799de397cc29552b3d80e8bd70d3",
    "0x94c793a5c86e2a690bc8a35e0daef3a5e537a64d",
    "0x0671096252fd56e23de40c3edb8aea94a74303c1",
    "0xa3a22aed1d45342c96012c64104bb8b121eca07c",
    "0xb5aab677c00bd468ac94163bf1bf100549e49304",
    "0xce9f93eb7f78fcb7e7d222c81f258535dc218d4b",
    "0x2499e22e19b0af3c1ab82071db2a9c4fd7ed328d",
    "0x1303c418b09a6a15c90c1667efa5a9183e6e80ac",
    "0x2086c6098d0fdf2c79e5ecc245e6e21cccd7a9bd",
    "0xf3ee7953a11d5ffae24d12a2e8d2d77afb5a2730",
    "0x6107d954b4770ea65a4f88015fb6b90655ac8e72",
    "0x9600b33b44d0cbd2ad4164cf2a8de6b13500254a",
    "0x40f69798812a1b2498d788a69e7e8edbadb72aad",
    "0xb32db51ba30c80a21a775635c1b6d6a01754fd06",
    "0xd91e79c081d8b21f765875c86dd84d39338261b0",
    "0xc7d3f0c133be2e5d5223c874ebea04aed9c7bf03",
    "0x58d3b315cc9f4e1f444a10b592421aaf33d6c3fb",
    "0xb740abc53d142690d7bfabe841102b41ffe25fb3",
    "0x0ea3754913cdf617507a4c640c0416147c9434aa",
    "0x3fec3c6e014e28566000a1be3cfcb43327d4b743",
    "0xd9b983018f07a102c431ca90d31886d93d2e20a2",
    "0x34b3bbce4e11e575ce32c91f628cc4a26fdf7907",
    "0x48b653e76959a1323f9581ab557bf729246d84f7",
    "0x0ccd5be12ebdba2416f31323c435d3d91e3dedd8",
    "0xb7aa741108ae27e02401fef2101114e5b8bb0ad9",
    "0x37c5fd4e97bb6779018116121fdfb5810c7a91cf",
    "0x223fbc3d404d38213f5d4ba090e3866f151dfffd",
    "0x9a84d2eb7f82a98399dff45c7bb13b7654fa95a6",
    "0xba14f6af1371a082c6308b6ae8116c834353746e",
    "0xa316a531a66c8f708f593554736618dc497b4716",
    "0x090853e608849943f52ff983abc4fd6d34ff1ec7",
    "0x72a7197bbccbe6ee1e9c688645436ed06017768a",
    "0x2cced50f5f352c9784ab348956ffc0e17b19982b",
    "0x73f1cd5face85917543c1c4b3dd8e88ccfa4965a",
    "0x54d920b15a6fc49f7c206df8924d5c192da4228e",
    "0x8edaaaf2f30edd0a561c219f475fff026cdac575",
    "0xf853c90891dd9eb7b0456ca6e78dc44d0b56c551",
    "0x43e91e4099e0028ce8871eb015593cbd1aebaf9e",
    "0x1971066fa9419a03a07cca394204915818d6c140",
    "0x0d1e361c72db59344b3aadb8037c964850ba13c0",
    "0x3b135dbf827508d8ed170548f157bdcd2dc857d3",
]

class HoneypotFinder(TraceAnalysis):
    def __init__(self, db_folder):
        super(HoneypotFinder, self).__init__(db_folder)
        self.parity_wallet_loss = dict()

    def find_honeypot(self, from_time):
        ABNORMAL_TYPE = "Honeypot"

        class STATUS:
            CREATED = 0
            INITIALIZED = 1
            PROFITED = 2
            WITHDRAWED = 3

        class Honeypot:
            def __init__(self, contract_addr, creater, create_tx, create_time):
                self.contract_addr = contract_addr

                self.creater = creater
                self.create_time = create_time
                self.status = STATUS.CREATED
                self.create_tx = create_tx

                self.profited = False
                self.profit = 0
                self.profit_txs = list()

                self.init_time = None
                self.bonus = 0
                self.init_tx = None

                self.withdrawed = 0
                self.withdraw_tx = None

            def __repr__(self):
                if self.status == STATUS.CREATED:
                    return "honeypot %s created" % (self.contract_addr)
                elif self.status == STATUS.INITIALIZED:
                    return "honeypot %s initialzed with %d wei bonus at %s" % (
                        self.contract_addr,
                        self.bonus,
                        DatetimeUtils.time_to_str(self.init_time)
                    )
                elif self.status == STATUS.PROFITED:
                    return "honeypot %s profited %d wei with %d wei bonus initialized at %s" % (
                        self.contract_addr,
                        self.profit,
                        self.bonus,
                        DatetimeUtils.time_to_str(self.init_time)
                    )
                else:
                    r = "honeypot %s closed with %d wei bonus initialized at %s" % (
                        self.contract_addr,
                        self.bonus,
                        DatetimeUtils.time_to_str(self.init_time)
                    )

                    if self.profited:
                        r += "with %d wei profit" % (self.profit)

                    return r

            def init(self, init_tx, from_addr, value):
                if self.status != STATUS.CREATED:
                    return False

                if from_addr != self.creater:
                    return False

                self.status = STATUS.INITIALIZED
                self.init_tx = init_tx
                self.bonus = value

                return True

            def income(self, profit_tx, from_addr, value):
                if self.status != STATUS.INITIALIZED and self.status != STATUS.PROFITED:
                    return False

                if from_addr == self.creater:
                    return False

                if value > 0:
                    self.status = STATUS.PROFITED
                    self.profited = True
                    self.profit += value
                    self.profit_txs.append(profit_tx)

                return True

            def withdraw(self, withdraw_tx, to_addr, value):
                if self.status != STATUS.INITIALIZED and self.status != STATUS.PROFITED:
                    return False

                # if value != self.bonus + self.profit:
                #     return False

                self.status = STATUS.WITHDRAWED

                return True

        # contract addr -> Honeypot
        tracked_honeypot = dict()
        # contracts failed to be initialized in 30min will not be tracked
        last_created = set()
        current_created = set()

        # use time window of 30min to avoiding taking too much memory
        WINDOW_LENGTH = timedelta(hours=10)

        window_start = DatetimeUtils.str_to_date(from_time) if isinstance(
            from_time, str) else from_time
        window_start = window_start.replace(tzinfo=timezone.utc)
        window_end = window_start + WINDOW_LENGTH

        for db_conn in self.database.get_all_connnections():
            traces = defaultdict(dict)
            error_txs = set()
            block_times = dict()

            l.info("Prepare data from %s", db_conn)
            for row in db_conn.read_traces(with_rowid=True):
                if row['trace_type'] not in ('call', 'create', 'suicide'):
                    l.debug("ignore trace of type %s", row['trace_type'])
                    continue

                block_time = row["block_timestamp"]
                block_number = row["block_number"]
                tx_index = row["transaction_index"]
                tx_hash = row["transaction_hash"]
                rowid = row['rowid']

                if block_number is None or tx_index is None:
                    continue

                if block_number not in block_times:
                    block_times[block_number] = block_time

                if row["status"] == 0:
                    continue

                if row["trace_type"] == "suicide" and row["from_address"] in parity_wallet_addrs:
                    self.parity_wallet_loss[row["from_address"]] = row["value"]

                if tx_index not in traces[block_number]:
                    traces[block_number][tx_index] = list()
                traces[block_number][tx_index].append(dict(row))

            l.info("Begin analysis")

            for block_number in sorted(traces):
                block_txs = traces[block_number]
                block_time = block_times[block_number]

                if block_time > window_end:
                    # window move
                    window_start = window_end
                    window_end = window_start + WINDOW_LENGTH

                    for contract in last_created:
                        tracked_honeypot.pop(contract)

                    last_created = current_created
                    current_created = set()

                for tx_index in sorted(block_txs):
                    tx_traces = block_txs[tx_index]

                    for trace in tx_traces:
                        tx_hash = trace["transaction_hash"]
                        to_addr = trace["to_address"]
                        from_addr = trace["from_address"]

                        if trace["trace_type"] == "create":
                            current_created.add(to_addr)
                            tracked_honeypot[to_addr] = Honeypot(
                                to_addr, from_addr, tx_hash, block_time)
                            l.debug("TX %s creates %s", tx_hash, to_addr)
                            break

                        value = trace["value"]

                        if to_addr in current_created or to_addr in last_created:
                            if value == 0:
                                continue

                            l.debug("TX %s transfers %d to %s to init honeypot",
                                    tx_hash, value, to_addr)

                            succ = tracked_honeypot[to_addr].init(tx_hash,
                                from_addr, value)
                            if succ:
                                if to_addr in current_created:
                                    current_created.remove(to_addr)
                                if to_addr in last_created:
                                    last_created.remove(to_addr)
                            else:
                                tracked_honeypot.pop(to_addr)
                                if to_addr in current_created:
                                    current_created.remove(to_addr)
                                if to_addr in last_created:
                                    last_created.remove(to_addr)
                                l.debug(
                                    "illegal initialization for %s", to_addr)

                        elif to_addr in tracked_honeypot:
                            l.debug("%s receives %d", to_addr, value)

                            succ = tracked_honeypot[to_addr].income(tx_hash,
                                from_addr, value)
                            if not succ:
                                tracked_honeypot.pop(to_addr)
                                if to_addr in current_created:
                                    current_created.remove(to_addr)
                                if to_addr in last_created:
                                    last_created.remove(to_addr)

                        elif from_addr in tracked_honeypot:
                            if value == 0:
                                continue
                            succ = tracked_honeypot[from_addr].withdraw(tx_hash,
                                to_addr, value)

                            if not succ:
                                tracked_honeypot.pop(from_addr)
                                if from_addr in current_created:
                                    current_created.remove(from_addr)
                                if from_addr in last_created:
                                    last_created.remove(from_addr)

        for addr, honeypot in tracked_honeypot.items():
            if True or honeypot.status != STATUS.CREATED:
                yield AttackCandidate(
                    "honeypot",
                    {
                        "contract": honeypot.contract_addr,
                        "status": honeypot.status,
                        "create_time": DatetimeUtils.time_to_str(honeypot.create_time),
                        "create_tx": honeypot.create_tx,
                        "bonus": honeypot.bonus,
                        "profit_txs": honeypot.profit_txs,
                        "withdraw_tx": honeypot.withdraw_tx,
                    },
                    {
                        "profits": honeypot.profit,
                        "withdrawed_eth": honeypot.withdrawed,
                    }
                )
