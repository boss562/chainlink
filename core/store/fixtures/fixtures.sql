-- Password for all encrypted keys is set the same as cltest.Password which is:
--   'p4SsW0rD1!@#_'
-- Scrypt params are chosen to be completely insecure and very fast to decrypt
-- Don't use any of these keys for anything outside of testing!

INSERT INTO "public"."encrypted_ocr_key_bundles"("id","on_chain_signing_address","off_chain_public_key","encrypted_private_keys","created_at","updated_at","config_public_key")
VALUES
(
    DECODE('7f993fb701b3410b1f6e8d4d93a7462754d24609b9b31a4fe64a0cb475a4d934','hex'),
    DECODE('57120312197c54ce8eeca1aabef8682d3d768bf4','hex'),
    DECODE('e82a081a49d27f11b526c42fe8228837832b25598a4ff146eb173f30a070030e','hex'),
    E'{"kdf": "scrypt", "mac": "01623cb2f2eac87e73b082a159960003ad1d627f0a3e4666bbeb4808baf8e367", "cipher": "aes-128-ctr", "kdfparams": {"n": 2, "p": 1, "r": 8, "salt": "0800e3d8a409beeb74c33ea539994e4c2fa22ef62735fa866bc9e146af1369bf", "dklen": 32}, "ciphertext": "bf931de9605adadebe2e833ea457a4629fa90a4ffff696f869a6f4ee29d4df1df8d2ecf68940d4134f95d70a78a561051d0b578e6c7fda4b0921e445595fe6ca25fa4421b022b1c2b13990476fe7b061c2ebbbbd6d1b1b9f9b9048078f6c0115f63e8d44d118ba82914e24a06ea09d31567f3c21ccac620d2c22f0fd2e1144c3b0ad66072f523096728536e7575fbf2c66c96f5cfce377a45e03bf230758edacbfeba55731fa59b43d8d794a32931a6f44740f7ad56fb6f6a90cd33f6021a6a25b71835bdacf0f5c544412af633d4a752e35ab973659a93154526354cf6404196daf0a9821faf3d231524763fc9dc5cd11291467503bec5d599e5ba1ee040e80a51b624bccbc1f769eaa798627bffb94cdfa12bec7b33dff28fb21a8b0e42f812c0b172b3b51c71d089f9f0d48984e98e030e97e672c6754e0a8fc1d1fc3ea1823894d8f79b5f8fd6c12cfa36b73", "cipherparams": {"iv": "cb05be43c5a44baf33ddba0d62b45017"}}',
    E'2021-01-22 02:59:40.087088+00',
    E'2021-01-22 02:59:40.087088+00',
    DECODE('1bd910cb46ffce56ebd59721e406bd4e7e76f9d0561352703bacc18e165af174','hex')
);

INSERT INTO "encrypted_ocr2_key_bundles" ("id","onchain_public_key","onchain_signing_address","offchain_signing_public_key","offchain_encryption_public_key","encrypted_private_keys","created_at","updated_at","deleted_at") VALUES
(
    DECODE('92be59c45d0d7b192ef88d391f444ea7c78644f8607f567aab11d53668c27a4d', 'hex'),
    DECODE('0fc03dfab767c159b13a1c81ed3acec1bab361f4', 'hex'),
    DECODE('0fc03dfab767c159b13a1c81ed3acec1bab361f4', 'hex'),
    DECODE('730062a57821072d48b6b6dc5eb3e25be2ed16252e9d011f7a26cba081a581bf', 'hex'),
    DECODE('8ebee64ea006e0d52abe706f585da94ac155651fec1b11297ab10986ffe22d56', 'hex'),
    E'{"kdf": "scrypt", "mac": "a5b4f015772e518e5e4b646da702f6cb2f04859cd79357ba889a6990ba1e1b69", "cipher": "aes-128-ctr", "kdfparams": {"n": 2, "p": 1, "r": 8, "salt": "2d34e75f6a8ee947b0cee24c070c57ed23a63c5a957ebd45a1b37f18f64d5c75", "dklen": 32}, "ciphertext": "369b711df7e45d2f436be138e0ba69ffd168406bec21bb1d159b99b112872a8bed64a3f22c76fa51467e682c198fd5d4f3545a9abc205d3e07827ca956f90fcf8148cb7abb91eac3a089f8145ba3e8f70fc339af8ac4c4ce2f23a34905a2112a707f2da5a95ab1032c77510a7c43e212bbbec4eeeef9f1ee31b5c8fdf9404542b27d07881257be0331f34dc4e315b79b4dc1e41658d8f5469becf1310a1fbb1c91ee716941f69799b6caa2d15130a32b27bb84e175c5244a9040c2fe3e2e7c29c1dd990d449c25caa45149b688f85196e032f502600e", "cipherparams": {"iv": "e2f82e3fcd03188b4bd34256326fa52a"}}',
    E'2021-08-16 16:52:35.821171+00',
    E'2021-08-16 16:52:35.821171+00',
    NULL
);

INSERT INTO "public"."encrypted_p2p_keys"("peer_id","pub_key","encrypted_priv_key","created_at","updated_at")
VALUES
(
    E'12D3KooWApUJaQB2saFjyEUfq6BmysnsSnhLnY5CF9tURYVKgoXK',
    DECODE('0ee29fb3bbcec807959c3f9e85c43ac85570c8a63d94e444599527884c992ece','hex'),
    E'{"kdf": "scrypt", "mac": "f1fde38d7d0a86c25eb8ce64885db212e10cbb493671e861151adc14367a4b25", "cipher": "aes-128-ctr", "kdfparams": {"n": 2, "p": 1, "r": 8, "salt": "7bfa8fab0a3f3907b1df7479d92183d32610b471c4a96629fa1f05428914b168", "dklen": 32}, "ciphertext": "a99751e60f8c8143b17635c107aa4ac1703ebb4f2eaf52d4e6e037b196c1e319a482d5a8cc8d49198f0de912452e42283132e53b0d931cf10d71bd641691919719144f0a", "cipherparams": {"iv": "88b81ab2a402b1a6c0981cc521ca24fa"}}',
    E'2021-01-22 02:59:40.085609+00',
    E'2021-01-22 02:59:40.085609+00'
);

INSERT INTO users (email, hashed_password, token_secret, created_at, updated_at) VALUES (
    'apiuser@chainlink.test',
    '$2a$10$Ee8YjCtcBgflgR7NWmii.u5kwOuWNF1bniacRf/sqobB5YaQv.Lm.', -- hash of literal string 'p4SsW0rD1!@#_'
    '1eCP/w0llVkchejFaoBpfIGaLRxZK54lTXBCT22YLW+pdzE4Fafy/XO5LoJ2uwHi',
    '2019-01-01',
    '2019-01-01'
);
