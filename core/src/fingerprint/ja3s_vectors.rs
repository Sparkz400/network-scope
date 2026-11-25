// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! JA3S test vectors (included by the tests of `fingerprint`).
//!
//! Each row is a ServerHello body (the message after its 4-byte handshake header), the JA3S
//! string and the MD5 that the reference implementation, `python/ja3s.py` of
//! github.com/salesforce/ja3 (commit 502cc63, 2025-05-01, BSD-3-Clause), printed for it.
//! Recorded 2026-11-20 with Python 3.13, dpkt 1.9.8.
//!
//! The `real` rows are ServerHellos of local TLS servers (Python 3.13 `ssl` on OpenSSL 3.5.9,
//! TLS 1.0 to 1.3, RSA and ECDSA certificates), taken from a wire capture (`scan --record
//! --record-wire`, Npcap loopback) of a scan of those servers; ja3s.py was run over the whole
//! capture and over a second pcap that holds exactly these messages. The `synthetic` rows are
//! hand-built messages for shapes no local server sends (no extension block, an empty one,
//! GREASE-like values, an unknown version); ja3s.py read them from a pcap the same way. The
//! row for `769,49172,65281-11` has the hash the README of the reference gives for the Trickbot
//! command-and-control server (`623de93db17d313345d7ea481e7443cf`).

/// `(what it is, ServerHello body as hex, JA3S string, JA3S hash)`
pub const VECTORS: &[(&str, &str, &str, &str)] = &[
    (
        "real, local TLS server on port 18446",
        "030120e5ab18034e7a4ccef81ff46414dd33d686bb07594333ba444f574e47524400206518c62c47f35f5afc39a1b2e2a1b4b80edca2f3430b0ef88a5d7f9e6e7338a50035000005ff01000100",
        "769,53,65281",
        "91589ea825a2ee41810c85fab06d2ef6",
    ),
    (
        "real, local TLS server on port 18446",
        "0301988e62370f72f82d0c0bcff7ed0730b3c9e0e170babc12b1444f574e4752440020854eed120210032c15675825dcd98e8f148b4f27abecd1e707694c0eaaf34d22c01400000dff01000100000b000403000102",
        "769,49172,65281-11",
        "623de93db17d313345d7ea481e7443cf",
    ),
    (
        "real, local TLS server on port 18446",
        "0302da4a00bea8d0758971514ee9b64ade65206a934b4908aec7444f574e4752440020612549644373cf3d4b6ac1ac6b372708f1fde0b55e2768570d6693c8fde1dbc40035000005ff01000100",
        "770,53,65281",
        "9f2e2080c0409c26ea913d9273e88773",
    ),
    (
        "real, local TLS server on port 18446",
        "03026ad751988c3e6c32200d9c00963e1ade5d4c47380a81fccf444f574e47524400207bd55b7f34d0c2d42eaec6a8a151be1ad9f37676f8eaeffc4cd09f92f3cf8f02c01400000dff01000100000b000403000102",
        "770,49172,65281-11",
        "ce815ab6e37127ab1cb9fe33d3ba250d",
    ),
    (
        "real, local TLS server on port 18446",
        "0303cc9cfe16fd65000387f0c8d7523c0837886115532a58d1812ab0ed4bbd895b69205c0a9bc2c489eb72279b5285d2f837748ed681dac4400d535a120bedfb0c2b3f003d000005ff01000100",
        "771,61,65281",
        "da2b67b20914678c1f1f5888281e1db9",
    ),
    (
        "real, local TLS server on port 18446",
        "030397feb048eb0e8a13ff47e52691733aabf10dd4aa58c21e01c669a2498fcc805120c43c1860323ed76de8e4108d95cfd80dc2b92bf921097aa826a46b352b85116a009c000005ff01000100",
        "771,156,65281",
        "ccd5709d4a9027ec272e98b9924c36f7",
    ),
    (
        "real, local TLS server on port 18446",
        "03039f846366db02d8a75e6ec2dba792ac34646f8a2b0816187acc34e2cdaab985ab20218980dd72b18205a55e55b15659b06ee10c8b5bea6404214c477055564cdfa9009d000005ff01000100",
        "771,157,65281",
        "f75082535b4a79c07b31bdd0e2b7eb87",
    ),
    (
        "real, local TLS server on port 18442",
        "03039fcedf32314f208a1034cddbc2bd723bb6913316a87f233882738f7510a1740820d614792e612eb6e212f246d052442dbfb78e8a36ea0c57f808513e0d57008b89130100002e002b0002030400330024001d00200f8d1ba95b8787e9e05b342c30adb1a3e4b97f610565cf3daf1410c8741dac4c",
        "771,4865,43-51",
        "f4febc55ea12b31ae17cfb7e614afda8",
    ),
    (
        "real, local TLS server on port 18448",
        "0303c49a19f8b54d2b4581a8d702051f1accb1ed11a38d766f312dfc39b58ed64c79200883d29479697a204701db452c7a05c57868dfae40d42c4e0301f0845b87de59130200002e002b0002030400330024001d00205905720ca1da20343d2db6fcc1161acf0c5e2bd94ebc562abdd369429a117b1e",
        "771,4866,43-51",
        "15af977ce25de452b96affa2addb1036",
    ),
    (
        "real, local TLS server on port 18442",
        "030366c930ea22675d01d27733f2038d09eb7db335d117c2347a6de176f26f110fd020626dad939e9c5be03e1fc0f0cd9ee3e5d7b43766f8c40d163fa17170583e1f88130300002e002b0002030400330024001d002050e672bca3f70a05b15b64a2a10bfbaafb962f74db29712929c9df872c253c78",
        "771,4867,43-51",
        "475c9302dc42b2751db9edcac3b74891",
    ),
    (
        "real, local TLS server on port 18446",
        "0303a7ac005375dde596bc5e4f94afdf9a94a9d20dd2d04c0a2d0811bacdc825389620ca3b27fe551fabd835156dcd05d46681af682a20c47ca2c146d343b0e3568ed2c01300000dff01000100000b000403000102",
        "771,49171,65281-11",
        "042b018de1d862323f09d5767e4068d5",
    ),
    (
        "real, local TLS server on port 18446",
        "03039b9c2e8e42297738a7dfe7adb2515c61f3b1d6773eb256dee59d782ce5c02baf202af5b1811fd5ac874d55ba541a3294eb750cf428fe6229b0aaa5d7ddf3a5f1dbc01400000dff01000100000b000403000102",
        "771,49172,65281-11",
        "f47b284bf7f61821a407e4f140a02686",
    ),
    (
        "real, local TLS server on port 18448",
        "0303bfd7057c21219cf6c0346c4413d2bf0a681edf9d37d023cc444f574e4752440120069b18691e3a47abd9d435265e5443cfce4592408d570219dab42ea2f30dd3f1c02700000dff01000100000b000403000102",
        "771,49191,65281-11",
        "a4cc547f75a117e7e973bd04ad9bec50",
    ),
    (
        "real, local TLS server on port 18446",
        "030355054bfe93aa645e47ac8a71db86a8ce4c79b3698ebe77319f6306394ddecc9c20f50285effd0ac292200e3f020577e9c048db89112539099e92969b0840c6274ec02800000dff01000100000b000403000102",
        "771,49192,65281-11",
        "9099266b09da09a1d9e1839ae9ad5682",
    ),
    (
        "real, local TLS server on port 18448",
        "03031f42e1c67ab4df725139f0e7447314f1c21202f1f550d7d0444f574e475244012001809142fb8547b2758e98107a391ff87ef6169759edf8e0c22fc11b066351bcc02f00000dff01000100000b000403000102",
        "771,49199,65281-11",
        "303951d4c50efb2e991652225a6f02b1",
    ),
    (
        "real, local TLS server on port 18441",
        "0303941fcbe29742abfe243490fb623f12af445ca9b986377a1e281af35dfa63bb5520f094be8d7b142a87b893fc42ce65747179ada0aab215d5c798c09446777d2903c03000000dff01000100000b000403000102",
        "771,49200,65281-11",
        "0debd3853f330c574b05e0b6d882dc27",
    ),
    (
        "real, local TLS server on port 18446",
        "0303f9f7e9b3d89cdfcf9af34774b2d8ac3f6a1d3cc1473e8eef22f10ca09e6c911f00c030000015ff01000100000b0004030001020023000000170000",
        "771,49200,65281-11-35-23",
        "ec74a5c51106f0419184d0dd08fb05bc",
    ),
    (
        "real, local TLS server on port 18446",
        "03038375ae9eefb90147beb7990d007e4b77a90418af4a807782a48df2bf7a027fdc201602779f4ff096af5f3d0ccf5de341f45672b655d07e41617dd2277a05fb1ac7cca800000dff01000100000b000403000102",
        "771,52392,65281-11",
        "d25619cb77d3219fc9fc14cb6b35eacc",
    ),
    (
        "real, local TLS server on port 18444",
        "0303db83c51a138961e050e5519840f8f07847a18e3c259692ede9b49dd7935a740b201faa8a923ff563c66be801934cd6ee6b6fe9207f0d6c8f47667c2fa9c8d6e64bcca900000dff01000100000b000403000102",
        "771,52393,65281-11",
        "954f7e9207d4c9012fd0692885732b12",
    ),
    (
        "real, local TLS server on port 18444",
        "0303a6ab012080a429fb778e85dbeddd39aaa630ecf740180b14691847f3f9a5f5a2200743ddff0106ddeb8c1c26a2adb6ee69d103c4b2e6c2da5effdbd4165e120a10cca9000011ff01000100000b00040300010200170000",
        "771,52393,65281-11-23",
        "7490298726840fd1ed02ef8d838fe9ed",
    ),
    (
        "synthetic: no extension block (TLS 1.0, TLS_RSA_WITH_AES_128_CBC_SHA)",
        "0301000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00002f00",
        "769,47,",
        "18e962e106761869a61045bed0e81c2c",
    ),
    (
        "synthetic: empty extension block (TLS 1.2, TLS_RSA_WITH_AES_128_GCM_SHA256)",
        "0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00009c000000",
        "771,156,",
        "ac4776ae2f7042ea107581e2be63ffa1",
    ),
    (
        "synthetic: SSL 3.0, TLS_RSA_WITH_RC4_128_SHA, renegotiation_info",
        "0300000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001010101010101010101010101010101010101010101010101010101010101010005000005ff01000100",
        "768,5,65281",
        "39983b5db860f7f78a44bb85e44fa173",
    ),
    (
        "synthetic: TLS 1.3 order: key_share first, supported_versions second",
        "0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200202020202020202020202020202020202020202020202020202020202020202130100002e00330024000000000000000000000000000000000000000000000000000000000000000000000000002b00020304",
        "771,4865,51-43",
        "eb1d94daa7e0344597e756a1fb6e7054",
    ),
    (
        "synthetic: TLS 1.2 with ALPN h2 and extended_master_secret",
        "0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00c030000012ff0100010000100005000302683200170000",
        "771,49200,65281-16-23",
        "d7e12962b60127bdbe4f65f39221f9e8",
    ),
    (
        "synthetic: GREASE-like extension types are kept (reference does not filter)",
        "0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200303030303030303030303030303030303030303030303030303030303030303130100000e0a0a0000002b00020304fafa0000",
        "771,4865,2570-43-64250",
        "7549689fa364820d9bc0f7549256a7dc",
    ),
    (
        "synthetic: GREASE-like cipher value is kept",
        "0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f002a2a000005ff01000100",
        "771,10794,65281",
        "63784617925cfad6f44fb3278fbab44d",
    ),
    (
        "synthetic: unknown legacy version 0x7f1c",
        "7f1c000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f001301000006002b00027f1c",
        "32540,4865,43",
        "ef92257cd148d8c07b3e4ccef767bb75",
    ),
];
