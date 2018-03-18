from clockchain import median_ts, Clockchain
from datetime import datetime


def test_median_ts():
    example_block = {
        "list": [
            {
                "nonce": 58655017330,
                "pubkey": "34c23a680e3b7952eb0c5f2c652806fd8bf8b069ebb2d81f7fea867bd67cfca15a88f1325f8ac78d79b8ed1e483689ebf91fe20eb5ecb39297278e5cbccc5f14",
                "signature": "e1f7b056e5b7f2b356eb49661d962725f88621a51586e981ddc7e4e1134d826f0a0ec1f2133cbdd146ff76c35251318bab7f784de7a6addbb8ca4fc8e2578ed2",
                "timestamp": datetime.timestamp(datetime(2018, 3, 18, 12, 00, 00))
            },
            {
                "nonce": 77558326635,
                "pubkey": "e5fb00585f2593fd332fc8b39bb38825eb79b63f0cfcaaad79f9640bf2a79f7fb75542ce6241d399236233e4653e19d080b14e589db186818b616e82e2d46306",
                "signature": "fc7cdcf376e7ad02df4a6e8093a2e24291eafc4da3eb2b597d486f6df236be40dac8702258cc4398d5e05376f12a1db09d0b872ce197b37b19370d21d995d34a",
                "timestamp": datetime.timestamp(datetime(2018, 3, 18, 12, 00, 5))
            },
            {
                "nonce": 44781585159,
                "pubkey": "ae77cfd2fd616fb68c995f17431b3da12c0c2ec5ad0cd7dd51b4e316d37eef0a71bafc9e2c31e04b4ea29b715227c7cb356648906e2363b9e96370f93198cae4",
                "signature": "64568567c4eb676a1e7a840819ba23de01bd2d286a765d688b444a3f664b0263edd8ae9ca045ab1545b2b8bf75343ab8f83e857675575055070288247a969393",
                "timestamp": datetime.timestamp(datetime(2018, 3, 18, 12, 00, 3))
            },
            {
                "nonce": 82024416193,
                "pubkey": "008d96667d18814833e27bd90ea9a1a7836068965bfea7a341fd41c739b889aa91ab11bee70820a41abe2f366ce4019dcc941a364027aee68f8ce3d7c0745e59",
                "signature": "0a11a6387254c38e44d59a059cc6b6f4919fa17669b936f94fd2d6e2387ba9b6d3c8eaa7eb7b6dda3b65678009d3d8143f7cfb236eff7eacccf3d526827d4ea0",
                "timestamp": datetime.timestamp(datetime(2018, 3, 18, 12, 00, 9))
            },
            {
                "nonce": 40088042837,
                "pubkey": "d60029a192ff3d56a544a81bf90a6da96fdac52dd7bba8ab233dc078b8cb57757a136b53de91c499c2943c2424dd2efc4f20a686ba301eedcf7aa5691457fa46",
                "signature": "f7c324597702191c8f4836241fbabf457b7f93e52d8b39984247db3627d0a5269b0e77cf442d6f9a4d01d465d878e2cd020a44e50ea88a06fbcbdd8e8b3a8989",
                "timestamp": datetime.timestamp(datetime(2018, 3, 18, 12, 00, 15))
            },
            {
                "nonce": 47592916502,
                "pubkey": "0003ee745a23a5267a4c90ca4dc19956c2a968ccfb5ef3314cffc3b5bd660f259130f23074f41f3cc28f1639b8bb34c2dd9bea59eb9be960d93d1c0658c19dcb",
                "signature": "62ba507854968bc0396c279178ce2813e25cc3b3caa2f76b18dba67b94a5e4a79979250c3986759b4866ac3b7e6e0348a8c4a9dbd6012598e4f7cd391cd7f11a",
                "timestamp": datetime.timestamp(datetime(2018, 3, 18, 12, 1, 00))
            }
        ],
        "nonce": 60730990514,
        "pubkey": "ba38fb21942d28afb9bdaeaffad1e01a7e2e39d304e218bb6dee33fb52c31bbb498c7869c61d37cafa744af6b70bc89deb2b4fcd78d8239458fd9e1eb23083d6",
        "signature": "c4021412f44d7115337fefa49c77365c8606bfd6f48f93231ef29d99d5ba8536ee0135485e29db90d9a680e3b3e927d063c802272fbc4b7aea4496357e43e04d",
        "timestamp": datetime(2018, 3, 18, 12, 5, 00)
    }
    print(median_ts(example_block))
    assert median_ts(example_block) == datetime(2018, 3, 18, 12, 00, 7)