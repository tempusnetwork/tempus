from datastructures.clockchain import median_ts


def test_median_ts():
    # TODO: Removed floats, will mess up signature though
    example_block = {
        "list": [
            {
                "nonce": 60981181474,
                "pubkey": "8f4ffc101792761942d1dd6f7fd03abbfa437e3dacba0e5ac6b5a5c267bc94dbeb88423ca3fd70a3216622bf482b264c5ac845684dc80f035de16eabf100ec26",
                "signature": "33bec8c98267689da887edcbf41210a47817801ecf761b16dc4115b975081afec6107c5408af317f3b5440868f87cf4930bc6fffe70e0917ccfc13284649219a",
                "timestamp": 1521393955
            },
            {
                "nonce": 8868330207,
                "pubkey": "74ead87444384388f8bbfb042e36def6d85810208c50fcb8230fecfcbcd2bc15f787dbd1c297915d91ea0c50875e6ec4606ebb34dd7ee0bc57be6758a836f70f",
                "signature": "48a9ce3de5b583219ee7aa5753100fdd97f126e31d66f67b23cb0c2579feaeb436790464c003b071e0368dcb626cbe64435be18f176c48c059b066417ae4b0c5",
                "timestamp": 1521393956
            },
            {
                "nonce": 61582927584,
                "pubkey": "874ec87c373bbbccf4e601de154ec9e8e91b7a19a0e25470b6be358e628c7691e40c2dbaff64ab34c69f060e1a75481555c86f4e9dae6f5b9a14f3f7d0e39c85",
                "signature": "e79b096413fe0633dd48bce83157a0826539e4b7abdd737e1f402bb2fdc581a859cd14d72d631d9ba98ded1a547b7154af6c5293208ed5c131e56bff9c1bfd81",
                "timestamp": 1521393942
            }
        ],
        "nonce": 4540045680,
        "pubkey": "108ac641ca7241a1b5cf12d2ef2a106d9f9f8a36d198e331178cb56ad953585f7fc7578006f2658614175e55a0404f70ea413cde021d7accb67d30bcbfeb8de8",
        "signature": "abdbc42cb87f3c0a2bb7de952af4ed4be437988404f43a4b7b60f73449f5cd95c24cb009de60893ae6757176be5183bf1b1389d0dfe972dc3e94e5b06ffbc029"
    }
    assert median_ts(example_block) == 1521393955
