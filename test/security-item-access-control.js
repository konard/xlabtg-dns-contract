// Security regression tests for nft-item.fc access control.
//
// These tests assert that privileged operations on a settled domain item can
// ONLY be performed by the authorized party (the current owner), and that
// every unauthorized attempt is rejected with the expected exit code. Every
// message below is expected to throw, so contract storage is never committed
// and each message runs against the same pristine `settled` state.
//
// Accompanies the security audit for https://github.com/xlabtg/dns-contract/issues/1.
// Acts as a permanent regression guard against accidental removal of the
// `throw_unless(..., equal_slices(sender_address, owner_address))` guards.

const {funcer} = require("./funcer");
const {
    TON, OWNER_ADDRESS, USER_ADDRESS, FC_ITEM,
    makeStorageItemComplete, AUCTION_START_TIME, CONTENT_EMPTY
} = require("./utils");

// A settled domain (no auction) owned by OWNER_ADDRESS.
const settled = makeStorageItemComplete({});

funcer({'logVmOps': false, 'logFiftCode': false}, {
    'path': './func/',
    'fc': FC_ITEM,
    'data': settled,
    // Network config with the DNS blacklist (id 80) present but NOT containing
    // this item's index -> governance decision must report "not found" (415).
    "configParams": {
        80: [
            'cell', [
                "uint256->cell", {
                    '1': [
                        'uint8', 0,
                        'Address', '0:' + USER_ADDRESS,
                        'uint2', 0,
                        'uint1', 0,
                        'coins', 0,
                        'uint1', 0
                    ]
                }
            ]
        ]
    },
    'in_msgs': [
        // 1) A non-owner MUST NOT be able to transfer the domain -> throw 401.
        {
            "time": AUCTION_START_TIME,
            "contract_balance": 1000 * TON,
            "sender": '0:' + USER_ADDRESS, // NOT the owner
            "amount": 1 * TON,
            "body": [
                'uint32', 0x5fcc3d14, // op::transfer
                'uint64', 123,
                'Address', '0:' + USER_ADDRESS, // new_owner_address (attacker)
                'uint2', 0,
                'uint1', 0,
                'coins', 0,
                'uint1', 0
            ],
            "exit_code": 401
        },
        // 2) A non-owner MUST NOT be able to edit content -> throw 410.
        {
            "time": AUCTION_START_TIME,
            "contract_balance": 1000 * TON,
            "sender": '0:' + USER_ADDRESS, // NOT the owner
            "amount": 1 * TON,
            "body": [
                'uint32', 0x1a0b9d51, // op::edit_content
                'uint64', 123,
                'cell', CONTENT_EMPTY
            ],
            "exit_code": 410
        },
        // 3) A non-owner MUST NOT be able to change a DNS record -> throw 411.
        {
            "time": AUCTION_START_TIME,
            "contract_balance": 1000 * TON,
            "sender": '0:' + USER_ADDRESS, // NOT the owner
            "amount": 1 * TON,
            "body": [
                'uint32', 0x4eb1f0f9, // op::change_dns_record
                'uint64', 123,
                'uint256', '0xe8d44050873dba865aa7c170ab4cce64d90839a34dcfd6cf71d14e0205443b1b',
            ],
            "exit_code": 411
        },
        // 4) An unknown operation code MUST be rejected -> throw 0xffff (65535).
        {
            "time": AUCTION_START_TIME,
            "contract_balance": 1000 * TON,
            "sender": '0:' + OWNER_ADDRESS,
            "amount": 1 * TON,
            "body": [
                'uint32', 0xdeadbeef, // unknown op
                'uint64', 123,
            ],
            "exit_code": 0xffff
        },
        // 5) dns_balance_release MUST fail while the domain is still fresh
        //    (last_fill_up_time within one year) -> throw 414.
        {
            "time": AUCTION_START_TIME, // last_fill_up_time == AUCTION_START_TIME => age 0
            "contract_balance": 1000 * TON,
            "sender": '0:' + USER_ADDRESS,
            "amount": 100 * TON,
            "body": [
                'uint32', 0x4ed14b65, // op::dns_balance_release
                'uint64', 123,
            ],
            "exit_code": 414
        },
        // 6) A governance decision MUST NOT apply to a domain that is not
        //    blacklisted in the network config -> throw 415.
        {
            "time": AUCTION_START_TIME,
            "contract_balance": 1000 * TON,
            "sender": '0:' + USER_ADDRESS,
            "amount": 1 * TON,
            "body": [
                'uint32', 0x44beae41, // op::process_governance_decision
                'uint64', 123,
            ],
            "exit_code": 415
        },
    ]
});
