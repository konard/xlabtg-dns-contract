// Security regression test for nft-item.fc governance during an active auction.
//
// A governance decision (op::process_governance_decision) must be rejected
// while the domain still has a live auction -> throw 413. This guards the
// invariant that on-chain governance cannot seize/destroy a domain out from
// under an ongoing auction.
//
// Accompanies the security audit for https://github.com/xlabtg/dns-contract/issues/1.

const {funcer} = require("./funcer");
const {
    TON, USER_ADDRESS, FC_ITEM, makeStorageItem, AUCTION_START_TIME
} = require("./utils");

// An item still in auction (owner is zero address, auction cell is present).
const inAuction = makeStorageItem({});

funcer({'logVmOps': false, 'logFiftCode': false}, {
    'path': './func/',
    'fc': FC_ITEM,
    'data': inAuction,
    'in_msgs': [
        {
            "time": AUCTION_START_TIME,
            "contract_balance": 1000 * TON,
            "sender": '0:' + USER_ADDRESS,
            "amount": 1 * TON,
            "body": [
                'uint32', 0x44beae41, // op::process_governance_decision
                'uint64', 123,
            ],
            "exit_code": 413
        },
    ]
});
