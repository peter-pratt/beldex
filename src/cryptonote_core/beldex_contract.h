//
// Created by allard on 31-7-22.
//

#ifndef BELDEX_BELDEX_CONTRACT_H
#define BELDEX_BELDEX_CONTRACT_H

#endif //BELDEX_BELDEX_CONTRACT_H



namespace contract {
    enum struct contract_type : uint16_t {
        create = 0,
        public_method,
        signed_method,
        terminate,
        _count
    };
}