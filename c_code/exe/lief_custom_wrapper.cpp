#include <LIEF/PE/Binary.h>
#include <LIEF/LIEF.hpp>
#include <LIEF/PE/Binary.hpp>

extern "C" {
    bool lief_pe_has_signatures(Pe_Binary_t *pe_binary) {
        // from c binding to cpp lol
        LIEF::PE::Binary* bin = reinterpret_cast<LIEF::PE::Binary*>(pe_binary);
        return bin->has_signatures();
    }

    bool lief_pe_has_imports(Pe_Binary_t *pe_binary) {
        // from c binding to cpp lol
        LIEF::PE::Binary* bin = reinterpret_cast<LIEF::PE::Binary*>(pe_binary);
        return bin->has_imports();
    }

    bool lief_pe_has_sections(Pe_Binary_t *pe_binary) {
        // from c binding to cpp lol
        LIEF::PE::Binary* bin = reinterpret_cast<LIEF::PE::Binary*>(pe_binary);
        return bin->sections().size() > 0;
    }
}
