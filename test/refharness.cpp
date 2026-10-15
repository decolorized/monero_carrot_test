// refharness.cpp — builds unsigned sets with the monero reference code
// (fcmp++-beta-stressnet-v3), signs them with the reference and with cwtool,
// and checks cwtool's signatures with the reference code.
//
// Build (Linux): first build monero branch fcmp++-beta-stressnet-v3
// (seraphis-migration/monero) in <monero>/build, then
//   g++ -std=c++17 -O1 refharness.cpp \
//       -I<monero>/src -I<monero>/contrib/epee/include -I<monero>/external \
//       -I<monero>/external/easylogging++ -I<monero>/external/rapidjson/include \
//       -I<monero>/build/generated_include -I<monero>/build \
//       -I<monero>/external/mx25519/include -I<monero>/src/fcmp_pp/fcmp_pp_rust \
//       <all static libraries from <monero>/build: libwallet.a, libcarrot_impl.a,
//        libcarrot_core.a, libfcmp_pp.a, libfcmp_pp_rust.a, libcryptonote_core.a, ...> \
//       -lboost_* -lsodium -lssl -lcrypto -lunbound -lzmq -lhidapi-libusb -lpthread -ldl
#include "wallet/hot_cold.h"
#include "wallet/hot_cold_serialization.h"
#include "wallet/tx_builder.h"
#include "carrot_impl/address_device_hierarchies.h"
#include "carrot_impl/spend_device_ram_borrowed.h"
#include "carrot_impl/knowledge_proof_utils.h"
#include "carrot_impl/tx_builder_outputs.h"
#include "carrot_impl/tx_proposal_utils.h"
#include "carrot_core/device_ram_borrowed.h"
#include "carrot_impl/address_device_ram_borrowed.h"
#include "carrot_core/enote_utils.h"
#include "carrot_core/destination.h"
#include "fcmp_pp/prove.h"
#include "ringct/rctOps.h"
#include "crypto/crypto.h"
#include "string_tools.h"
#include "file_io_utils.h"
#include "mx25519.h"

#include <cstdio>
#include <iostream>

using namespace tools::wallet::cold;
using tools::wallet::make_sal_opening_hint_from_transfer_details;
using tools::wallet::collect_non_burned_transfers_by_onetime_address;

static std::string hex(const void *p, size_t n) { return epee::string_tools::buff_to_hex_nodelimer(std::string((const char *)p, n)); }

struct Wallet {
    crypto::secret_key k_s, k_v;
    crypto::public_key K_s;
    std::shared_ptr<carrot::cryptonote_view_incoming_key_ram_borrowed_device> kv_dev;
    std::shared_ptr<carrot::cryptonote_hierarchy_address_device> addr;
    std::shared_ptr<carrot::spend_device_ram_borrowed> spend;
    Wallet() {
        k_s = rct::rct2sk(rct::skGen());
        k_v = rct::rct2sk(rct::skGen());
        crypto::secret_key_to_public_key(k_s, K_s);
        kv_dev = std::make_shared<carrot::cryptonote_view_incoming_key_ram_borrowed_device>(k_v);
        addr = std::make_shared<carrot::cryptonote_hierarchy_address_device>(kv_dev, K_s);
        spend = std::make_shared<carrot::spend_device_ram_borrowed>(k_s, k_v);
    }
};

static mx25519_pubkey rand_x25519()
{
    crypto::secret_key s = rct::rct2sk(rct::skGen());
    mx25519_pubkey p;
    mx25519_scmul_base_unclamped(mx25519_select_impl(MX25519_TYPE_AUTO), &p, (const mx25519_privkey *)&s);
    return p;
}

// pre-Carrot output to subaddress j (main if j == 0)
static exported_pre_carrot_transfer_details make_pre_carrot(const Wallet &w, carrot::subaddress_index j,
                                                            uint64_t amount, bool rct, bool with_additional)
{
    exported_pre_carrot_transfer_details e{};
    crypto::public_key Ks, Kv;
    w.addr->get_address_pubkeys({j, carrot::AddressDeriveType::PreCarrot}, Ks, Kv);
    crypto::secret_key r = rct::rct2sk(rct::skGen());
    crypto::public_key R;
    const bool sub = j.is_subaddress();
    // R = r G (main) or r K^j_s (subaddress, in additional)
    crypto::secret_key_to_public_key(r, R);
    crypto::public_key Radd = rct::rct2pk(rct::scalarmultKey(rct::pk2rct(Ks), rct::sk2rct(r)));
    const uint64_t idx = with_additional ? 1 : 0;
    crypto::key_derivation D;
    crypto::generate_key_derivation(sub ? Kv : Kv, r, D);   // 8 r K^j_v
    crypto::public_key O;
    crypto::derive_public_key(D, idx, Ks, O);
    e.m_pubkey = O;
    e.m_internal_output_index = idx;
    e.m_global_output_index = 1000 + rand() % 1000;
    e.m_tx_pubkey = (sub && !with_additional) ? Radd : R;
    if (with_additional) {
        e.m_additional_tx_keys.push_back(rct::rct2pk(rct::pkGen()));
        e.m_additional_tx_keys.push_back(sub ? Radd : R);
    }
    e.m_flags.flags = 0;
    e.m_flags.m_rct = rct;
    e.m_amount = amount;
    e.m_subaddr_index_major = j.major;
    e.m_subaddr_index_minor = j.minor;
    return e;
}

static exported_carrot_transfer_details make_carrot(carrot::subaddress_index j, uint64_t amount,
                                                    int kind /*0 normal,1 selfsend payment,2 selfsend change,3 coinbase,4 pid*/)
{
    exported_carrot_transfer_details e{};
    e.flags.flags = 0;
    e.amount = amount;
    e.janus_anchor = carrot::gen_janus_anchor();
    if (kind == 3) {
        e.flags.m_coinbase = 1;
        e.block_index = 100000 + rand() % 1000;
        e.subaddr_index = {0, 0};
    } else {
        e.tx_first_key_image = rct::rct2ki(rct::pkGen());
        e.subaddr_index = j;
    }
    if (kind == 1 || kind == 2) {
        e.flags.m_selfsend = 1;
        e.flags.m_enote_type_change = kind == 2;
        e.selfsend_enote_ephemeral_pubkey = rand_x25519();
    }
    if (kind == 4) {
        e.flags.m_has_pid = 1;
        e.payment_id = carrot::gen_payment_id();
        e.subaddr_index = {0, 0};
    }
    return e;
}

struct Case {
    std::string name;
    std::vector<exported_transfer_details_variant> outs;
    std::vector<size_t> spend;                 // indices into outs
    std::vector<carrot::CarrotDestinationV1> pay;
    std::vector<std::pair<carrot::subaddress_index, carrot::CarrotEnoteType>> self;
};

static int fails = 0;

static bool run_case(const Wallet &w, const Case &c, const std::string &dir, const std::string &keys_args)
{
    std::cout << "=== " << c.name << std::endl;
    // import outputs as the hot wallet would see them
    wallet2_basic::transfer_container tds;
    for (const auto &etd : c.outs) {
        tds.push_back(import_cold_output(etd, *w.addr, w.spend.get()));
        tds.back().m_key_image_known = false;      // request all
        tds.back().m_key_image_request = true;
        if (std::holds_alternative<exported_carrot_transfer_details>(etd)
                && std::get<exported_carrot_transfer_details>(etd).flags.m_coinbase)
            tds.back().m_block_height = std::get<exported_carrot_transfer_details>(etd).block_index;
        if (std::holds_alternative<exported_pre_carrot_transfer_details>(etd)) {
            const auto &pe = std::get<exported_pre_carrot_transfer_details>(etd);
            tds.back().m_global_output_index = pe.m_global_output_index;
            // the real hot wallet knows the true mask: derive it from whichever R opens O
            std::vector<crypto::public_key> cands{pe.m_tx_pubkey};
            cands.insert(cands.end(), pe.m_additional_tx_keys.begin(), pe.m_additional_tx_keys.end());
            crypto::public_key Ks;
            w.addr->get_address_spend_pubkey({{pe.m_subaddr_index_major, pe.m_subaddr_index_minor}, carrot::AddressDeriveType::PreCarrot}, Ks);
            for (const auto &R : cands) {
                crypto::key_derivation D;
                crypto::generate_key_derivation(R, w.k_v, D);
                crypto::public_key O;
                crypto::derive_public_key(D, pe.m_internal_output_index, Ks, O);
                if (O != pe.m_pubkey) continue;
                crypto::secret_key sc;
                crypto::derivation_to_scalar(D, pe.m_internal_output_index, sc);
                if (pe.m_flags.m_rct) {
                    const rct::key true_mask = rct::genCommitmentMask(rct::sk2rct(sc));
                    if (true_mask != tds.back().m_mask) std::cout << "  (reference import got a different mask for output "
                        << tds.size() - 1 << "; using the true one)" << std::endl;
                    tds.back().m_mask = true_mask;
                }
                break;
            }
        }
    }

    // tx proposal
    carrot::CarrotTransactionProposalV1 p;
    uint64_t in_sum = 0;
    for (size_t i : c.spend) {
        p.input_proposals.push_back(make_sal_opening_hint_from_transfer_details(tds.at(i)));
        in_sum += tds.at(i).amount();
    }
    const uint64_t fee = 123456;
    uint64_t left = in_sum - fee;
    const size_t n_out = c.pay.size() + c.self.size();
    const uint64_t each = left / (n_out + 1);
    for (const auto &d : c.pay) {
        p.normal_payment_proposals.push_back({d, each, carrot::gen_janus_anchor()});
        left -= each;
    }
    for (size_t i = 0; i < c.self.size(); ++i) {
        const uint64_t a = (i + 1 == c.self.size()) ? left : each;
        left -= a;
        crypto::public_key Ks;
        w.addr->get_address_spend_pubkey({c.self[i].first, carrot::AddressDeriveType::PreCarrot}, Ks);
        p.selfsend_payment_proposals.push_back(carrot::CarrotPaymentProposalVerifiableSelfSendV1{
            .destination_address_spend_pubkey = Ks,
            .subaddr_index = {c.self[i].first, carrot::AddressDeriveType::PreCarrot},
            .amount = a,
            .enote_type = c.self[i].second,
            .enote_ephemeral_privkey = rct::rct2sk(rct::skGen()),
            .internal_message = std::nullopt});
    }
    p.dummy_encrypted_payment_id = carrot::gen_encrypted_payment_id();
    p.fee = fee;

    tools::wallet::pending_tx ptx{};
    ptx.construction_data = p;
    const auto uset = generate_unsigned_tx_set_from_pending_txs({ptx}, tds, true, *w.addr);
    std::string ufile;
    encrypt_unsigned_tx_set(uset, w.k_v, 1, ufile);
    const std::string up = dir + "/" + c.name + "_unsigned";
    epee::file_io_utils::save_string_to_file(up, ufile);

    // reference cold signing
    UnsignedTransactionSetVariant uset2;
    decrypt_unsigned_tx_set(ufile, w.k_v, 1, uset2);
    SignedCarrotTransactionSetV1 sref;
    std::unordered_map<crypto::hash, std::vector<crypto::secret_key>> eph;
    auto nofetch = [](const crypto::public_key &) -> carrot::InputProposalV1 { throw std::runtime_error("not found"); };
    sign_carrot_tx_set_v1(std::get<UnsignedCarrotTransactionSetV1>(uset2), nofetch, *w.addr, *w.spend, sref, eph);
    std::string sfile;
    encrypt_signed_tx_set(sref, w.k_v, 1, sfile);
    epee::file_io_utils::save_string_to_file(dir + "/" + c.name + "_signed_ref", sfile);

    // our signer
    const std::string mine = dir + "/" + c.name + "_signed_mine";
    const std::string cmd = "./cwtool sign " + keys_args + " " + up + " " + mine;
    if (system(cmd.c_str()) != 0) { std::cout << "  cwtool sign FAILED" << std::endl; ++fails; return false; }
    const std::string cmd2 = "./cwtool verify " + keys_args + " " + up + " " + dir + "/" + c.name + "_signed_ref";
    if (system(cmd2.c_str()) != 0) { std::cout << "  cwtool verify(ref) FAILED" << std::endl; ++fails; }

    // reference verification of our file
    std::string mfile;
    epee::file_io_utils::load_file_to_string(mine, mfile);
    SignedTransactionSetVariant sv;
    try { decrypt_signed_tx_set(mfile, w.k_v, 1, sv); }
    catch (const std::exception &e) { std::cout << "  ref cannot decrypt/parse ours: " << e.what() << std::endl; ++fails; return false; }
    const auto &sm = std::get<SignedCarrotTransactionSetV1>(sv);
    if (sm.tx_proposals.size() != 1) { std::cout << "  no resent proposals" << std::endl; ++fails; return false; }

    const auto fetch = make_supplemental_input_proposals_fetcher(tds);
    carrot::CarrotTransactionProposalV1 expanded;
    std::vector<crypto::key_image> kis;
    std::vector<FcmpRerandomizedOutputCompressed> rr;
    expand_carrot_transaction_proposal_and_rerandomized_outputs(sm.tx_proposals.at(0), fetch, *w.addr, *w.spend,
        expanded, kis, rr);
    crypto::hash h;
    carrot::make_signable_tx_hash_from_proposal_v1(expanded, nullptr, w.addr.get(), kis, h);
    bool ok = sm.signed_inputs.size() == kis.size();
    for (size_t i = 0; i < kis.size(); ++i) {
        auto it = sm.signed_inputs.find(kis[i]);
        if (it == sm.signed_inputs.end()) { std::cout << "  KI missing " << i << std::endl; ok = false; continue; }
        if (it->second.first != carrot::onetime_address_ref(expanded.input_proposals.at(i))) { std::cout << "  OTA mismatch" << std::endl; ok = false; }
        if (!fcmp_pp::verify_sal(h, rr[i].input, kis[i], it->second.second)) { std::cout << "  SA/L " << i << " REJECTED by reference" << std::endl; ok = false; }
    }
    // same set of other key images as reference, and valid
    if (sm.other_key_images.size() != sref.other_key_images.size()) { std::cout << "  other KI count differs " << sm.other_key_images.size() << " vs " << sref.other_key_images.size() << std::endl; ok = false; }
    const auto best = collect_non_burned_transfers_by_onetime_address(tds);
    for (const auto &e : sm.other_key_images) {
        auto r = sref.other_key_images.find(e.first);
        if (r == sref.other_key_images.end() || r->second.first != e.second.first) { std::cout << "  other KI mismatch" << std::endl; ok = false; continue; }
        const auto &td = tds.at(best.at(e.first));
        const bool biased = carrot::use_biased_hash_to_point(make_sal_opening_hint_from_transfer_details(td));
        if (!carrot::validate_key_image_proof(e.first, biased, e.second.first, e.second.second)) { std::cout << "  other KI proof REJECTED" << std::endl; ok = false; }
    }
    std::cout << (ok ? "  reference accepts our signed set" : "  FAIL") << " (" << kis.size() << " inputs, "
              << sm.other_key_images.size() << " other KIs)" << std::endl;
    if (!ok) ++fails;

    // outputs -> key images
    std::string ofile;
    encrypt_exported_outputs(0, c.outs.size(), c.outs, w.K_s, w.k_v, 1, ofile);
    const std::string op = dir + "/" + c.name + "_outputs";
    epee::file_io_utils::save_string_to_file(op, ofile);
    const std::string kp = dir + "/" + c.name + "_keyImages";
    if (system(("./cwtool ki " + keys_args + " " + op + " " + kp).c_str()) != 0) { std::cout << "  cwtool ki FAILED" << std::endl; ++fails; return false; }
    std::string kfile;
    epee::file_io_utils::load_file_to_string(kp, kfile);
    std::uint64_t off;
    std::vector<std::pair<crypto::key_image, carrot::KeyImageProofVariant>> proofs;
    try { decrypt_key_image_proofs(kfile, w.K_s, w.k_v, 1, off, proofs); }
    catch (const std::exception &e) { std::cout << "  ref cannot parse our key images: " << e.what() << std::endl; ++fails; return false; }
    bool kok = proofs.size() == tds.size() && off == 0;
    for (size_t i = 0; i < proofs.size() && kok; ++i) {
        const auto hint = make_sal_opening_hint_from_transfer_details(tds[i]);
        const crypto::key_image expect = w.spend->derive_key_image(hint);
        if (proofs[i].first != expect) { std::cout << "  KI " << i << " differs" << std::endl; kok = false; }
        if (!carrot::validate_key_image_proof(carrot::onetime_address_ref(hint), carrot::use_biased_hash_to_point(hint), proofs[i].first, proofs[i].second))
        { std::cout << "  KI proof " << i << " rejected" << std::endl; kok = false; }
    }
    std::cout << (kok ? "  reference accepts our key images (" : "  KEY IMAGES FAIL (") << proofs.size()
              << ", v" << (int)(unsigned char)kfile[23] << ")" << std::endl;
    if (!kok) ++fails;
    return ok && kok;
}

int main(int argc, char **argv)
{
    const std::string dir = argc > 1 ? argv[1] : "cases";
    srand(1234);
    Wallet w;
    const std::string keys_args = hex(&w.k_s, 32) + " " + hex(&w.k_v, 32);
    const carrot::subaddress_index main{0, 0}, sub1{0, 1}, sub2{2, 7};

    std::vector<Case> cases;
    {   Case c{"A_legacy_to_main"};
        c.outs = { make_pre_carrot(w, main, 5000000000ull, true, false), make_carrot(main, 3000000000ull, 0) };
        c.spend = {0, 1};
        c.pay = { carrot::gen_carrot_main_address_v1() };
        c.self = { {main, carrot::CarrotEnoteType::CHANGE} };
        cases.push_back(c); }
    {   Case c{"B_mixed_3out"};
        c.outs = { make_pre_carrot(w, sub1, 7000000000ull, true, false), make_carrot(sub2, 4000000000ull, 1),
                   make_carrot(main, 6000000000ull, 3), make_carrot(main, 1000000, 4), make_pre_carrot(w, main, 900000000ull, false, false) };
        c.spend = {0, 1, 2, 4};
        c.pay = { carrot::gen_carrot_subaddress_v1(), carrot::gen_carrot_integrated_address_v1() };
        c.self = { {sub1, carrot::CarrotEnoteType::CHANGE} };
        cases.push_back(c); }
    {   Case c{"C_2out_selfsends"};
        c.outs = { make_carrot(sub1, 8000000000ull, 2), make_carrot(main, 2000000000ull, 0) };
        c.spend = {0};
        c.self = { {sub2, carrot::CarrotEnoteType::PAYMENT}, {main, carrot::CarrotEnoteType::CHANGE} };
        cases.push_back(c); }
    {   Case c{"D_many_outputs"};
        c.outs = { make_carrot(main, 9000000000ull, 0), make_carrot(sub2, 9000000000ull, 0), make_pre_carrot(w, sub2, 9000000000ull, true, false) };
        c.spend = {0, 1, 2};
        c.pay = { carrot::gen_carrot_main_address_v1(), carrot::gen_carrot_subaddress_v1(), carrot::gen_carrot_main_address_v1(), carrot::gen_carrot_subaddress_v1() };
        c.self = { {main, carrot::CarrotEnoteType::CHANGE}, {sub1, carrot::CarrotEnoteType::PAYMENT} };
        cases.push_back(c); }
    {   Case c{"E_legacy_only_v3ki"};
        c.outs = { make_pre_carrot(w, main, 5000000000ull, true, false), make_pre_carrot(w, sub2, 2500000000ull, true, false) };
        c.spend = {0, 1};
        c.pay = { carrot::gen_carrot_integrated_address_v1() };
        c.self = { {main, carrot::CarrotEnoteType::CHANGE} };
        cases.push_back(c); }

    for (const auto &c : cases) {
        try { run_case(w, c, dir, keys_args); }
        catch (const std::exception &e) { std::cout << "  EXCEPTION " << e.what() << std::endl; ++fails; }
    }
    std::cout << "fails=" << fails << std::endl;
    return fails != 0;
}
