// DVEL Cinematic Simulator for TFT Hardware Visualizer

#include <cstdio>
#include <vector>
#include <thread>
#include <chrono>
#include <iostream>

#include "../core/types.hpp"
#include "../core/bus.hpp"
#include "../core/node.hpp"
#include "../core/gossip.hpp"

using namespace dvelsim;

int main() {
    // Disable stdout buffering for real-time streaming
    std::setvbuf(stdout, NULL, _IONBF, 0);

    // --- Create nodes ---
    NodeRuntime n0(0, make_pubkey(0xA1), make_secret(0xA1));
    NodeRuntime n1(1, make_pubkey(0xB2), make_secret(0xB2));
    NodeRuntime n2(2, make_pubkey(0xC3), make_secret(0xC3));

    std::vector<NodeRuntime*> nodes = {&n0, &n1, &n2};
    std::vector<uint32_t> peer_ids = {0, 1, 2};

    // Keep track of pubkey tags / IDs mapping for printing
    // Node 0 -> A1 (0xA1), Node 1 -> B2 (0xB2), Node 2 -> C3 (0xC3)
    std::vector<std::string> peer_pubkeys = {
        pubkey_to_hex(n0.author()),
        pubkey_to_hex(n1.author()),
        pubkey_to_hex(n2.author())
    };

    // --- Message bus & gossip ---
    MessageBus bus(/*default_delay_ticks=*/1);
    BroadcastAll gossip(/*delay_ticks=*/1);

    const uint64_t END_TICK = 25;

    for (uint64_t t = 0; t <= END_TICK; t++) {
        // Signal Tick Start
        std::printf("{\"type\":\"tick_start\",\"tick\":%llu}\n", (unsigned long long)t);

        // Helper to produce a standard event and gossip it
        auto produce_and_gossip = [&](NodeRuntime& n, uint8_t payload_tag) {
            const dvel_hash_t prev = n.current_tip_or_zero();
            const uint64_t ts = 1000 + t;
            Message msg = n.make_event_message(ts, prev, payload_tag);

            // Self accept
            n.local_append(msg, t, /*verbose=*/false);
            
            // Print self link immediately
            dvel_hash_t ev_hash = dvel_hash_event_struct(&msg.event);
            std::printf("{\"type\":\"link\",\"tick\":%llu,\"node\":%u,\"hash\":\"%s\",\"parent\":\"%s\",\"author\":%u}\n",
                        (unsigned long long)t, n.id(), hash_to_hex(ev_hash).c_str(), hash_to_hex(prev).c_str(), n.id());

            // Gossip to all peers
            gossip.broadcast_event(bus, t, n.id(), msg, peer_ids);
        };

        // Schedule Event Productions (Deterministic Scenario)
        if (t == 1) produce_and_gossip(n0, 0x10);
        if (t == 3) produce_and_gossip(n1, 0x11);
        if (t == 5) produce_and_gossip(n2, 0x12);
        if (t == 7) produce_and_gossip(n0, 0x13);

        if (t == 9) {
            // SYBIL ATTACK: Node 2 equivocates!
            // It creates event A and sends it ONLY to Node 0.
            // It creates event B (conflicting, same prev, same timestamp) and sends it ONLY to Node 1.
            const dvel_hash_t prev = n2.current_tip_or_zero();
            const uint64_t ts = 1000 + t;

            Message msgA = n2.make_event_message(ts, prev, 0x99); // Payload 0x99
            Message msgB = n2.make_event_message(ts, prev, 0xAA); // Payload 0xAA

            // Node 2 accepts msgA locally
            n2.local_append(msgA, t, /*verbose=*/false);
            dvel_hash_t hashA = dvel_hash_event_struct(&msgA.event);
            std::printf("{\"type\":\"link\",\"tick\":%llu,\"node\":2,\"hash\":\"%s\",\"parent\":\"%s\",\"author\":2}\n",
                        (unsigned long long)t, hash_to_hex(hashA).c_str(), hash_to_hex(prev).c_str());

            // Gossip conflicting event msgA only to Node 0, and msgB only to Node 1
            gossip.broadcast_event(bus, t, n2.id(), msgA, {0});
            gossip.broadcast_event(bus, t, n2.id(), msgB, {1});
        }

        if (t == 12) produce_and_gossip(n0, 0x14);
        if (t == 14) produce_and_gossip(n1, 0x15);
        if (t == 16) produce_and_gossip(n0, 0x16);
        if (t == 18) produce_and_gossip(n1, 0x17);
        if (t == 20) produce_and_gossip(n2, 0x18); // Node 2 recovers and tries to gossip normally

        // Deliver Scheduled Gossip Messages on Bus
        bus.deliver(t, [&](uint32_t to, const Message& msg) {
            if (to < nodes.size()) {
                nodes[to]->inbox_push(msg);
            }
        });

        // Process Inbox and Print Linkage Telemetry
        for (NodeRuntime* n : nodes) {
            // We inspect nodes before and after processing inbox to print link visualizer details
            std::deque<Message> inbox_copy = n->inbox_; // peek inbox
            ProcessStats stats = n->process_inbox(t, /*verbose=*/false);

            if (stats.accepted > 0) {
                // To get the newly linked hashes, we look at the node's trace or check ledger tips.
                // For simplicity, since we know what messages were in the inbox, we print the link:
                for (const auto& msg : inbox_copy) {
                    dvel_hash_t ev_hash = dvel_hash_event_struct(&msg.event);
                    std::printf("{\"type\":\"link\",\"tick\":%llu,\"node\":%u,\"hash\":\"%s\",\"parent\":\"%s\",\"author\":%u}\n",
                                (unsigned long long)t, n->id(), hash_to_hex(ev_hash).c_str(), hash_to_hex(msg.event.prev_hash).c_str(), msg.from);
                }
            }
        }

        // Observe & Stream Tips, Merkle Roots, and Sybil Peer Weights
        for (NodeRuntime* n : nodes) {
            // Tips
            dvel_preferred_tip_t pref = n->preferred_tip(t);
            dvel_hash_t m_root{};
            std::string merkle_str = n->merkle_root(m_root) ? hash_to_hex(m_root) : "null";
            std::string pref_tip_str = pref.has_value ? hash_to_hex(pref.tip) : "null";

            std::printf("{\"type\":\"tip\",\"tick\":%llu,\"node\":%u,\"tip\":\"%s\",\"score\":%llu,\"merkle\":\"%s\"}\n",
                        (unsigned long long)t, n->id(), pref_tip_str.c_str(), (unsigned long long)pref.score, merkle_str.c_str());

            // Peer weights
            for (uint32_t peer_idx = 0; peer_idx < nodes.size(); ++peer_idx) {
                uint64_t w = n->author_weight_sybil_fp(t, nodes[peer_idx]->author());
                // Scaling fixed_point is 1000, so a weight of 1000 = 1.0, 0 = 0.0
                std::printf("{\"type\":\"weight\",\"tick\":%llu,\"node\":%u,\"peer\":%u,\"weight\":%llu}\n",
                            (unsigned long long)t, n->id(), peer_idx, (unsigned long long)w);
            }
        }

        std::printf("{\"type\":\"tick_end\",\"tick\":%llu}\n", (unsigned long long)t);
        std::fflush(stdout);

        // Sleep for 1.5 seconds between ticks for human-friendly real-time telemetry streaming
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    }

    std::printf("{\"type\":\"sim_end\"}\n");
    std::fflush(stdout);
    return 0;
}
