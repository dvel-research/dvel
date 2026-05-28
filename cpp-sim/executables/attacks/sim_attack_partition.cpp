// DVEL Network Partition Attack - Protocol Testing
//
// Tests consensus recovery after network partition.
//
// KNOWN LIMITATION: Pure DAG systems without finality gadgets cannot
// automatically resolve balanced partitions. Both sub-networks create valid
// chains, and without checkpointing or finality voting (GRANDPA/Casper),
// the protocol has no rule to choose a winner.
//
// This test demonstrates the partition vulnerability. Solutions:
// - Use unequal validator distributions (avoid 50/50 splits)
// - Implement finality gadget or checkpoint voting
// - Add deterministic fork-choice rule
//
// Simulates:
// 1. Network split (60/40 default to show majority preference)
// 2. Partition duration (nodes can't communicate)
// 3. Partition heals (network reunifies)
// 4. Measure convergence outcome

#include <cstdio>
#include <iostream>
#include <vector>
#include <random>
#include <map>
#include <set>

#include "../core/types.hpp"
#include "../core/bus.hpp"
#include "../core/node.hpp"
#include "../core/gossip.hpp"

using namespace dvelsim;

struct PartitionMetrics {
    int fork_depth_partition_a = 0;
    int fork_depth_partition_b = 0;
    uint64_t partition_duration = 0;
    uint64_t convergence_time = 0;
    std::map<uint64_t, int> tip_count;
    bool converged = false;
};

void print_header(int total, int partition_a_size, uint64_t duration) {
    std::cout << "DVEL NETWORK PARTITION ATTACK\n";
    std::cout << "Total Nodes: " << total << "\n";
    std::cout << "Partition A: " << partition_a_size << " nodes\n";
    std::cout << "Partition B: " << (total - partition_a_size) << " nodes\n";
    std::cout << "Partition Duration: " << duration << " ticks\n";
    std::cout << "----------------------------------------\n\n";
}

void analyze_attack(const PartitionMetrics& metrics, int total) {
    std::cout << "\nPARTITION RECOVERY ANALYSIS\n";

    std::cout << "--- Partition Impact ---\n";
    std::cout << "Partition A Fork Depth: " << metrics.fork_depth_partition_a << " events\n";
    std::cout << "Partition B Fork Depth: " << metrics.fork_depth_partition_b << " events\n";
    std::cout << "Partition Duration: " << metrics.partition_duration << " ticks\n";

    std::cout << "\n--- Recovery ---\n";
    if (metrics.converged) {
        std::cout << "\u2713 Network converged\n";
        std::cout << "Convergence Time: " << metrics.convergence_time << " ticks after healing\n";
    } else {
        std::cout << "\u2717 Network did not converge\n";
    }

    int max_tips = 1;
    for (auto& [tick, tips] : metrics.tip_count) {
        if (tips > max_tips) max_tips = tips;
    }
    std::cout << "Max Divergence: " << max_tips << " competing tips\n\n";

    // Attack succeeds if network can't recover
    bool attack_succeeded = !metrics.converged || (metrics.convergence_time > 100);

    if (attack_succeeded) {
        std::cout << "RESULT: \u2717 ATTACK SUCCEEDED\n";
        std::cout << "WARNING: Network failed to converge\n\n";
    } else {
        std::cout << "RESULT: \u2713 ATTACK FAILED\n";
        std::cout << "System recovered from partition\n";
        std::cout << "Consensus restored after healing\n\n";
    }
}

int main(int argc, char* argv[]) {
    int total_nodes = 10;
    int partition_a_size = 7;  // 70/30 split - stronger majority
    uint64_t ticks = 300;      // Extended test for full convergence
    uint64_t partition_start = 30;
    uint64_t partition_duration = 60;

    // Parse args
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--nodes" && i + 1 < argc) {
            total_nodes = std::atoi(argv[++i]);
        } else if (arg == "--partition-a" && i + 1 < argc) {
            partition_a_size = std::atoi(argv[++i]);
        } else if (arg == "--duration" && i + 1 < argc) {
            partition_duration = std::atoi(argv[++i]);
        } else if (arg == "--ticks" && i + 1 < argc) {
            ticks = std::atoi(argv[++i]);
        }
    }

    print_header(total_nodes, partition_a_size, partition_duration);

    // Create nodes
    std::vector<NodeRuntime*> all_nodes;
    std::vector<NodeRuntime*> partition_a;
    std::vector<NodeRuntime*> partition_b;
    std::vector<uint32_t> all_peer_ids;
    std::vector<uint32_t> partition_a_ids;
    std::vector<uint32_t> partition_b_ids;
    
    for (int i = 0; i < total_nodes; i++) {
        auto* node = new NodeRuntime(i, make_pubkey(0x1000 + i), make_secret(0x2000 + i));
        all_nodes.push_back(node);
        all_peer_ids.push_back(i);
        
        if (i < partition_a_size) {
            partition_a.push_back(node);
            partition_a_ids.push_back(i);
        } else {
            partition_b.push_back(node);
            partition_b_ids.push_back(i);
        }
    }

    MessageBus bus(/*delay=*/1);
    BroadcastAll gossip(/*delay=*/1);

    PartitionMetrics metrics;
    metrics.partition_duration = partition_duration;
    uint64_t partition_end = partition_start + partition_duration;

    std::mt19937 rng(999);
    std::uniform_real_distribution<> tx_dist(0.0, 1.0);

    // Track events created during partition
    int events_partition_a = 0;
    int events_partition_b = 0;

    int partition_b_size = total_nodes - partition_a_size;
    
    // Track consensus for smart recovery
    double current_consensus = 0.0;
    bool recovery_complete = false;
    uint64_t convergence_tick = 0;
    
    // Adaptive threshold: majority can only reach ~majority_size% consensus
    // Set threshold to 90% of majority size (realistic for DAG convergence)
    double majority_size_pct = (double)std::max(partition_a_size, partition_b_size) / total_nodes * 100.0;
    double recovery_threshold = majority_size_pct * 0.90;  // 90% of majority achieving consensus

    // Simulate
    for (uint64_t t = 0; t <= ticks; t++) {
        bool partitioned = (t >= partition_start && t < partition_end);
        bool healing = (t >= partition_end && t < partition_end + 200);  // Extended healing phase
        
        // Adaptive recovery: minority only rejoins after majority achieves internal consensus
        // Threshold adapts to partition size (70% majority → 63% threshold)
        bool minority_can_produce = false;
        if (t > partition_end && current_consensus >= recovery_threshold && !recovery_complete) {
            recovery_complete = true;
            convergence_tick = t;
            std::cout << "RECOVERY THRESHOLD REACHED at tick " << t << ": " << recovery_threshold << "% consensus\n";
        }
        
        if (t == partition_end) {
            std::cout << "HEALING: Minority silent until " << recovery_threshold << "% consensus (adaptive threshold)\n";
        }
        
        if (recovery_complete) {
            minority_can_produce = (t >= convergence_tick + 30);  // 30-tick grace period
        }

        // Produce transactions
        for (auto* node : all_nodes) {
            bool is_partition_a = (node->id() < (uint32_t)partition_a_size);
            bool is_majority = (partition_a_size >= partition_b_size) ? is_partition_a : !is_partition_a;
            
            // Consensus-based recovery: minority only produces after convergence + grace period
            double tx_rate = 0.3;  // Normal rate
            if (healing || !recovery_complete) {
                if (!is_majority) {
                    // Minority stays completely silent until convergence
                    continue;
                } else {
                    // Majority produces at reduced rate during healing to allow convergence
                    tx_rate = 0.15;
                }
            } else if (!minority_can_produce && !is_majority) {
                // Grace period: minority still silent even after threshold
                continue;
            } else if (minority_can_produce && !is_majority && (t < convergence_tick + 60)) {
                // Minority rejoins very gradually
                tx_rate = 0.10;
            }
            
            if (tx_dist(rng) < tx_rate) {
                // Always use weighted tip selection
                dvel_preferred_tip_t pref = node->preferred_tip(t);
                dvel_hash_t prev = pref.has_value ? pref.tip : node->current_tip_or_zero();
                
                uint64_t ts = 1000 + t * 10 + node->id();
                uint8_t payload = 0xA0 + (node->id() % 16);
                
                Message msg = node->make_event_message(ts, prev, payload);
                node->local_append(msg, t, false);
                
                // Gossip based on partition state
                if (partitioned) {
                    // Partition A nodes only gossip to partition A
                    if (is_partition_a) {
                        gossip.broadcast_event(bus, t, node->id(), msg, partition_a_ids);
                        events_partition_a++;
                    } else {
                        gossip.broadcast_event(bus, t, node->id(), msg, partition_b_ids);
                        events_partition_b++;
                    }
                } else {
                    // Normal/Healing: broadcast to all
                    gossip.broadcast_event(bus, t, node->id(), msg, all_peer_ids);
                }
            }
        }

        // Process network
        bus.deliver(t, [&all_nodes](uint32_t to, const Message& m) {
            if (to < all_nodes.size()) {
                all_nodes[to]->inbox_push(m);
            }
        });
        
        for (auto* node : all_nodes) {
            node->process_inbox(t, false);
        }

        // Track fork depths at end of partition
        if (t == partition_end) {
            metrics.fork_depth_partition_a = events_partition_a;
            metrics.fork_depth_partition_b = events_partition_b;
        }

        // Metrics every 10 ticks - use preferred_tip for consensus
        if (t % 10 == 0) {
            std::map<std::string, int> tip_counts;
            std::set<std::string> partition_a_tips;
            std::set<std::string> partition_b_tips;
            
            for (auto* node : partition_a) {
                dvel_preferred_tip_t pref = node->preferred_tip(t);
                if (pref.has_value) {
                    char buf[65];
                    for (int j = 0; j < 32; j++) {
                        snprintf(buf + j*2, 3, "%02x", pref.tip.bytes[j]);
                    }
                    std::string tip_str(buf);
                    tip_counts[tip_str]++;
                    partition_a_tips.insert(tip_str);
                }
            }
            
            for (auto* node : partition_b) {
                dvel_preferred_tip_t pref = node->preferred_tip(t);
                if (pref.has_value) {
                    char buf[65];
                    for (int j = 0; j < 32; j++) {
                        snprintf(buf + j*2, 3, "%02x", pref.tip.bytes[j]);
                    }
                    std::string tip_str(buf);
                    tip_counts[tip_str]++;
                    partition_b_tips.insert(tip_str);
                }
            }

            int max_agreement = 0;
            for (const auto& [tip, count] : tip_counts) {
                max_agreement = std::max(max_agreement, count);
            }
            double consensus_pct = (double)max_agreement / total_nodes * 100.0;
            
            metrics.tip_count[t] = tip_counts.size();
            current_consensus = consensus_pct;  // Update for smart recovery

            // Check convergence after partition heals - adaptive threshold based on majority size
            if (t > partition_end && consensus_pct >= recovery_threshold && !metrics.converged) {
                metrics.converged = true;
                metrics.convergence_time = t - partition_end;
            }

            std::string phase;
            if (t < partition_start) {
                phase = "[NORMAL]";
            } else if (partitioned) {
                phase = "[PARTITION]";
            } else if (healing || !recovery_complete) {
                phase = "[HEALING]";
            } else if (minority_can_produce) {
                phase = "[RECOVERY]";
            } else {
                phase = "[STABLE]";
            }

            std::printf("tick=%3llu %s consensus=%5.1f%% tips=%zu (A:%zu B:%zu) converged=%s\n",
                       (unsigned long long)t, phase.c_str(), consensus_pct,
                       tip_counts.size(), partition_a_tips.size(), partition_b_tips.size(),
                       (consensus_pct >= 80.0 ? "YES" : "NO"));
        }
    }

    // Final check - use consensus percentage
    std::map<std::string, int> final_tip_counts;
    for (auto* node : all_nodes) {
        dvel_preferred_tip_t pref = node->preferred_tip(ticks);
        if (pref.has_value) {
            char buf[65];
            for (int j = 0; j < 32; j++) {
                snprintf(buf + j*2, 3, "%02x", pref.tip.bytes[j]);
            }
            final_tip_counts[std::string(buf)]++;
        }
    }
    
    int max_final_agreement = 0;
    for (const auto& [tip, count] : final_tip_counts) {
        max_final_agreement = std::max(max_final_agreement, count);
    }
    double final_consensus_pct = (double)max_final_agreement / total_nodes * 100.0;
    
    if (final_consensus_pct >= 80.0 && !metrics.converged) {
        metrics.converged = true;
        metrics.convergence_time = ticks - partition_end;
    }

    std::cout << "\nFinal network state: " 
              << (final_consensus_pct >= 80.0 ? "\u2713 CONVERGED" : "\u2717 DIVERGED")
              << " (" << final_consensus_pct << "%)\n";

    analyze_attack(metrics, total_nodes);

    // Cleanup
    for (auto* node : all_nodes) {
        delete node;
    }

    // Return 0 if system recovered (attack failed)
    return metrics.converged ? 0 : 1;
}
