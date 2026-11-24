#include "ddp/integrity.hpp"

#include <charconv>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void usage(const char* executable) {
    std::cerr << "Usage:\n"
              << "  " << executable << " submit <ledger.tsv> <transaction-id> <actor> <action> <amount-minor>\n"
              << "  " << executable << " verify <ledger.tsv>\n"
              << "  " << executable << " demo <ledger.tsv>\n\n"
              << "Set DDP_WATERMARK_KEY to a secret of at least 16 bytes.\n";
}

std::int64_t parse_amount(const std::string& text) {
    std::int64_t value{};
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) {
        throw std::invalid_argument("amount-minor must be a signed 64-bit integer");
    }
    return value;
}

std::string watermark_key() {
    const char* value = std::getenv("DDP_WATERMARK_KEY");
    if (value == nullptr) throw std::invalid_argument("DDP_WATERMARK_KEY is not set");
    return value;
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 3) {
            usage(argv[0]);
            return 2;
        }
        const std::string command = argv[1];
        ddp::AuditLedger ledger(argv[2], watermark_key());

        if (command == "verify" && argc == 3) {
            const auto result = ledger.verify();
            std::cout << (result.valid ? "VALID" : "INVALID") << ": " << result.message
                      << " (" << result.events_checked << " events checked)\n";
            return result.valid ? 0 : 1;
        }
        if (command == "submit" && argc == 7) {
            ddp::IntegrityAgent agent(ledger, 100000000); // 1,000,000.00 in minor units
            const auto result = agent.submit(argv[3], argv[4], argv[5], parse_amount(argv[6]));
            std::cout << "decision=" << result.decision << "\n"
                      << "explanation=" << result.explanation << "\n"
                      << "watermark=" << result.watermark << "\n";
            return 0;
        }
        if (command == "demo" && argc == 3) {
            const auto id = "demo-" + std::to_string(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
            ddp::IntegrityAgent agent(ledger, 100000000);
            const auto result = agent.submit(id, "demo-operator", "advisory.transfer", 125000);
            std::cout << "transaction=" << id << "\ndecision=" << result.decision
                      << "\nwatermark=" << result.watermark << "\n";
            return 0;
        }
        usage(argv[0]);
        return 2;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
