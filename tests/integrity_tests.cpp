#include "ddp/integrity.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
}

int main() {
    try {
        const auto path = std::filesystem::temp_directory_path() / "ddp-integrity-test-ledger.tsv";
        std::filesystem::remove(path);
        ddp::AuditLedger ledger(path, "test-key-with-more-than-16-bytes");
        ddp::IntegrityAgent agent(ledger, 10000);

        const auto low = agent.submit("txn-001", "advisor-1", "advisory.transfer", 5000);
        check(low.decision == "allow", "below-threshold transaction should be allowed by prototype policy");
        check(low.watermark.size() == 64, "watermark should be a SHA-256 HMAC hex digest");

        const auto high = agent.submit("txn-002", "advisor-2", "advisory.transfer", 10000);
        check(high.decision == "review_required", "threshold transaction should require review");
        check(ledger.verify().valid, "new ledger should verify");
        check(ledger.events().size() == 6, "each submission should record three audit events");

        bool duplicate_rejected = false;
        try {
            (void)agent.submit("txn-001", "advisor-1", "advisory.transfer", 5000);
        } catch (const std::invalid_argument&) {
            duplicate_rejected = true;
        }
        check(duplicate_rejected, "duplicate transaction ID should be rejected");

        {
            std::ofstream tamper(path, std::ios::binary | std::ios::app);
            tamper << "tampered";
        }
        check(!ledger.verify().valid, "malformed/tampered ledger should fail verification");
        std::filesystem::remove(path);
        std::cout << "All DDP/CLAW integrity tests passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Test failure: " << error.what() << '\n';
        return 1;
    }
}
