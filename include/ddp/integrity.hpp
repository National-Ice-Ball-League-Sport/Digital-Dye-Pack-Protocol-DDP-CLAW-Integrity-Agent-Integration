#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace ddp {

struct AuditEvent {
    std::uint64_t sequence{};
    std::int64_t timestamp_ms{};
    std::string transaction_id;
    std::string actor;
    std::string action;
    std::int64_t amount_minor{};
    std::string watermark;
    std::string previous_hash;
    std::string hash;
};

struct VerificationResult {
    bool valid{};
    std::size_t events_checked{};
    std::string message;
};

struct SubmissionResult {
    std::string watermark;
    std::string decision;
    std::string explanation;
};

// A local append-only, hash-chained audit file. This prototype assumes a single
// writer; production deployments need durable storage, access controls, and an
// independently anchored checkpoint to protect against full-file replacement.
class AuditLedger {
public:
    AuditLedger(std::filesystem::path path, std::string watermark_key);

    void append(const std::string& transaction_id,
                const std::string& actor,
                const std::string& action,
                std::int64_t amount_minor);

    VerificationResult verify() const;
    std::vector<AuditEvent> events() const;
    bool has_submission(const std::string& transaction_id) const;

private:
    std::filesystem::path path_;
    std::string watermark_key_;
    std::vector<AuditEvent> read_events() const;
    std::string make_watermark(const std::string& transaction_id,
                               std::int64_t amount_minor) const;
};

// CLAW-style policy gate: records an explicit decision, but does not execute or
// authorize a payment. Amounts are integer minor units (for example, cents).
class IntegrityAgent {
public:
    IntegrityAgent(AuditLedger& ledger, std::int64_t review_threshold_minor);

    SubmissionResult submit(const std::string& transaction_id,
                            const std::string& actor,
                            const std::string& action,
                            std::int64_t amount_minor);

private:
    AuditLedger& ledger_;
    std::int64_t review_threshold_minor_;
};

} // namespace ddp
