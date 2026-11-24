#include "ddp/integrity.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <array>
#include <charconv>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string_view>

namespace ddp {
namespace {

constexpr std::string_view kGenesisHash =
    "0000000000000000000000000000000000000000000000000000000000000000";

std::string to_hex(const unsigned char* data, std::size_t size) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0x0f]);
    }
    return out;
}

std::string from_hex(const std::string& input) {
    if (input.size() % 2 != 0) throw std::runtime_error("invalid hex field");
    auto nibble = [](char c) -> unsigned char {
        if (c >= '0' && c <= '9') return static_cast<unsigned char>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<unsigned char>(c - 'a' + 10);
        if (c >= 'A' && c <= 'F') return static_cast<unsigned char>(c - 'A' + 10);
        throw std::runtime_error("invalid hex field");
    };
    std::string out;
    out.reserve(input.size() / 2);
    for (std::size_t i = 0; i < input.size(); i += 2) {
        out.push_back(static_cast<char>((nibble(input[i]) << 4) | nibble(input[i + 1])));
    }
    return out;
}

std::string sha256(const std::string& input) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int length = 0;
    if (EVP_Digest(input.data(), input.size(), digest.data(), &length,
                   EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("SHA-256 operation failed");
    }
    return to_hex(digest.data(), length);
}

std::string hmac_sha256(const std::string& key, const std::string& input) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int length = 0;
    if (key.size() > static_cast<std::size_t>(INT_MAX) ||
        HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
             reinterpret_cast<const unsigned char*>(input.data()), input.size(),
             digest.data(), &length) == nullptr) {
        throw std::runtime_error("HMAC-SHA-256 operation failed");
    }
    return to_hex(digest.data(), length);
}

std::vector<std::string> split_tabs(const std::string& line) {
    std::vector<std::string> fields;
    std::size_t start = 0;
    while (true) {
        const auto end = line.find('\t', start);
        fields.push_back(line.substr(start, end == std::string::npos ? end : end - start));
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return fields;
}

template <typename T>
T parse_integer(const std::string& value, const char* field_name) {
    T parsed{};
    const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (result.ec != std::errc{} || result.ptr != value.data() + value.size()) {
        throw std::runtime_error(std::string("invalid ") + field_name + " in ledger");
    }
    return parsed;
}

std::string event_payload(const AuditEvent& event) {
    std::ostringstream out;
    out << event.sequence << '\t' << event.timestamp_ms << '\t'
        << to_hex(reinterpret_cast<const unsigned char*>(event.transaction_id.data()), event.transaction_id.size()) << '\t'
        << to_hex(reinterpret_cast<const unsigned char*>(event.actor.data()), event.actor.size()) << '\t'
        << to_hex(reinterpret_cast<const unsigned char*>(event.action.data()), event.action.size()) << '\t'
        << event.amount_minor << '\t' << event.watermark << '\t' << event.previous_hash;
    return out.str();
}

AuditEvent parse_event(const std::string& line) {
    const auto fields = split_tabs(line);
    if (fields.size() != 9) throw std::runtime_error("malformed ledger row");
    AuditEvent event;
    event.sequence = parse_integer<std::uint64_t>(fields[0], "sequence");
    event.timestamp_ms = parse_integer<std::int64_t>(fields[1], "timestamp");
    event.transaction_id = from_hex(fields[2]);
    event.actor = from_hex(fields[3]);
    event.action = from_hex(fields[4]);
    event.amount_minor = parse_integer<std::int64_t>(fields[5], "amount");
    event.watermark = fields[6];
    event.previous_hash = fields[7];
    event.hash = fields[8];
    return event;
}

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

void require_text(const std::string& value, const char* name) {
    if (value.empty() || value.size() > 1024) {
        throw std::invalid_argument(std::string(name) + " must contain 1 to 1024 bytes");
    }
}

} // namespace

AuditLedger::AuditLedger(std::filesystem::path path, std::string watermark_key)
    : path_(std::move(path)), watermark_key_(std::move(watermark_key)) {
    if (path_.empty()) throw std::invalid_argument("ledger path is required");
    if (watermark_key_.size() < 16) {
        throw std::invalid_argument("watermark key must be at least 16 bytes");
    }
}

std::string AuditLedger::make_watermark(const std::string& transaction_id,
                                        std::int64_t amount_minor) const {
    const std::string message =
        to_hex(reinterpret_cast<const unsigned char*>(transaction_id.data()), transaction_id.size()) +
        ":" + std::to_string(amount_minor);
    return hmac_sha256(watermark_key_, message);
}

std::vector<AuditEvent> AuditLedger::read_events() const {
    std::vector<AuditEvent> result;
    std::ifstream input(path_, std::ios::binary);
    if (!input) {
        if (!std::filesystem::exists(path_)) return result;
        throw std::runtime_error("unable to read ledger: " + path_.string());
    }
    std::string line;
    while (std::getline(input, line)) {
        if (line.empty()) throw std::runtime_error("empty row in ledger");
        result.push_back(parse_event(line));
    }
    if (input.bad()) throw std::runtime_error("error while reading ledger");
    return result;
}

std::vector<AuditEvent> AuditLedger::events() const { return read_events(); }

bool AuditLedger::has_submission(const std::string& transaction_id) const {
    for (const auto& event : read_events()) {
        if (event.action == "transaction.submitted" && event.transaction_id == transaction_id) return true;
    }
    return false;
}

VerificationResult AuditLedger::verify() const {
    try {
        const auto all_events = read_events();
        std::string expected_previous(kGenesisHash);
        std::uint64_t expected_sequence = 1;
        for (const auto& event : all_events) {
            if (event.sequence != expected_sequence) {
                return {false, static_cast<std::size_t>(expected_sequence - 1), "sequence mismatch"};
            }
            if (event.previous_hash != expected_previous) {
                return {false, static_cast<std::size_t>(expected_sequence - 1), "previous-hash mismatch"};
            }
            if (event.watermark != make_watermark(event.transaction_id, event.amount_minor)) {
                return {false, static_cast<std::size_t>(expected_sequence - 1), "watermark authentication failed"};
            }
            if (event.hash != sha256(event_payload(event))) {
                return {false, static_cast<std::size_t>(expected_sequence - 1), "event hash mismatch"};
            }
            expected_previous = event.hash;
            ++expected_sequence;
        }
        return {true, all_events.size(), "ledger integrity verified"};
    } catch (const std::exception& error) {
        return {false, 0, error.what()};
    }
}

void AuditLedger::append(const std::string& transaction_id,
                         const std::string& actor,
                         const std::string& action,
                         std::int64_t amount_minor) {
    require_text(transaction_id, "transaction ID");
    require_text(actor, "actor");
    require_text(action, "action");

    const auto verification = verify();
    if (!verification.valid) throw std::runtime_error("refusing to append: " + verification.message);
    const auto all_events = read_events();

    AuditEvent event;
    event.sequence = static_cast<std::uint64_t>(all_events.size()) + 1;
    event.timestamp_ms = now_ms();
    event.transaction_id = transaction_id;
    event.actor = actor;
    event.action = action;
    event.amount_minor = amount_minor;
    event.watermark = make_watermark(transaction_id, amount_minor);
    event.previous_hash = all_events.empty() ? std::string(kGenesisHash) : all_events.back().hash;
    event.hash = sha256(event_payload(event));

    std::ofstream output(path_, std::ios::binary | std::ios::app);
    if (!output) throw std::runtime_error("unable to open ledger for append: " + path_.string());
    output << event_payload(event) << '\t' << event.hash << '\n';
    output.flush();
    if (!output) throw std::runtime_error("failed to write ledger event");
}

IntegrityAgent::IntegrityAgent(AuditLedger& ledger, std::int64_t review_threshold_minor)
    : ledger_(ledger), review_threshold_minor_(review_threshold_minor) {
    if (review_threshold_minor_ <= 0) {
        throw std::invalid_argument("review threshold must be positive");
    }
}

SubmissionResult IntegrityAgent::submit(const std::string& transaction_id,
                                        const std::string& actor,
                                        const std::string& action,
                                        std::int64_t amount_minor) {
    require_text(transaction_id, "transaction ID");
    require_text(actor, "actor");
    require_text(action, "action");
    if (ledger_.has_submission(transaction_id)) {
        throw std::invalid_argument("transaction ID has already been submitted");
    }

    ledger_.append(transaction_id, actor, "transaction.submitted", amount_minor);

    std::string decision;
    std::string explanation;
    if (amount_minor <= 0) {
        decision = "reject";
        explanation = "amount must be greater than zero";
    } else if (amount_minor >= review_threshold_minor_) {
        decision = "review_required";
        explanation = "amount meets or exceeds the configured review threshold";
    } else {
        decision = "allow";
        explanation = "within configured prototype policy threshold";
    }

    ledger_.append(transaction_id, actor, action, amount_minor);
    ledger_.append(transaction_id, "claw-integrity-agent", "claw.decision." + decision, amount_minor);
    return {ledger_.events().back().watermark, decision, explanation};
}

} // namespace ddp
