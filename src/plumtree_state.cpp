#include "meshlink/plumtree_state.h"

#include <algorithm>
#include <utility>

namespace invilite::Mesh {

PlumtreeState::PlumtreeState(PlumtreeConfig config) : config(config) {}

void PlumtreeState::addLink(const PeerId& peer) {
    this->eagerByLink[peer] = true;
}

std::vector<PeerId> PlumtreeState::removeLink(const PeerId& peer) {
    const auto found = this->eagerByLink.find(peer);
    if (found == this->eagerByLink.end()) return {};
    const bool wasEager = found->second;
    this->eagerByLink.erase(found);
    this->queuedAnnouncements.erase(peer);
    for (auto& [key, entry] : this->missing) {
        std::erase(entry.announcers, peer);
        std::erase(entry.asked, peer);
    }

    // We cannot tell whether the lost link was our parent in the tree, so any eager loss repairs: every lazy link
    // turns eager on both sides for a moment
    std::vector<PeerId> graftTo;
    if (!wasEager) return graftTo;
    for (auto& [link, eager] : this->eagerByLink) {
        if (eager) continue;
        eager = true;
        graftTo.push_back(link);
    }
    return graftTo;
}

PlumtreeNewMessageDecision PlumtreeState::onNewMessage(const RoutedMessageKey& key, const std::optional<PeerId>& receivedFrom, bool forwarding, std::chrono::steady_clock::time_point now) {
    PlumtreeNewMessageDecision decision;

    // It was announced before it arrived: if the eager copy came clearly later than the lazy announcement, the lazy link
    // is the faster path — swap them, so the tree follows changing delays. Not once we asked by GRAFT: then the copy
    // answers us and the GRAFT already made the announcer eager.
    std::vector<PeerId> holders;                                                    // links that announced it to us: they have it
    if (auto found = this->missing.find(key); found != this->missing.end()) {
        const MissingMessage& entry = found->second;
        holders.assign(entry.announcers.begin(), entry.announcers.end());
        holders.insert(holders.end(), entry.asked.begin(), entry.asked.end());
        const bool cameEager = receivedFrom && this->isEager(*receivedFrom);
        if (!entry.graftSent && cameEager && !entry.announcers.empty() && now - entry.firstAnnouncedAt > this->config.treeOptimizationThreshold) {
            const PeerId fasterLink = entry.announcers.front();
            this->eagerByLink[fasterLink] = true;
            this->eagerByLink[*receivedFrom] = false;
            decision.graftTo = fasterLink;
            decision.pruneTo = *receivedFrom;
        }
        this->eraseMissing(found);
    }
    if (!forwarding) return decision;

    for (const auto& [link, eager] : this->eagerByLink) {
        if (link == receivedFrom || link == key.sender || std::find(holders.begin(), holders.end(), link) != holders.end()) continue;
        if (eager) {
            decision.fullCopyTo.push_back(link);
        } else {
            this->queuedAnnouncements[link].push_back(key);
            if (!this->announcementsDueAt) this->announcementsDueAt = now + this->config.announcementInterval;
        }
    }
    return decision;
}

bool PlumtreeState::onDuplicate(const PeerId& receivedFrom, bool higherTtlThanOurs) {
    const auto found = this->eagerByLink.find(receivedFrom);
    if (found == this->eagerByLink.end() || !found->second || higherTtlThanOurs) return false;
    found->second = false;
    return true;
}

void PlumtreeState::onPrune(const PeerId& from) {
    if (const auto found = this->eagerByLink.find(from); found != this->eagerByLink.end()) found->second = false;
}

void PlumtreeState::onGraft(const PeerId& from) {
    if (const auto found = this->eagerByLink.find(from); found != this->eagerByLink.end()) found->second = true;
}

void PlumtreeState::onAnnouncement(const PeerId& from, const std::vector<RoutedMessageKey>& unseenKeys, std::chrono::steady_clock::time_point now) {
    if (!this->eagerByLink.contains(from)) return;
    for (const RoutedMessageKey& key : unseenKeys) {
        auto found = this->missing.find(key);
        if (found == this->missing.end()) {
            // Bounded overall and per link: announcements of nothing cannot grow memory, nor crowd out other links' repairs
            size_t& openedByThisLink = this->missingOpenedByLink[from];
            if (this->missing.size() >= this->config.maxMissingMessages || openedByThisLink >= this->config.maxMissingPerLink) continue;
            ++openedByThisLink;
            found = this->missing.emplace(key, MissingMessage{ now, this->graftDeadlines.emplace(now + this->config.graftTimeout, key), from, {}, {}, false }).first;
        }
        auto& announcers = found->second.announcers;
        if (announcers.size() < this->config.maxAnnouncersPerMessage && std::find(announcers.begin(), announcers.end(), from) == announcers.end()) {
            announcers.push_back(from);
        }
    }
}

std::unordered_map<PeerId, std::vector<RoutedMessageKey>, PeerIDHash> PlumtreeState::takeDueGrafts(std::chrono::steady_clock::time_point now) {
    std::unordered_map<PeerId, std::vector<RoutedMessageKey>, PeerIDHash> grafts;
    while (!this->graftDeadlines.empty() && this->graftDeadlines.begin()->first <= now) {
        const auto entryIt = this->missing.find(this->graftDeadlines.begin()->second);
        MissingMessage& entry = entryIt->second;
        if (entry.announcers.empty()) { this->eraseMissing(entryIt); continue; }    // nobody left to ask: given up

        const PeerId announcer = entry.announcers.front();
        entry.announcers.pop_front();
        entry.asked.push_back(announcer);
        this->eagerByLink[announcer] = true;
        grafts[announcer].push_back(entryIt->first);
        entry.graftSent = true;
        this->graftDeadlines.erase(entry.graftAt);                                  // not answered in time → the next announcer
        entry.graftAt = this->graftDeadlines.emplace(now + this->config.graftTimeout, entryIt->first);
    }
    return grafts;
}

std::unordered_map<PeerId, std::vector<RoutedMessageKey>, PeerIDHash> PlumtreeState::takeDueAnnouncements(std::chrono::steady_clock::time_point now) {
    if (!this->announcementsDueAt || *this->announcementsDueAt > now) return {};
    this->announcementsDueAt.reset();
    return std::exchange(this->queuedAnnouncements, {});
}

std::optional<std::chrono::steady_clock::time_point> PlumtreeState::nextDeadline() const {
    std::optional<std::chrono::steady_clock::time_point> earliest = this->announcementsDueAt;
    if (!this->graftDeadlines.empty() && (!earliest || this->graftDeadlines.begin()->first < *earliest)) earliest = this->graftDeadlines.begin()->first;
    return earliest;
}

PlumtreeState::MissingMessages::iterator PlumtreeState::eraseMissing(MissingMessages::iterator entry) {
    if (const auto opener = this->missingOpenedByLink.find(entry->second.openedBy); opener != this->missingOpenedByLink.end() && --opener->second == 0) {
        this->missingOpenedByLink.erase(opener);
    }
    this->graftDeadlines.erase(entry->second.graftAt);
    return this->missing.erase(entry);
}

bool PlumtreeState::isEager(const PeerId& peer) const {
    const auto found = this->eagerByLink.find(peer);
    return found != this->eagerByLink.end() && found->second;
}

} // namespace invilite::Mesh
