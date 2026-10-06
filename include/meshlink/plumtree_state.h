#pragma once

#ifndef MESH_PLUMTREE_STATE_H
#define MESH_PLUMTREE_STATE_H

#include "meshlink/peer_directory.h"
#include "meshlink/routed_message_key.h"

#include <chrono>
#include <cstddef>
#include <deque>
#include <map>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace invilite::Mesh {

    struct PlumtreeConfig {
        std::chrono::milliseconds   announcementInterval      = std::chrono::milliseconds(100);  // IHAVE batch period
        std::chrono::milliseconds   graftTimeout              = std::chrono::milliseconds(500);  // announced, not arrived → GRAFT
        std::chrono::milliseconds   treeOptimizationThreshold = std::chrono::milliseconds(50);   // announcement earlier than the full copy by more → swap links
        size_t                      maxMissingMessages        = 4096;              // announced-but-missing messages tracked at once
        size_t                      maxMissingPerLink         = 512;               // share one link's announcements may open — fake keys from one neighbor cannot block repair for the rest
        size_t                      maxAnnouncersPerMessage   = 8;                 // neighbors remembered per missing message, GRAFT tries them in order
        // A link that GRAFTs for missing messages this often within pinWindow oscillates (several senders' PRUNEs cut the
        // eager graph apart, docs/router.md 4.3): pinned eager until it closes, duplicates on it no longer PRUNE. 0 = never.
        size_t                      pinAfterGrafts            = 3;
        std::chrono::seconds        pinWindow                 = std::chrono::minutes(10);
    };

    // Decisions for a message seen for the first time (docs/router.md 4.3)
    struct PlumtreeNewMessageDecision {
        std::vector<PeerId>     fullCopyTo;                                         // eager links, minus where it came from, its originator and its announcers
        std::optional<PeerId>   graftTo;                                            // tree optimization: the faster announcer becomes eager (empty GRAFT)
        std::optional<PeerId>   pruneTo;                                            // … and the slower eager link becomes lazy (PRUNE)
    };

    // Plumtree for BROADCAST (docs/router.md 4.3): which links get full copies (eager) and which only announcements (lazy),
    // which announced messages are missing and whom to GRAFT them from. Decides only — the Router sends, checks duplicates
    // and serves GRAFTs from BroadcastCache. Links are identified by PeerId, not by connections, so a future group
    // delivery (class C) can run it over paths instead of TCP links.
    // Not thread-safe: owned by the Router thread. Time comes in as `now` (tests drive it by hand).
    class PlumtreeState {
    public:
        explicit PlumtreeState(PlumtreeConfig config = {});

        // A new link starts eager: until something is pruned, Plumtree is exactly flooding
        void addLink(const PeerId& peer);

        // Returns the lazy links to send an empty GRAFT to when an eager link was lost (fast repair: a short flood that
        // duplicates prune back); the returned links are eager from now on
        std::vector<PeerId> removeLink(const PeerId& peer);

        // A verified message seen for the first time. `receivedFrom` is empty for our own message. `forwarding` is false
        // when TTL ends here: nothing is sent or announced, but a pending GRAFT for it is cancelled all the same.
        PlumtreeNewMessageDecision onNewMessage(const RoutedMessageKey& key, const std::optional<PeerId>& receivedFrom, bool forwarding, std::chrono::steady_clock::time_point now);

        // A copy we already had. True: send PRUNE to `receivedFrom` (it was eager, now lazy). A copy with a higher TTL than
        // ours is a better path, not a redundant one — no PRUNE.
        bool onDuplicate(const PeerId& receivedFrom, bool higherTtlThanOurs);

        void onPrune(const PeerId& from);

        // `from` is eager from now on; the Router answers the keys it holds. Only a GRAFT that asks for messages counts
        // towards pinning — an empty one (fast repair, tree optimization) is no sign of oscillation.
        void onGraft(const PeerId& from, bool asksForMessages, std::chrono::steady_clock::time_point now);

        // Keys announced by `from` that we have not seen (the Router filters with its duplicate memory)
        void onAnnouncement(const PeerId& from, const std::vector<RoutedMessageKey>& unseenKeys, std::chrono::steady_clock::time_point now);

        // GRAFTs due now, per link: each missing message goes to its next announcer, which becomes eager; a message whose
        // announcers are used up is given up
        std::unordered_map<PeerId, std::vector<RoutedMessageKey>, PeerIDHash> takeDueGrafts(std::chrono::steady_clock::time_point now);

        // The IHAVE batch, per link, once the announcement interval has passed
        std::unordered_map<PeerId, std::vector<RoutedMessageKey>, PeerIDHash> takeDueAnnouncements(std::chrono::steady_clock::time_point now);

        // Earliest moment takeDueGrafts / takeDueAnnouncements has something; empty when nothing waits
        [[nodiscard]] std::optional<std::chrono::steady_clock::time_point> nextDeadline() const;

        [[nodiscard]] bool isEager(const PeerId& peer) const;
        [[nodiscard]] bool hasLink(const PeerId& peer) const { return this->eagerByLink.contains(peer); }
        [[nodiscard]] bool isPinned(const PeerId& peer) const;
        [[nodiscard]] size_t pinnedLinkCount() const;
        [[nodiscard]] size_t missingCount() const { return this->missing.size(); }

    private:
        using GraftDeadlines = std::multimap<std::chrono::steady_clock::time_point, RoutedMessageKey>;

        struct MissingMessage {
            std::chrono::steady_clock::time_point   firstAnnouncedAt;
            GraftDeadlines::iterator                graftAt;                        // this message's entry in graftDeadlines
            PeerId                                  openedBy{};                     // the link whose announcement opened it — its share is charged
            std::deque<PeerId>                      announcers;                     // not yet asked, in announcement order
            std::vector<PeerId>                     asked;                          // announcers already sent a GRAFT — they hold it too
            bool                                    graftSent = false;
        };
        using MissingMessages = std::unordered_map<RoutedMessageKey, MissingMessage, RoutedMessageKeyHash>;

        MissingMessages::iterator eraseMissing(MissingMessages::iterator entry);
        void countGraftForMissing(const PeerId& link, std::chrono::steady_clock::time_point now);   // sent or received — both ends count the same GRAFT

        PlumtreeConfig                                                          config;
        std::unordered_map<PeerId, bool, PeerIDHash>                            eagerByLink;
        std::unordered_map<PeerId, std::deque<std::chrono::steady_clock::time_point>, PeerIDHash> recentGraftsByLink;   // within pinWindow, until pinned
        std::unordered_set<PeerId, PeerIDHash>                                  pinnedLinks;
        MissingMessages                                                         missing;
        GraftDeadlines                                                          graftDeadlines;     // earliest first: nextDeadline and takeDueGrafts never scan
        std::unordered_map<PeerId, size_t, PeerIDHash>                          missingOpenedByLink;
        std::unordered_map<PeerId, std::vector<RoutedMessageKey>, PeerIDHash>   queuedAnnouncements;
        std::optional<std::chrono::steady_clock::time_point>                    announcementsDueAt;     // set when the first key is queued
    };

} // namespace invilite::Mesh

#endif // MESH_PLUMTREE_STATE_H
