# Overlay Network Integration Guide

## Public Primitives

- Membership: `MembershipTable`, `MembershipEvent`, `MemberState`.
- Presence metadata: `NodePresenceMap`, `NodePresenceDelta`, `PresenceDigestEntry`.
- SWIM: `SwimState`, `SwimMessage`, `ProbePlan`.
- Routing: `RouteCandidate`, `RouteClass`, `RouteSelectionPolicy`, `select_best_path`, `select_stable_path`.
- Transport: `TransportCapabilities`, `TransportKind`, `choose_transport_pair`.
- Hardening: `FrameGuard`, `PeerRateLimiter`, `FailureCircuitBreaker`.
- Overlay coordinator: `OverlayNetwork`.

## Integration Notes

- Keep liveness authority in `MembershipTable`.
- Treat presence as metadata and anti-entropy data plane only.
- Use `choose_stable_path` for anti-flap behavior in production loops.
- Apply ingress checks (`allow_incoming_frame`) before decode/dispatch.
- Use `OrderedDeliveryState` when best-effort ordering is acceptable.
