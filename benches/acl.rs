use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use enumflags2::BitFlags;
use shitspeak_rs::acl::{evaluate_permission, ACLPermissions, ACL};
use shitspeak_rs::channels::Channel;
use shitspeak_rs::client::group::ClientMembershipQuery;

/// Build a channel with `n` ACL entries, half allowing and half denying.
fn make_channel_with_acls(n: usize) -> Channel {
    let mut acls = Vec::with_capacity(n);
    for i in 0..n {
        let allow: BitFlags<ACLPermissions> = if i % 2 == 0 {
            (ACLPermissions::Enter | ACLPermissions::Traverse | ACLPermissions::Speak).into()
        } else {
            ACLPermissions::Enter.into()
        };
        let deny: BitFlags<ACLPermissions> = if i % 3 == 0 {
            ACLPermissions::Traverse.into()
        } else {
            BitFlags::empty()
        };
        acls.push(ACL {
            user_id: Some(i as i32),
            group: None,
            apply_here: true,
            apply_subs: i % 4 == 0,
            allow,
            deny,
        });
    }
    Channel {
        id: 1,
        name: "Test".into(),
        position: 0,
        max_users: 0,
        parent_id: Some(0),
        inherit_acl: true,
        links: Default::default(),
        description_hash: None,
        acls,
    }
}

fn make_membership() -> ClientMembershipQuery<'static> {
    let group_refs: &'static [&str] = Box::leak(Box::new(["admin", "user", "trusted"]));
    let token_refs: &'static [&str] = Box::leak(Box::new(["token_a", "token_b"]));
    ClientMembershipQuery {
        groups: group_refs,
        authenticated: true,
        access_tokens: token_refs,
        cert_hash: None,
        has_verified_cert_chain: false,
        ip_address: None,
        asn: None,
        country_code: None,
    }
}

// ── channel_has_restriction: for loop vs iter().any() ──────────────────────

fn bench_channel_has_restriction_for_loop(c: &mut Criterion) {
    let mut group = c.benchmark_group("channel_has_restriction");
    for n in [0, 10, 100, 1000] {
        let ch = make_channel_with_acls(n);
        group.bench_with_input(BenchmarkId::new("for_loop", n), &ch, |b, ch| {
            b.iter(|| {
                let mut found = false;
                for acl in &ch.acls {
                    if acl.apply_here && acl.deny.contains(ACLPermissions::Traverse) {
                        found = true;
                        break;
                    }
                }
                black_box(found)
            });
        });
    }
}

fn bench_channel_has_restriction_iter_any(c: &mut Criterion) {
    let mut group = c.benchmark_group("channel_has_restriction");
    for n in [0, 10, 100, 1000] {
        let ch = make_channel_with_acls(n);
        group.bench_with_input(BenchmarkId::new("iter_any", n), &ch, |b, ch| {
            b.iter(|| {
                let found = ch
                    .acls
                    .iter()
                    .any(|acl| acl.apply_here && acl.deny.contains(ACLPermissions::Traverse));
                black_box(found)
            });
        });
    }
}

// ── evaluate_permission ───────────────────────────────────────────────────

fn bench_evaluate_permission(c: &mut Criterion) {
    let membership = make_membership();
    let ancestors: Vec<Channel> = (0..5)
        .map(|i| {
            let mut ch = make_channel_with_acls(10);
            ch.id = 100 + i as u32;
            ch.parent_id = if i == 0 {
                Some(0)
            } else {
                Some(100 + (i - 1) as u32)
            };
            ch
        })
        .collect();

    let mut group = c.benchmark_group("evaluate_permission");
    for n in [0, 10, 100] {
        let channel = make_channel_with_acls(n);
        group.bench_with_input(
            BenchmarkId::new("acls", n),
            &(&channel, &ancestors),
            |b, (ch, anc)| {
                b.iter(|| {
                    evaluate_permission(
                        black_box(ch),
                        black_box(anc),
                        black_box(Some(42)),
                        black_box(&membership),
                        black_box(ch.id),
                    )
                });
            },
        );
    }
}

// ── evaluate_permission with deep nesting ─────────────────────────────────

fn bench_evaluate_permission_deep(c: &mut Criterion) {
    let membership = make_membership();

    let mut group = c.benchmark_group("evaluate_permission_deep");
    for depth in [1, 5, 10, 20] {
        // Build a chain of `depth` ancestors, each with 10 ACLs, all inheriting
        let mut ancestors: Vec<Channel> = Vec::with_capacity(depth);
        for i in 0..depth {
            let mut ch = make_channel_with_acls(10);
            ch.id = 100 + i as u32;
            ch.parent_id = if i == 0 {
                Some(0)
            } else {
                Some(100 + (i - 1) as u32)
            };
            ch.inherit_acl = true;
            ancestors.push(ch);
        }
        let channel = ancestors.last().unwrap().clone();

        group.bench_with_input(
            BenchmarkId::new("depth", depth),
            &(&channel, &ancestors),
            |b, (ch, anc)| {
                b.iter(|| {
                    evaluate_permission(
                        black_box(ch),
                        black_box(anc),
                        black_box(Some(42)),
                        black_box(&membership),
                        black_box(ch.id),
                    )
                });
            },
        );
    }
}

// ── evaluate_permission with mixed inheritance ────────────────────────────

fn bench_evaluate_permission_mixed_inherit(c: &mut Criterion) {
    let membership = make_membership();

    let mut group = c.benchmark_group("evaluate_permission_mixed_inherit");
    for break_at in [0, 1, 3, 5] {
        // Build 10 ancestors; the one at `break_at` has inherit_acl = false
        let mut ancestors: Vec<Channel> = Vec::with_capacity(10);
        for i in 0..10 {
            let mut ch = make_channel_with_acls(10);
            ch.id = 100 + i as u32;
            ch.parent_id = if i == 0 {
                Some(0)
            } else {
                Some(100 + (i - 1) as u32)
            };
            ch.inherit_acl = i != break_at;
            ancestors.push(ch);
        }
        let channel = ancestors.last().unwrap().clone();

        group.bench_with_input(
            BenchmarkId::new("break_at", break_at),
            &(&channel, &ancestors),
            |b, (ch, anc)| {
                b.iter(|| {
                    evaluate_permission(
                        black_box(ch),
                        black_box(anc),
                        black_box(Some(42)),
                        black_box(&membership),
                        black_box(ch.id),
                    )
                });
            },
        );
    }
}

// ── ACL match_group ───────────────────────────────────────────────────────

fn bench_acl_match_group(c: &mut Criterion) {
    let membership = make_membership();
    let acl_user = ACL {
        user_id: Some(42),
        group: None,
        apply_here: true,
        apply_subs: false,
        allow: BitFlags::from(ACLPermissions::Enter),
        deny: BitFlags::empty(),
    };
    let acl_group = ACL {
        user_id: None,
        group: Some("admin".into()),
        apply_here: true,
        apply_subs: false,
        allow: BitFlags::from(ACLPermissions::Write),
        deny: BitFlags::empty(),
    };

    c.bench_function("acl_match_user", |b| {
        b.iter(|| black_box(acl_user.match_user(42)))
    });
    c.bench_function("acl_match_group", |b| {
        b.iter(|| {
            acl_group.match_group(
                black_box(1),
                black_box(Some(1)),
                black_box(&[]),
                black_box(&membership),
            )
        })
    });
}

criterion_group!(
    benches,
    bench_channel_has_restriction_for_loop,
    bench_channel_has_restriction_iter_any,
    bench_evaluate_permission,
    bench_evaluate_permission_deep,
    bench_evaluate_permission_mixed_inherit,
    bench_acl_match_group,
);
criterion_main!(benches);
