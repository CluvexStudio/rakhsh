use super::{Confirm, CONFIRM_ROUNDS};

#[test]
fn a_single_bad_round_is_not_announced() {
    let mut c = Confirm::default();
    assert!(!c.observe("iran", "down"));
    assert!(!c.observe("iran", "ok"));
    assert!(!c.observe("iran", "down"));
    assert!(!c.observe("iran", "ok"));
}

#[test]
fn a_state_that_persists_is_announced_once() {
    let mut c = Confirm::default();
    for _ in 1..CONFIRM_ROUNDS {
        assert!(!c.observe("iran", "down"));
    }
    assert!(
        c.observe("iran", "down"),
        "the confirmed state is announced"
    );
    assert!(!c.observe("iran", "down"), "and not announced again");
    assert!(!c.observe("iran", "down"));
}

#[test]
fn recovery_is_announced_only_once_it_holds() {
    let mut c = Confirm::default();
    for _ in 1..CONFIRM_ROUNDS {
        c.observe("iran", "down");
    }
    assert!(c.observe("iran", "down"));
    for _ in 1..CONFIRM_ROUNDS {
        assert!(!c.observe("iran", "ok"));
    }
    assert!(c.observe("iran", "ok"));
}

#[test]
fn a_state_that_changes_mid_confirmation_restarts_the_count() {
    let mut c = Confirm::default();
    assert!(!c.observe("iran", "cpu"));
    assert!(!c.observe("iran", "loss"));
    for _ in 1..CONFIRM_ROUNDS {
        assert!(!c.observe("iran", "cpu"));
    }
    assert!(c.observe("iran", "cpu"));
}

#[test]
fn nodes_are_tracked_apart() {
    let mut c = Confirm::default();
    for _ in 1..CONFIRM_ROUNDS {
        c.observe("iran", "down");
    }
    assert!(!c.observe("exit", "down"), "the exit has its own count");
    assert!(c.observe("iran", "down"));
}
