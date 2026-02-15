use std::collections::{HashMap, VecDeque};

#[derive(Clone, Debug)]
pub struct ReplayCache {
    window_ms: u64,
    // principal -> nonce -> seen_at
    seen: HashMap<Vec<u8>, HashMap<Vec<u8>, u64>>,
    // (seen_at, principal, nonce) for eviction
    queue: VecDeque<(u64, Vec<u8>, Vec<u8>)>,
}

#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error("timestamp outside window")]
    OutsideWindow,
    #[error("replay")]
    Replay,
}

impl ReplayCache {
    pub fn new(window_ms: u64) -> Self {
        Self {
            window_ms,
            seen: HashMap::new(),
            queue: VecDeque::new(),
        }
    }

    pub fn check_and_record(
        &mut self,
        now_ms: u64,
        ts_ms: u64,
        principal: &[u8],
        nonce: &[u8],
    ) -> Result<(), ReplayError> {
        let dt = if now_ms >= ts_ms {
            now_ms - ts_ms
        } else {
            ts_ms - now_ms
        };
        if dt > self.window_ms {
            return Err(ReplayError::OutsideWindow);
        }

        self.evict(now_ms);

        let p = principal.to_vec();
        let n = nonce.to_vec();
        let entry = self.seen.entry(p.clone()).or_default();
        if entry.contains_key(&n) {
            return Err(ReplayError::Replay);
        }
        entry.insert(n.clone(), ts_ms);
        self.queue.push_back((ts_ms, p, n));
        Ok(())
    }

    fn evict(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        while let Some((seen_at, p, n)) = self.queue.front().cloned() {
            if seen_at >= cutoff {
                break;
            }
            self.queue.pop_front();
            if let Some(m) = self.seen.get_mut(&p) {
                m.remove(&n);
                if m.is_empty() {
                    self.seen.remove(&p);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_cache_rejects_duplicate_nonce() {
        let mut c = ReplayCache::new(120_000);
        c.check_and_record(1_000_000, 1_000_000, b"a", b"n").unwrap();
        assert!(matches!(
            c.check_and_record(1_000_100, 1_000_100, b"a", b"n"),
            Err(ReplayError::Replay)
        ));
    }

    #[test]
    fn replay_cache_rejects_outside_window() {
        let mut c = ReplayCache::new(120_000);
        assert!(matches!(
            c.check_and_record(1_000_000, 1_000_000 + 120_001, b"a", b"n"),
            Err(ReplayError::OutsideWindow)
        ));
    }
}
