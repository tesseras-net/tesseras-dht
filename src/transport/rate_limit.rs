use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

/// Per-IP token bucket rate limiter.
pub struct RateLimiter {
    buckets: HashMap<IpAddr, TokenBucket>,
    rate_per_second: u32,
    burst: u32,
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    last_used: Instant,
}

impl RateLimiter {
    /// Create a new rate limiter with the given steady-state rate and burst capacity.
    pub fn new(rate_per_second: u32, burst: u32) -> Self {
        Self {
            buckets: HashMap::new(),
            rate_per_second,
            burst,
        }
    }

    /// Check if a request from the given IP is allowed. Returns true if allowed.
    pub fn check(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let rate = self.rate_per_second;
        let burst = self.burst;

        let bucket = self.buckets.entry(ip).or_insert_with(|| TokenBucket {
            tokens: burst as f64,
            last_refill: now,
            last_used: now,
        });

        // Refill tokens based on elapsed time
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens =
            (bucket.tokens + elapsed * rate as f64).min(burst as f64);
        bucket.last_refill = now;
        bucket.last_used = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Remove entries idle for longer than the given duration.
    pub fn cleanup(&mut self, max_idle: std::time::Duration) {
        let now = Instant::now();
        self.buckets.retain(|_, bucket| {
            now.duration_since(bucket.last_used) < max_idle
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_rate_limiter_allows_burst() {
        let mut limiter = RateLimiter::new(50, 10);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Should allow up to burst count
        for _ in 0..10 {
            assert!(limiter.check(ip));
        }
        // 11th should be denied
        assert!(!limiter.check(ip));
    }

    #[test]
    fn test_rate_limiter_different_ips() {
        let mut limiter = RateLimiter::new(50, 10);
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        // Exhaust ip1
        for _ in 0..10 {
            assert!(limiter.check(ip1));
        }
        assert!(!limiter.check(ip1));

        // ip2 should still be fine
        assert!(limiter.check(ip2));
    }

    #[test]
    fn test_rate_limiter_cleanup() {
        let mut limiter = RateLimiter::new(50, 10);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        limiter.check(ip);
        assert_eq!(limiter.buckets.len(), 1);

        // Cleanup with zero idle time removes everything
        limiter.cleanup(std::time::Duration::ZERO);
        assert_eq!(limiter.buckets.len(), 0);
    }
}
