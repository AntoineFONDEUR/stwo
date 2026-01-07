use std::collections::BTreeSet;
use std::ops::Deref;

use itertools::Itertools;

use super::channel::Channel;

pub const UPPER_BOUND_QUERY_BYTES: usize = 4;

/// An ordered set of query positions.
#[derive(Debug, Clone)]
pub struct Queries {
    /// Query positions sorted in ascending order.
    pub positions: Vec<usize>,
    /// Size of the domain from which the queries were sampled.
    pub log_domain_size: u32,
}

/// Query positions along with the branching pattern derived from them.
#[derive(Debug, Clone)]
pub struct QueriesWithBranching {
    pub queries: Queries,
    pub branching: Vec<Vec<u8>>,
}

impl Queries {
    /// Randomizes a set of query indices uniformly over the range [0, 2^`log_query_size`).
    pub fn generate(channel: &mut impl Channel, log_domain_size: u32, n_queries: usize) -> Self {
        let mut queries = BTreeSet::new();
        let mut query_cnt = 0;
        let max_query = (1 << log_domain_size) - 1;
        loop {
            let random_bytes = channel.draw_random_bytes();
            for chunk in random_bytes.chunks_exact(UPPER_BOUND_QUERY_BYTES) {
                let query_bits = u32::from_le_bytes(chunk.try_into().unwrap());
                let quotient_query = query_bits & max_query;
                queries.insert(quotient_query as usize);
                query_cnt += 1;
                if query_cnt == n_queries {
                    return Self {
                        positions: queries.into_iter().collect(),
                        log_domain_size,
                    };
                }
            }
        }
    }

    /// Calculates the matching query indices in a folded domain (i.e each domain point is doubled)
    /// given `self` (the queries of the original domain) and the number of folds between domains.
    pub fn fold(&self, n_folds: u32) -> Self {
        assert!(n_folds <= self.log_domain_size);
        Self {
            positions: self.iter().map(|q| q >> n_folds).dedup().collect(),
            log_domain_size: self.log_domain_size - n_folds,
        }
    }

    #[cfg(test)]
    pub fn from_positions(positions: Vec<usize>, log_domain_size: u32) -> Self {
        assert!(positions.is_sorted());
        assert!(positions.iter().all(|p| *p < (1 << log_domain_size)));
        Self {
            positions,
            log_domain_size,
        }
    }

    /// Returns the branching pattern per parent log size.
    /// Each entry is a bitmask: bit 0 for left child present, bit 1 for right child present.
    pub fn branching_by_parent(&self) -> Vec<Vec<u8>> {
        let max_log_size = self.log_domain_size as usize;
        let mut queries_by_log_size = vec![Vec::new(); max_log_size + 1];
        let mut current = self.clone();
        loop {
            let log_size = current.log_domain_size as usize;
            queries_by_log_size[log_size] = current.positions.clone();
            if log_size == 0 {
                break;
            }
            current = current.fold(1);
        }

        let mut branching = vec![Vec::new(); max_log_size + 1];
        for parent_log in 0..max_log_size {
            let parents = &queries_by_log_size[parent_log];
            let children = &queries_by_log_size[parent_log + 1];
            for &parent in parents {
                let left = parent * 2;
                let right = left + 1;
                let left_present = children.binary_search(&left).is_ok();
                let right_present = children.binary_search(&right).is_ok();
                let code = (left_present as u8) | ((right_present as u8) << 1);
                branching[parent_log].push(code);
            }
        }

        branching
    }

    pub fn into_with_branching(self) -> QueriesWithBranching {
        let branching = self.branching_by_parent();
        QueriesWithBranching {
            queries: self,
            branching,
        }
    }
}

impl Deref for Queries {
    type Target = Vec<usize>;

    fn deref(&self) -> &Self::Target {
        &self.positions
    }
}

#[cfg(test)]
mod tests {
    use crate::core::backend::cpu::bit_reverse;
    use crate::core::channel::Blake2sChannel;
    use crate::core::poly::circle::CanonicCoset;
    use crate::core::queries::Queries;

    #[test]
    fn test_generate_queries() {
        let channel = &mut Blake2sChannel::default();
        let log_query_size = 31;
        let n_queries = 100;

        let queries = Queries::generate(channel, log_query_size, n_queries);

        assert!(queries.len() == n_queries);
        assert!(queries.iter().is_sorted());
        assert!(*queries.positions.last().unwrap() < 1 << log_query_size);
    }

    #[test]
    pub fn test_folded_queries() {
        let log_domain_size = 7;
        let domain = CanonicCoset::new(log_domain_size).circle_domain();
        let mut values = domain.iter().collect::<Vec<_>>();
        bit_reverse(&mut values);

        let log_folded_domain_size = 5;
        let folded_domain = CanonicCoset::new(log_folded_domain_size).circle_domain();
        let mut folded_values = folded_domain.iter().collect::<Vec<_>>();
        bit_reverse(&mut folded_values);

        // Generate all possible queries.
        let queries = Queries {
            positions: (0..1 << log_domain_size).collect(),
            log_domain_size,
        };
        let n_folds = log_domain_size - log_folded_domain_size;
        let ratio = 1 << n_folds;

        let folded_queries = queries.fold(n_folds);
        let repeated_folded_queries = folded_queries
            .iter()
            .flat_map(|q| std::iter::repeat_n(q, ratio));
        for (query, folded_query) in queries.iter().zip(repeated_folded_queries) {
            // Check only the x coordinate since folding might give you the conjugate point.
            assert_eq!(
                values[*query].repeated_double(n_folds).x,
                folded_values[*folded_query].x
            );
        }
    }
}
