use super::reservation;
use iteron_protocol::{TokenRateCard, Usage};
use iteron_provider::ProviderUsageBoundSemantics::{IndependentClasses, PartitionedInput};

#[test]
fn native_partitions_bound_every_real_pricing_split_including_rounding() {
    for rates in [
        TokenRateCard {
            input_microusd_per_million: 1,
            output_microusd_per_million: 1,
            cache_creation_microusd_per_million: 1,
            cache_read_microusd_per_million: 1,
            thinking_microusd_per_million: 1,
        },
        TokenRateCard {
            input_microusd_per_million: 999_999,
            output_microusd_per_million: 2_000_001,
            cache_creation_microusd_per_million: 1_250_001,
            cache_read_microusd_per_million: 100_000,
            thinking_microusd_per_million: 3_000_001,
        },
    ] {
        let admitted = reservation(PartitionedInput, rates, 12, 8).unwrap();
        assert_eq!(admitted.tokens, 28);
        for input in 0..=12 {
            for creation in 0..=12 - input {
                for read in 0..=12 - input - creation {
                    for output in 0..=8 {
                        for thinking in 0..=output {
                            let real = Usage {
                                input,
                                output,
                                cache_creation: creation,
                                cache_read: read,
                                thinking,
                            };
                            let charged =
                                iteron_obs::pricing::projected_amount_microusd(rates, real)
                                    .unwrap();
                            assert!(charged <= admitted.cost_microusd, "{real:?}");
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn native_partition_reduces_a_real_finite_reservation_without_guessing_request_tokens() {
    let rates = TokenRateCard {
        input_microusd_per_million: 1_000_000,
        output_microusd_per_million: 1_000_000,
        cache_creation_microusd_per_million: 1_000_000,
        cache_read_microusd_per_million: 1_000_000,
        thinking_microusd_per_million: 1_000_000,
    };
    let native = reservation(PartitionedInput, rates, 16, 4).unwrap();
    let unknown = reservation(IndependentClasses, rates, 16, 4).unwrap();
    assert!(native.cost_microusd <= 24);
    assert!(unknown.cost_microusd > 24);
    let budget = crate::runtime::pricing::SharedUsdBudget::from_microusd(24);
    assert!(
        budget
            .reserve_provider_attempt(native.cost_microusd)
            .is_ok()
    );
    assert_eq!(native.tokens, 24);
    assert_eq!(unknown.tokens, 56);
}

#[test]
fn signed_zero_and_overflow_remain_distinct_from_unknown() {
    let zero = TokenRateCard {
        input_microusd_per_million: 0,
        output_microusd_per_million: 0,
        cache_creation_microusd_per_million: 0,
        cache_read_microusd_per_million: 0,
        thinking_microusd_per_million: 0,
    };
    assert_eq!(
        reservation(PartitionedInput, zero, 12, 8)
            .unwrap()
            .cost_microusd,
        0
    );
    assert!(reservation(PartitionedInput, zero, u64::MAX, 1).is_err());
    let high = TokenRateCard {
        input_microusd_per_million: u64::MAX,
        ..zero
    };
    assert!(reservation(PartitionedInput, high, u64::MAX, 0).is_err());
}
