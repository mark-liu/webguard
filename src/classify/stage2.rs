use super::result::Match;

pub fn score_stage2(
    matches: &[Match],
    text_len: usize,
    has_encoded: bool,
    zero_width_count: usize,
) -> f64 {
    if matches.is_empty() {
        return 0.0;
    }

    let mut weights: Vec<f64> = matches.iter().map(|m| m.severity.weight()).collect();

    // Proximity bonus: authority-claim + instruction-override within 200 chars
    apply_proximity_bonus(
        matches,
        &mut weights,
        "authority-claim",
        "instruction-override",
        200,
        1.5,
    );

    // Clustering bonus: any 2 matches within 200 chars
    apply_clustering_bonus(matches, &mut weights, 200, 1.5);

    let mut total: f64 = weights.iter().sum();

    // Density boost: > 2 matches per 1000 chars
    if text_len > 0 {
        let density = matches.len() as f64 / (text_len as f64 / 1000.0);
        if density > 2.0 {
            total *= 1.2;
        }
    }

    // Encoding penalty
    if has_encoded {
        total *= 1.3;
    }

    // Zero-width penalty
    if zero_width_count >= 10 {
        total *= 1.5;
    } else if zero_width_count >= 3 {
        total *= 1.2;
    }

    // Round to 4 decimal places
    (total * 10000.0).round() / 10000.0
}

fn apply_proximity_bonus(
    matches: &[Match],
    weights: &mut [f64],
    cat_a: &str,
    cat_b: &str,
    max_dist: usize,
    factor: f64,
) {
    for i in 0..matches.len() {
        for j in (i + 1)..matches.len() {
            let a = &matches[i];
            let b = &matches[j];
            let dist = a.offset.abs_diff(b.offset);
            if dist <= max_dist {
                let a_match = a.category == cat_a && b.category == cat_b;
                let b_match = a.category == cat_b && b.category == cat_a;
                if a_match || b_match {
                    weights[i] *= factor;
                    weights[j] *= factor;
                }
            }
        }
    }
}

fn apply_clustering_bonus(
    matches: &[Match],
    weights: &mut [f64],
    max_dist: usize,
    factor: f64,
) {
    for i in 0..matches.len() {
        for j in (i + 1)..matches.len() {
            let dist = matches[i].offset.abs_diff(matches[j].offset);
            if dist <= max_dist {
                weights[i] *= factor;
                weights[j] *= factor;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::result::Severity;

    fn make_match(category: &str, severity: Severity, offset: usize) -> Match {
        Match {
            pattern_id: "test".into(),
            category: category.into(),
            severity,
            text: "test".into(),
            offset,
            from_decoded: false,
        }
    }

    #[test]
    fn test_empty_matches() {
        assert_eq!(score_stage2(&[], 1000, false, 0), 0.0);
    }

    #[test]
    fn test_single_match_scoring() {
        let matches = vec![make_match("test", Severity::Medium, 0)];
        let score = score_stage2(&matches, 10000, false, 0);
        assert!(score > 0.0);
    }

    #[test]
    fn test_proximity_bonus() {
        let matches = vec![
            make_match("authority-claim", Severity::High, 10),
            make_match("instruction-override", Severity::High, 50),
        ];
        let score_close = score_stage2(&matches, 10000, false, 0);

        let matches_far = vec![
            make_match("authority-claim", Severity::High, 10),
            make_match("instruction-override", Severity::High, 500),
        ];
        let score_far = score_stage2(&matches_far, 10000, false, 0);

        assert!(
            score_close > score_far,
            "close matches should score higher: {score_close} vs {score_far}"
        );
    }

    #[test]
    fn test_encoding_penalty() {
        let matches = vec![make_match("test", Severity::High, 0)];
        let score_normal = score_stage2(&matches, 10000, false, 0);
        let score_encoded = score_stage2(&matches, 10000, true, 0);
        assert!(score_encoded > score_normal);
    }

    #[test]
    fn test_zero_width_penalty() {
        let matches = vec![make_match("test", Severity::High, 0)];
        let score_none = score_stage2(&matches, 10000, false, 0);
        let score_few = score_stage2(&matches, 10000, false, 5);
        let score_many = score_stage2(&matches, 10000, false, 15);
        assert!(score_few > score_none);
        assert!(score_many > score_few);
    }
}
