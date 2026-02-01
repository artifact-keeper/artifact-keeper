//! Security scanning system tests.
//!
//! Unit tests for security models that don't require database access.

#[cfg(test)]
mod security_model_tests {
    use artifact_keeper_backend::models::security::{Grade, Severity};

    #[test]
    fn test_severity_ordering() {
        // Severity is ordered from most severe (Critical=0) to least (Info=4)
        assert!(Severity::Critical < Severity::High);
        assert!(Severity::High < Severity::Medium);
        assert!(Severity::Medium < Severity::Low);
        assert!(Severity::Low < Severity::Info);

        // Reverse comparisons
        assert!(Severity::Info > Severity::Low);
        assert!(Severity::Low > Severity::Medium);
        assert!(Severity::Medium > Severity::High);
        assert!(Severity::High > Severity::Critical);

        // Equality
        assert_eq!(Severity::Critical, Severity::Critical);
        assert_eq!(Severity::High, Severity::High);
        assert_eq!(Severity::Medium, Severity::Medium);
        assert_eq!(Severity::Low, Severity::Low);
        assert_eq!(Severity::Info, Severity::Info);
    }

    #[test]
    fn test_severity_penalty_weights() {
        assert_eq!(Severity::Critical.penalty_weight(), 25);
        assert_eq!(Severity::High.penalty_weight(), 10);
        assert_eq!(Severity::Medium.penalty_weight(), 3);
        assert_eq!(Severity::Low.penalty_weight(), 1);
        assert_eq!(Severity::Info.penalty_weight(), 0);
    }

    #[test]
    fn test_severity_from_str_loose() {
        // Critical
        assert_eq!(
            Severity::from_str_loose("critical"),
            Some(Severity::Critical)
        );
        assert_eq!(
            Severity::from_str_loose("CRITICAL"),
            Some(Severity::Critical)
        );
        assert_eq!(
            Severity::from_str_loose("Critical"),
            Some(Severity::Critical)
        );

        // High
        assert_eq!(Severity::from_str_loose("high"), Some(Severity::High));
        assert_eq!(Severity::from_str_loose("HIGH"), Some(Severity::High));
        assert_eq!(Severity::from_str_loose("High"), Some(Severity::High));

        // Medium (including "moderate" alias)
        assert_eq!(Severity::from_str_loose("medium"), Some(Severity::Medium));
        assert_eq!(Severity::from_str_loose("MEDIUM"), Some(Severity::Medium));
        assert_eq!(Severity::from_str_loose("Medium"), Some(Severity::Medium));
        assert_eq!(Severity::from_str_loose("moderate"), Some(Severity::Medium));
        assert_eq!(Severity::from_str_loose("MODERATE"), Some(Severity::Medium));

        // Low
        assert_eq!(Severity::from_str_loose("low"), Some(Severity::Low));
        assert_eq!(Severity::from_str_loose("LOW"), Some(Severity::Low));
        assert_eq!(Severity::from_str_loose("Low"), Some(Severity::Low));

        // Info (including aliases)
        assert_eq!(Severity::from_str_loose("info"), Some(Severity::Info));
        assert_eq!(Severity::from_str_loose("INFO"), Some(Severity::Info));
        assert_eq!(
            Severity::from_str_loose("informational"),
            Some(Severity::Info)
        );
        assert_eq!(
            Severity::from_str_loose("INFORMATIONAL"),
            Some(Severity::Info)
        );
        assert_eq!(Severity::from_str_loose("none"), Some(Severity::Info));
        assert_eq!(Severity::from_str_loose("NONE"), Some(Severity::Info));

        // Unknown/invalid
        assert_eq!(Severity::from_str_loose("unknown"), None);
        assert_eq!(Severity::from_str_loose("invalid"), None);
        assert_eq!(Severity::from_str_loose(""), None);
        assert_eq!(Severity::from_str_loose("garbage"), None);
    }

    #[test]
    fn test_severity_meets_threshold() {
        // Critical meets all thresholds (it's the highest severity)
        assert!(Severity::Critical.meets_threshold(Severity::Critical));
        assert!(Severity::Critical.meets_threshold(Severity::High));
        assert!(Severity::Critical.meets_threshold(Severity::Medium));
        assert!(Severity::Critical.meets_threshold(Severity::Low));
        assert!(Severity::Critical.meets_threshold(Severity::Info));

        // High meets High and below, but not Critical
        assert!(!Severity::High.meets_threshold(Severity::Critical));
        assert!(Severity::High.meets_threshold(Severity::High));
        assert!(Severity::High.meets_threshold(Severity::Medium));
        assert!(Severity::High.meets_threshold(Severity::Low));
        assert!(Severity::High.meets_threshold(Severity::Info));

        // Medium meets Medium and below
        assert!(!Severity::Medium.meets_threshold(Severity::Critical));
        assert!(!Severity::Medium.meets_threshold(Severity::High));
        assert!(Severity::Medium.meets_threshold(Severity::Medium));
        assert!(Severity::Medium.meets_threshold(Severity::Low));
        assert!(Severity::Medium.meets_threshold(Severity::Info));

        // Low only meets Low and Info thresholds
        assert!(!Severity::Low.meets_threshold(Severity::Critical));
        assert!(!Severity::Low.meets_threshold(Severity::High));
        assert!(!Severity::Low.meets_threshold(Severity::Medium));
        assert!(Severity::Low.meets_threshold(Severity::Low));
        assert!(Severity::Low.meets_threshold(Severity::Info));

        // Info only meets Info threshold
        assert!(!Severity::Info.meets_threshold(Severity::Critical));
        assert!(!Severity::Info.meets_threshold(Severity::High));
        assert!(!Severity::Info.meets_threshold(Severity::Medium));
        assert!(!Severity::Info.meets_threshold(Severity::Low));
        assert!(Severity::Info.meets_threshold(Severity::Info));
    }

    #[test]
    fn test_grade_from_score() {
        // Grade A: 90-100
        assert_eq!(Grade::from_score(100), Grade::A);
        assert_eq!(Grade::from_score(95), Grade::A);
        assert_eq!(Grade::from_score(90), Grade::A);

        // Grade B: 75-89
        assert_eq!(Grade::from_score(89), Grade::B);
        assert_eq!(Grade::from_score(80), Grade::B);
        assert_eq!(Grade::from_score(75), Grade::B);

        // Grade C: 50-74
        assert_eq!(Grade::from_score(74), Grade::C);
        assert_eq!(Grade::from_score(60), Grade::C);
        assert_eq!(Grade::from_score(50), Grade::C);

        // Grade D: 25-49
        assert_eq!(Grade::from_score(49), Grade::D);
        assert_eq!(Grade::from_score(35), Grade::D);
        assert_eq!(Grade::from_score(25), Grade::D);

        // Grade F: 0-24
        assert_eq!(Grade::from_score(24), Grade::F);
        assert_eq!(Grade::from_score(10), Grade::F);
        assert_eq!(Grade::from_score(0), Grade::F);

        // Negative scores should also be F
        assert_eq!(Grade::from_score(-10), Grade::F);
        assert_eq!(Grade::from_score(-100), Grade::F);
    }

    #[test]
    fn test_grade_as_char() {
        assert_eq!(Grade::A.as_char(), 'A');
        assert_eq!(Grade::B.as_char(), 'B');
        assert_eq!(Grade::C.as_char(), 'C');
        assert_eq!(Grade::D.as_char(), 'D');
        assert_eq!(Grade::F.as_char(), 'F');
    }

    #[test]
    fn test_score_penalty_calculation() {
        // Simulate: 1 critical + 2 high + 3 medium = 25 + 20 + 9 = 54 penalty
        // Score = 100 - 54 = 46, Grade = D
        let penalty = Severity::Critical.penalty_weight()
            + 2 * Severity::High.penalty_weight()
            + 3 * Severity::Medium.penalty_weight();
        let score = (100 - penalty).max(0);
        assert_eq!(penalty, 54);
        assert_eq!(score, 46);
        assert_eq!(Grade::from_score(score), Grade::D);
    }

    #[test]
    fn test_score_penalty_all_severities() {
        // Test with all severity types
        let penalty = 2 * Severity::Critical.penalty_weight()  // 50
            + Severity::High.penalty_weight()                   // 10
            + 2 * Severity::Medium.penalty_weight()            // 6
            + 3 * Severity::Low.penalty_weight()               // 3
            + 5 * Severity::Info.penalty_weight(); // 0
        let score = (100 - penalty).max(0);
        assert_eq!(penalty, 69);
        assert_eq!(score, 31);
        assert_eq!(Grade::from_score(score), Grade::D);
    }

    #[test]
    fn test_score_floor_at_zero() {
        // 5 criticals = 125 penalty, score should be 0 not negative
        let penalty = 5 * Severity::Critical.penalty_weight();
        let score = (100 - penalty).max(0);
        assert_eq!(penalty, 125);
        assert_eq!(score, 0);
        assert_eq!(Grade::from_score(score), Grade::F);
    }

    #[test]
    fn test_perfect_score() {
        // No findings = 0 penalty = 100 score = A grade
        let penalty = 0;
        let score = (100 - penalty).max(0);
        assert_eq!(score, 100);
        assert_eq!(Grade::from_score(score), Grade::A);
    }

    #[test]
    fn test_boundary_scores() {
        // Test boundary values between grades
        assert_eq!(Grade::from_score(89), Grade::B);
        assert_eq!(Grade::from_score(90), Grade::A);

        assert_eq!(Grade::from_score(74), Grade::C);
        assert_eq!(Grade::from_score(75), Grade::B);

        assert_eq!(Grade::from_score(49), Grade::D);
        assert_eq!(Grade::from_score(50), Grade::C);

        assert_eq!(Grade::from_score(24), Grade::F);
        assert_eq!(Grade::from_score(25), Grade::D);
    }

    #[test]
    fn test_only_low_and_info_findings() {
        // Many low severity findings should still allow decent score
        let penalty = 20 * Severity::Low.penalty_weight()   // 20
            + 50 * Severity::Info.penalty_weight(); // 0
        let score = (100 - penalty).max(0);
        assert_eq!(penalty, 20);
        assert_eq!(score, 80);
        assert_eq!(Grade::from_score(score), Grade::B);
    }

    #[test]
    fn test_single_critical_impact() {
        // A single critical vulnerability significantly impacts score
        let penalty = Severity::Critical.penalty_weight();
        let score = (100 - penalty).max(0);
        assert_eq!(penalty, 25);
        assert_eq!(score, 75);
        assert_eq!(Grade::from_score(score), Grade::B);
    }
}
