package analyze

import "testing"

// TestFixtureExercisesManyCategories keeps fullyPopulatedReport honest: if it
// ever stops producing findings across most of the analyzer, the invariant
// tests that walk its output would quietly stop checking anything.
func TestFixtureExercisesManyCategories(t *testing.T) {
	report := fullyPopulatedReport()
	Report(&report)
	categories := map[string]struct{}{}
	for _, f := range report.Findings {
		categories[f.Category] = struct{}{}
	}
	if len(categories) < 12 {
		t.Fatalf("fixture only reached %d categories (%v); the contract tests need broad coverage to be meaningful", len(categories), categories)
	}
	t.Logf("%d findings across %d categories", len(report.Findings), len(categories))
}
