package types

import "strings"

type RiskCategory struct {
	ID                         string       `json:"id,omitempty" yaml:"id,omitempty"`
	Title                      string       `json:"title,omitempty" yaml:"title,omitempty"`
	Description                string       `json:"description,omitempty" yaml:"description,omitempty"`
	Impact                     string       `json:"impact,omitempty" yaml:"impact,omitempty"`
	ASVS                       string       `json:"asvs,omitempty" yaml:"asvs,omitempty"`
	CheatSheet                 string       `json:"cheat_sheet,omitempty" yaml:"cheat_sheet,omitempty"`
	Action                     string       `json:"action,omitempty" yaml:"action,omitempty"`
	Mitigation                 string       `json:"mitigation,omitempty" yaml:"mitigation,omitempty"`
	Check                      string       `json:"check,omitempty" yaml:"check,omitempty"`
	Function                   RiskFunction `json:"function,omitempty" yaml:"function,omitempty"`
	STRIDE                     STRIDE       `json:"stride,omitempty" yaml:"stride,omitempty"`
	DetectionLogic             string       `json:"detection_logic,omitempty" yaml:"detection_logic,omitempty"`
	RiskAssessment             string       `json:"risk_assessment,omitempty" yaml:"risk_assessment,omitempty"`
	FalsePositives             string       `json:"false_positives,omitempty" yaml:"false_positives,omitempty"`
	ModelFailurePossibleReason bool         `json:"model_failure_possible_reason,omitempty" yaml:"model_failure_possible_reason,omitempty"`
	CWE                        int          `json:"cwe,omitempty" yaml:"cwe,omitempty"`
	// FindingClass says what a finding in this category shows: a weakness the model's own facts
	// show, or a control the model cannot evidence (see FindingClassWeaknessShown).
	FindingClass string `json:"finding_class,omitempty" yaml:"finding_class,omitempty"`
}

const (
	// FindingClassWeaknessShown: the model's own facts show the weakness (a plain-HTTP link, a
	// static secret on a link, an unauthenticated agent-to-agent hop).
	FindingClassWeaknessShown = "weakness-shown"
	// FindingClassControlNotEvidenced: the rule fires because an interface or capability exists,
	// and the model cannot show whether the control is in place. A reviewer confirms it.
	FindingClassControlNotEvidenced = "control-not-evidenced"
)

// IsValidFindingClass reports whether value is one of the two finding classes.
func IsValidFindingClass(value string) bool {
	return value == FindingClassWeaknessShown || value == FindingClassControlNotEvidenced
}

type RiskCategories []*RiskCategory

func (what *RiskCategories) Add(categories ...*RiskCategory) bool {
	for _, newCategory := range categories {
		for _, existingCategory := range *what {
			if strings.EqualFold(existingCategory.ID, newCategory.ID) {
				return false
			}
		}

		*what = append(*what, newCategory)
	}

	return true
}
