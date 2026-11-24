package types

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// MissionCriticality is the model-level rating of how much the mission depends on the system. It is
// a separate, four-value scale from Criticality, which rates each asset's and data asset's
// integrity and availability (and which the risk calibration's CIA step is built on).
type MissionCriticality int

const (
	MissionCriticalityAdministrative MissionCriticality = iota
	MissionCriticalitySupport
	MissionCriticalityEssential
	MissionCriticalityCritical
)

var MissionCriticalityTypeDescription = [...]TypeDescription{
	{"administrative", "Supports administrative or business functions; the mission continues without it"},
	{"mission-support", "Supports the mission; loss degrades it but has workarounds"},
	{"mission-essential", "Needed to accomplish the mission; loss stops a mission function"},
	{"mission-critical", "Loss causes mission failure"},
}

var missionCriticalityTitles = [...]string{"Administrative", "Mission Support", "Mission Essential", "Mission Critical"}

// legacyMissionCriticality maps the five business_criticality values models used before the
// four-value scale, so existing models keep parsing.
var legacyMissionCriticality = map[string]MissionCriticality{
	"archive":          MissionCriticalityAdministrative,
	"operational":      MissionCriticalityAdministrative,
	"important":        MissionCriticalitySupport,
	"critical":         MissionCriticalityEssential,
	"mission-critical": MissionCriticalityCritical,
}

func MissionCriticalityValues() []MissionCriticality {
	return []MissionCriticality{
		MissionCriticalityAdministrative,
		MissionCriticalitySupport,
		MissionCriticalityEssential,
		MissionCriticalityCritical,
	}
}

// ParseMissionCriticality accepts a four-value name, or one of the legacy five business
// criticality values (reported as legacy so callers can say so).
func ParseMissionCriticality(value string) (criticality MissionCriticality, legacy bool, err error) {
	if found, findErr := MissionCriticality(0).Find(value); findErr == nil {
		return found, false, nil
	}
	if mapped, ok := legacyMissionCriticality[strings.ToLower(strings.TrimSpace(value))]; ok {
		return mapped, true, nil
	}
	return MissionCriticalityAdministrative, false, fmt.Errorf(
		"unknown mission criticality value %q (expected administrative, mission-support, mission-essential or mission-critical)", value)
}

func (what MissionCriticality) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return MissionCriticalityTypeDescription[what].Name
}

// Title is the display name used in reports, such as "Mission Support".
func (what MissionCriticality) Title() string {
	return missionCriticalityTitles[what]
}

func (what MissionCriticality) Explain() string {
	return MissionCriticalityTypeDescription[what].Description
}

func (what MissionCriticality) Find(value string) (MissionCriticality, error) {
	for index, description := range MissionCriticalityTypeDescription {
		if strings.EqualFold(strings.TrimSpace(value), description.Name) {
			return MissionCriticality(index), nil
		}
	}
	return MissionCriticalityAdministrative, fmt.Errorf("unknown mission criticality value %q", value)
}

func (what MissionCriticality) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *MissionCriticality) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	value, _, err := ParseMissionCriticality(text)
	if err != nil {
		return err
	}
	*what = value
	return nil
}

func (what MissionCriticality) MarshalYAML() (interface{}, error) {
	return what.String(), nil
}

func (what *MissionCriticality) UnmarshalYAML(node *yaml.Node) error {
	value, _, err := ParseMissionCriticality(node.Value)
	if err != nil {
		return err
	}
	*what = value
	return nil
}
