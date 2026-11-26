package common

import (
	"fmt"
)

type StringValue struct {
	value string
	name  Path
	event *Event
}

func (what StringValue) Value() any {
	return what.value
}

func (what StringValue) Name() Path {
	return what.name
}

func (what StringValue) SetName(name ...string) {
	what.name.SetPath(name...)
}

func (what StringValue) Event() *Event {
	return what.event
}

func (what StringValue) PlainValue() any {
	return what.value
}

func (what StringValue) Text() []string {
	return []string{what.value}
}

func (what StringValue) StringValue() string {
	return what.value
}

func EmptyStringValue() *StringValue {
	return &StringValue{}
}

func SomeStringValue(value string, event *Event) *StringValue {
	return &StringValue{
		value: value,
		event: event,
	}
}

func ToStringValue(value Value) (*StringValue, error) {
	castValue, ok := value.Value().(string)

	var conversionError error
	// An empty value converts to "", matching compare(), which already treats an empty value
	// as equal to an empty string when it is the first operand.
	if !ok && value.Value() != nil {
		conversionError = fmt.Errorf("expected value-expression to eval to a string instead of %T", value.Value())
	}

	return &StringValue{
		value: castValue,
		name:  value.Name(),
		event: value.Event(),
	}, conversionError
}
