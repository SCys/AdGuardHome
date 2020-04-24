package worker

import (
	"sort"
	"sync"
)

// RuleManager rule list
type RuleManager struct {
	items []string
	size  int

	lock sync.RWMutex
}

// Has check rule in list
func (rules *RuleManager) Has(item string) bool {
	return sort.SearchStrings(rules.items, item) != rules.size
}

// Append append a rule
func (rules *RuleManager) Append(item string) bool {
	if rules.Has(item) {
		return false
	}

	rules.lock.Lock()

	rules.items = append(rules.items, item)
	sort.Strings(rules.items)

	rules.lock.Unlock()
	return true
}

// Remove remove a rule
func (rules *RuleManager) Remove(item string) bool {
	index := sort.SearchStrings(rules.items, item)
	if index == rules.size {
		return false
	}

	rules.lock.Lock()

	rules.items = append(rules.items[:index], rules.items[index+1:]...)
	// sort.Strings(rules.items) order no change

	rules.lock.Unlock()
	return true
}
